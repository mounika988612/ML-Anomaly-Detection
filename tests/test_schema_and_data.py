import numpy as np
import pandas as pd
import pytest

from ids_pipeline.data import clean_day
from ids_pipeline.features import FeatureSpace
from ids_pipeline.schema import DataError, training_columns, validate_flows

from .conftest import make_flows


@pytest.fixture(scope="module")
def names(benign):
    return FeatureSpace().fit(benign).names


def test_valid_batch_passes_and_is_float32(benign, names):
    clean, rej = validate_flows(benign.head(50), names)
    assert len(clean) == 50 and not rej
    assert clean["Flow Duration"].dtype == np.float32


def test_missing_column_is_a_batch_error(benign, names):
    with pytest.raises(DataError, match="Flow Duration"):
        validate_flows(benign.head(5).drop(columns=["Flow Duration"]), names)


def test_bad_rows_are_rejected_individually(benign, names):
    df = benign.head(6).copy().astype({"Flow Duration": "object"})
    df.loc[1, "Flow Duration"] = "abc"                 # non-numeric
    df.loc[2, "Tot Fwd Pkts"] = np.inf                 # infinite
    df.loc[3, "Tot Bwd Pkts"] = np.nan                 # missing
    df.loc[4, "Dst Port"] = 70000                      # out of range
    df.loc[5, "Flow Duration"] = -3                    # negative duration
    clean, rej = validate_flows(df, names)
    assert sorted(rej) == [1, 2, 3, 4, 5] and len(clean) == 1
    assert "Dst Port" in rej[4] and "negative" in rej[5]


def test_numeric_strings_are_coerced(benign, names):
    df = benign.head(3).astype({"Tot Fwd Pkts": "object"})
    df["Tot Fwd Pkts"] = df["Tot Fwd Pkts"].map(lambda v: f"{v:.3f}")
    clean, rej = validate_flows(df, names)
    assert len(clean) == 3 and not rej


def _csv(tmp_path, df, name="day.csv"):
    p = tmp_path / name
    df.to_csv(p, index=False)
    return p


def _day_frame(n=40):
    df = make_flows(n, seed=5)
    df["Timestamp"] = pd.date_range("2018-02-14 09:00:00", periods=n, freq="min").strftime("%d/%m/%Y %H:%M:%S")
    df["Label"] = "Benign"
    return df


def test_clean_day_drops_malformed_rows(tmp_path):
    df = _day_frame(40)
    df.loc[3, "Tot Fwd Pkts"] = np.inf
    df.loc[4, "Flow Byts/s"] = np.nan
    df.loc[5, "Timestamp"] = "01/01/1970 00:00:00"      # corrupt timestamp seen in the real files
    dup = df.iloc[[10]]
    hdr = pd.DataFrame([{c: c for c in df.columns}])     # header repeated inside the file
    out, stats = clean_day(_csv(tmp_path, pd.concat([df, dup, hdr], ignore_index=True)))
    assert stats["header_rows"] == 1
    assert len(out) == 40 - 3 and out["ts"].is_monotonic_increasing
    assert np.isfinite(out.drop(columns="Label").to_numpy(np.float64)).all()


def test_clean_day_missing_file_and_columns(tmp_path):
    with pytest.raises(DataError, match="not found"):
        clean_day(tmp_path / "absent.csv")
    df = _day_frame(10).drop(columns=["Flow IAT Mean"])
    with pytest.raises(DataError, match="Flow IAT Mean"):
        clean_day(_csv(tmp_path, df))


def test_clean_day_empty_and_garbage(tmp_path):
    (tmp_path / "empty.csv").write_text("", encoding="utf-8")
    with pytest.raises(DataError):
        clean_day(tmp_path / "empty.csv")
    df = _day_frame(5)
    df["Tot Fwd Pkts"] = np.nan
    with pytest.raises(DataError, match="no valid rows"):
        clean_day(_csv(tmp_path, df, "allbad.csv"))


def test_training_columns_cover_the_feature_space():
    cols = set(training_columns())
    assert {"Label", "Timestamp", "Dst Port", "Protocol", "Flow Duration"} <= cols
