import json

import numpy as np
import pandas as pd
import pytest

from ids_pipeline.bundle import BundleError
from ids_pipeline.cli import main as cli_main
from ids_pipeline.schema import COLUMN_ALIASES, DataError, normalize_columns, validate_flows
from ids_pipeline.service import Detector, load_column_map, recalibrate_bundle

from .conftest import FEATURE_COLS, make_flows


def shifted(n, seed, factor=4.0):
    df = make_flows(n, seed)
    df[FEATURE_COLS] = df[FEATURE_COLS] * factor
    return df


def test_aliases_are_canonical_names_of_the_feature_space():
    assert set(COLUMN_ALIASES.values()) <= set(FEATURE_COLS) | {"Dst Port"}


def test_alias_columns_are_scored_like_canonical_ones(detector, benign):
    inv = {v: k for k, v in COLUMN_ALIASES.items()}
    other = benign.head(20).rename(columns=inv)
    a = [r["score"] for r in detector.score_frame(benign.head(20), top_k=0).rows]
    b = [r["score"] for r in detector.score_frame(other, top_k=0).rows]
    assert a == b


def test_canonical_column_wins_over_alias():
    df = pd.DataFrame({"Dst Port": [1], "Destination Port": [2]})
    assert normalize_columns(df)["Dst Port"].tolist() == [1]


def test_custom_column_map(detector, benign, tmp_path):
    df = benign.head(5).rename(columns={"Flow Duration": "dur_us"})
    with pytest.raises(DataError, match="Flow Duration"):
        detector.score_frame(df)
    p = tmp_path / "map.json"
    p.write_text(json.dumps({"dur_us": "Flow Duration"}))
    d2 = Detector(detector.bundle_dir, load_column_map(p))
    assert len(d2.score_frame(df, top_k=0).rows) == 5
    p.write_text("[1]")
    with pytest.raises(DataError):
        load_column_map(p)


def test_role_override(detector, benign):
    df = benign.head(6).copy()
    df["__role__"] = ["database", None, "web", "mail", "database", "nonsense"]
    res = detector.score_frame(df, top_k=0)
    assert res.rejected.keys() == {5} and "unknown role" in res.rejected[5]
    roles = {r["index"]: r["role"] for r in res.rows}
    assert roles[0] == "database" and roles[2] == "web" and roles[3] == "mail"
    port_role = detector.score_frame(benign.head(6), top_k=0).rows[1]["role"]
    assert roles[1] == port_role                                  # None -> port heuristic


def test_recalibration_fixes_threshold_drift(bundle_dir, tmp_path):
    old = Detector(bundle_dir)
    site_train, site_eval = shifted(3000, 20), shifted(2000, 21)
    before = np.mean([r["alert"] for r in old.score_frame(site_eval, top_k=0).rows])
    out = tmp_path / "site"
    m = recalibrate_bundle(bundle_dir, out, [site_train.iloc[:1500], site_train.iloc[1500:]])
    new = Detector(out)
    after = np.mean([r["alert"] for r in new.score_frame(site_eval, top_k=0).rows])
    assert before > 3 * m["target_fpr"], "test data should drift"
    assert after < 3 * m["target_fpr"] and after < before / 3
    assert m["recalibrated"]["n_flows"] == 3000 and m["sha256"] == old.manifest["sha256"]
    assert new.info["calibrated_on"]["source"] == "deployment benign traffic"


def test_recalibration_guards(bundle_dir, tmp_path):
    with pytest.raises(DataError, match="at least"):
        recalibrate_bundle(bundle_dir, tmp_path / "o", [make_flows(100, 3)])
    with pytest.raises(BundleError, match="new directory"):
        recalibrate_bundle(bundle_dir, bundle_dir, [make_flows(2500, 3)])


def test_cli_recalibrate_and_role_column(bundle_dir, tmp_path, capsys):
    src = tmp_path / "benign.csv"
    df = shifted(2500, 30)
    df["asset_role"] = "web"
    df.to_csv(src, index=False)
    out = tmp_path / "b2"
    args = ["recalibrate", "--benign", str(src), "--bundle", str(bundle_dir), "--out", str(out)]
    assert cli_main([*args, "--role-column", "asset_role"]) == 0
    assert "recalibrated on 2500" in capsys.readouterr().out and (out / "manifest.json").is_file()
    assert cli_main([*args, "--role-column", "nope"]) == 2


def test_drift_monitor(bundle_dir):
    d = Detector(bundle_dir)
    assert d.drift()["status"] == "insufficient_data"
    d.score_frame(shifted(1500, 40), top_k=0)
    assert d.drift()["status"] == "drifting" and d.drift()["ratio"] > 3
    d2 = Detector(bundle_dir)
    d2.score_frame(make_flows(1500, 41), top_k=0)
    assert d2.drift()["status"] == "ok"


def test_validate_flows_role_and_alias_together(benign, detector):
    df = benign.head(3).rename(columns={"Dst Port": "Destination Port"})
    clean, rej = validate_flows(df, detector.fs.names)
    assert len(clean) == 3 and not rej and "Dst Port" in clean
