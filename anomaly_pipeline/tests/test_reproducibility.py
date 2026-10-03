"""Row order must not depend on the platform: saved scores are matched to labels by row position."""
import numpy as np
import pandas as pd
import pytest

from ids_pipeline.data import check_aligned, clean_day, load_scored
from ids_pipeline.schema import DataError
from ids_pipeline.train import _save_scores

from .conftest import make_flows


def test_clean_day_keeps_file_order_within_a_second(tmp_path):
    n = 600
    df = make_flows(n, seed=7)
    # 3 timestamps for 600 flows, written out of time order: almost every row is tied with ~200 others
    stamps = pd.to_datetime(["2018-02-14 09:00:02", "2018-02-14 09:00:00", "2018-02-14 09:00:01"])
    df["Timestamp"] = np.tile(stamps.strftime("%d/%m/%Y %H:%M:%S"), n // 3)
    df["Label"] = "Benign"
    df["Flow Duration"] = np.arange(n, dtype=float)          # marks the original file position
    p = tmp_path / "day.csv"
    df.to_csv(p, index=False)
    out, _ = clean_day(p)
    assert out["ts"].is_monotonic_increasing
    for _, g in out.groupby("ts"):                            # ties keep file order on every platform
        assert g["Flow Duration"].is_monotonic_increasing


def _tests():
    return {"Mon": dict(y=np.array([0, 1, 1, 0], np.int8), label=np.array(["Benign", "Bot", "DoS", "Benign"])),
            "Tue": dict(y=np.array([1, 0], np.int8), label=np.array(["Bot", "Benign"]))}


def test_scores_carry_their_labels(tmp_path):
    cfg = {"paths": {"results_dir": tmp_path}}
    tests = _tests()
    test = {d: np.arange(len(t["y"]), dtype=np.float32) for d, t in tests.items()}
    _save_scores(cfg, "m", np.zeros(3, np.float32), 1.0, test, 0.0, tests)
    got = load_scored(tmp_path / "scores" / "m.npz")
    for d, t in tests.items():
        s, y, label = got[d]
        assert np.array_equal(s, test[d]) and np.array_equal(y, t["y"]) and list(label) == list(t["label"])


def test_check_aligned_detects_reordered_rows(tmp_path):
    cfg = {"paths": {"results_dir": tmp_path}}
    tests = _tests()
    _save_scores(cfg, "m", np.zeros(3, np.float32), 1.0, {d: np.zeros(len(t["y"]), np.float32) for d, t in tests.items()},
                 0.0, tests)
    z = np.load(tmp_path / "scores" / "m.npz")
    check_aligned(z, "Mon", tests["Mon"], "m")                # same rows: passes
    shuffled = dict(y=tests["Mon"]["y"][[1, 0, 2, 3]])
    with pytest.raises(DataError, match="row order"):
        check_aligned(z, "Mon", shuffled, "m")
    with pytest.raises(DataError, match="row order"):
        check_aligned(z, "Tue", dict(y=np.zeros(5, np.int8)), "m")


def test_old_score_files_without_labels_still_load(tmp_path):
    np.savez(tmp_path / "old.npz", val=np.zeros(2), thr=0.0, test_Mon=np.zeros(4, np.float32))
    z = np.load(tmp_path / "old.npz")
    check_aligned(z, "Mon", _tests()["Mon"], "old")           # length matches, no labels stored: accepted
    with pytest.raises(DataError, match="rerun"):
        load_scored(tmp_path / "old.npz")
