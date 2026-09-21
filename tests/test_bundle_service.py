import json
import shutil

import numpy as np
import pytest
from sklearn.metrics import roc_auc_score

from ids_pipeline.bundle import FORMAT_VERSION, BundleError, load_bundle
from ids_pipeline.service import Detector


def test_bundle_layout_and_manifest(bundle_dir):
    m = json.loads((bundle_dir / "manifest.json").read_text())
    assert m["format_version"] == FORMAT_VERSION and m["method"] == "ssl_mm_role_knn"
    assert set(m["sha256"]) == {"weights.pt", "reference.npz"}
    assert not list(bundle_dir.glob("*.pkl")), "bundles must not contain pickles"
    assert 0 < m["metrics"]["validation_alert_rate"] < 0.1     # calibrated near the 2% target


def test_load_is_deterministic(bundle_dir, benign):
    a, b = Detector(bundle_dir), Detector(bundle_dir)
    s1 = [r["score"] for r in a.score_frame(benign.head(50)).rows]
    s2 = [r["score"] for r in b.score_frame(benign.head(50)).rows]
    assert s1 == s2


def test_tampered_bundle_is_refused(bundle_dir, tmp_path):
    bad = tmp_path / "bad"
    shutil.copytree(bundle_dir, bad)
    with open(bad / "weights.pt", "ab") as f:
        f.write(b"x")
    with pytest.raises(BundleError, match="checksum"):
        load_bundle(bad)


def test_missing_and_incompatible_bundle(bundle_dir, tmp_path):
    with pytest.raises(BundleError, match="manifest"):
        load_bundle(tmp_path / "nothing")
    bad = tmp_path / "v99"
    shutil.copytree(bundle_dir, bad)
    m = json.loads((bad / "manifest.json").read_text())
    m["format_version"] = 99
    (bad / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(BundleError, match="unsupported"):
        load_bundle(bad)
    (bad / "manifest.json").write_text("{not json")
    with pytest.raises(BundleError, match="corrupt"):
        load_bundle(bad)


def test_attacks_rank_above_benign(detector, attacks, benign):
    held = benign.iloc[3200:]
    s_ben = [r["score"] for r in detector.score_frame(held, top_k=0).rows]
    s_att = [r["score"] for r in detector.score_frame(attacks, top_k=0).rows]
    auc = roc_auc_score([0] * len(s_ben) + [1] * len(s_att), s_ben + s_att)
    assert auc > 0.9


def test_alerts_carry_explanations_and_threshold(detector, attacks, benign):
    res = detector.score_frame(attacks, top_k=3)
    alerts = [r for r in res.rows if r["alert"]]
    assert len(alerts) > 0.25 * len(attacks)     # tiny model, but far above the ~2% benign alert rate
    assert all(len(r["top_features"]) == 3 for r in alerts)
    assert all(r["alert"] == (r["score"] > r["threshold"]) for r in res.rows)
    quiet = detector.score_frame(benign.iloc[3200:], top_k=3)
    assert all(not r["top_features"] for r in quiet.rows if not r["alert"])
    assert sum(r["alert"] for r in quiet.rows) / len(quiet.rows) < 0.15   # false-positive rate near target on held-out benign


def test_rejected_rows_keep_positions(detector, benign):
    df = benign.head(5).copy()
    df.loc[2, "Tot Fwd Pkts"] = np.nan
    res = detector.score_frame(df, top_k=0)
    assert res.rejected.keys() == {2}
    assert [r["index"] for r in res.rows] == [0, 1, 3, 4]


def test_non_default_index_and_empty_result(detector, benign):
    df = benign.head(3).copy()
    df.index = [10, 20, 30]
    assert [r["index"] for r in detector.score_frame(df).rows] == [0, 1, 2]
    df["Dst Port"] = -1
    res = detector.score_frame(df)
    assert res.rows == [] and len(res.rejected) == 3


def test_counters_and_info(detector, benign):
    before = detector.counters["flows_scored"]
    detector.score_frame(benign.head(10), top_k=0)
    assert detector.counters["flows_scored"] == before + 10
    info = detector.info
    assert "Dst Port" in info["required_columns"] and info["threshold"] == detector.threshold
