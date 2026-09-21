"""Inference engine: raw CICFlowMeter flow records in, calibrated anomaly scores and alerts out.

Independent of the research pipeline (no training data, no config file); it needs only a model bundle.
"""
import json
import os
import shutil
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from .bundle import FILES, BundleError, knn_score, load_bundle, read_manifest
from .features import ROLE_NAMES
from .schema import ROLE_COLUMN, DataError, validate_flows

CHUNK = 8192
_EPS = 1e-8
DRIFT_WINDOW = 10_000        # recent flows the drift monitor looks at
DRIFT_MIN_FLOWS = 1_000      # do not judge drift on fewer flows than this
DRIFT_FACTOR = 3.0           # "drifting" when the recent alert rate exceeds this multiple of the design FPR


def load_column_map(path):
    """optional JSON file {their_column: canonical_column} for exporters whose names differ from CICFlowMeter's."""
    if not path:
        return None
    try:
        m = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise DataError(f"column map {path}: {e}") from e
    if not isinstance(m, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in m.items()):
        raise DataError(f"column map {path}: expected a JSON object of string -> string")
    return m


@dataclass
class ScoreResult:
    """scores for the accepted rows, plus the rows that were rejected and why (keyed by input position)."""
    rows: list = field(default_factory=list)          # dicts: index, score, threshold, alert, role, top_features
    rejected: dict = field(default_factory=dict)      # input position -> reason


class Detector:
    def __init__(self, bundle_dir, column_map=None):
        self.bundle_dir = Path(bundle_dir)
        self.manifest, self.fs, self.model, self.knn = load_bundle(self.bundle_dir)
        self.threshold = float(self.manifest["threshold"])
        self.calibration = self.manifest["calibration"]
        self.idx = np.array(self.manifest["input_idx"])
        self.names = [self.fs.names[i] for i in self.idx]
        self.required_columns = self.fs.required_columns()
        self.column_map = column_map if column_map is not None else load_column_map(os.environ.get("IDS_COLUMN_MAP"))
        self._lock = threading.Lock()
        self._recent = deque(maxlen=DRIFT_WINDOW)          # 1/0 alert flags of the most recent flows
        self.counters = dict(requests=0, flows_scored=0, flows_rejected=0, alerts=0, seconds=0.0)

    @property
    def info(self):
        m = self.manifest
        return dict(method=m["method"], format_version=m["format_version"], created_utc=m["created_utc"],
                    threshold=self.threshold, target_fpr=m["target_fpr"], n_features=len(self.fs.names),
                    modalities=m["modalities"], required_columns=self.required_columns,
                    roles=ROLE_NAMES, runtime=m["runtime"], sha256=m["sha256"],
                    calibrated_on=m.get("recalibrated", {"source": "training run"}), drift=self.drift())

    def drift(self):
        """alert rate over the last flows vs the design false-positive rate. A persistently high ratio means
        the traffic no longer looks like the calibration data: recalibrate (`ids-detect recalibrate`)."""
        with self._lock:
            n, alerts = len(self._recent), sum(self._recent)
        target = float(self.manifest["target_fpr"])
        rate = alerts / n if n else 0.0
        status = "insufficient_data" if n < DRIFT_MIN_FLOWS else ("drifting" if rate > DRIFT_FACTOR * target else "ok")
        return dict(status=status, recent_flows=n, recent_alert_rate=round(rate, 5), target_alert_rate=target,
                    ratio=round(rate / target, 2) if target else None)

    def _distances(self, x, role):
        out = []
        with torch.inference_mode():
            for i in range(0, len(x), CHUNK):
                e = self.model.embed(torch.from_numpy(x[i:i + CHUNK]), torch.from_numpy(role[i:i + CHUNK])).numpy()
                out.append(self.knn.distances(e, role[i:i + CHUNK]))
        return np.concatenate(out) if out else np.zeros(0, np.float32)

    def _prepare(self, clean):
        x, role = self.fs.transform(clean)
        if ROLE_COLUMN in clean:                                  # asset role supplied by the caller overrides the port heuristic
            given = clean[ROLE_COLUMN].map({n: i for i, n in enumerate(ROLE_NAMES)})
            role = np.where(given.notna().to_numpy(), given.fillna(0).to_numpy(), role).astype(np.int8)
        return x[:, self.idx], role

    def _top_features(self, x, role, k):
        """native attribution: features with the largest reconstruction error (standardised units)."""
        with torch.inference_mode():
            err = self.model.components(torch.from_numpy(x), torch.from_numpy(role))["feat_err"].numpy()
        top = np.argsort(-err, axis=1)[:, :k]
        return [[dict(feature=self.names[j], error=round(float(err[i, j]), 4)) for j in top[i]] for i in range(len(x))]

    def score_frame(self, df, top_k=3):
        t0 = time.perf_counter()
        df = df.reset_index(drop=True)
        clean, rejected = validate_flows(df, self.fs.names, self.column_map)
        res = ScoreResult(rejected=dict(rejected))
        if len(clean):
            pos = np.array([i for i in range(len(df)) if i not in rejected])
            x, role = self._prepare(clean)
            s = knn_score(self._distances(x, role), self.calibration)
            finite = np.isfinite(s)                               # never emit a NaN score
            for j in np.flatnonzero(~finite):
                res.rejected[int(pos[j])] = "non-finite score"
            alert = finite & (s > self.threshold)
            tops = {}
            if top_k > 0 and alert.any():
                ai = np.flatnonzero(alert)
                tops = dict(zip(ai.tolist(), self._top_features(x[ai], role[ai], top_k)))
            for j in np.flatnonzero(finite):
                res.rows.append(dict(index=int(pos[j]), score=round(float(s[j]), 4), threshold=self.threshold,
                                     alert=bool(alert[j]), role=ROLE_NAMES[int(role[j])], top_features=tops.get(int(j), [])))
        with self._lock:
            c = self.counters
            c["requests"] += 1
            c["flows_scored"] += len(res.rows)
            c["flows_rejected"] += len(res.rejected)
            c["alerts"] += sum(r["alert"] for r in res.rows)
            c["seconds"] += time.perf_counter() - t0
            self._recent.extend(int(r["alert"]) for r in res.rows)
        return res

    def score_records(self, records, top_k=3):
        return self.score_frame(pd.DataFrame.from_records(records), top_k)

    def benign_distances(self, df):
        """kNN distances of (assumed benign) site flows; used to recalibrate. Invalid rows are dropped and counted."""
        df = df.reset_index(drop=True)
        clean, rejected = validate_flows(df, self.fs.names, self.column_map)
        if not len(clean):
            return np.zeros(0, np.float32), len(rejected)
        x, role = self._prepare(clean)
        return self._distances(x, role), len(rejected)


MIN_RECALIBRATION_FLOWS = 2000


def recalibrate_bundle(src, out, chunks, target_fpr=None, column_map=None):
    """New bundle whose calibration and alert threshold are fitted on benign flows of the deployment network.

    The network weights and the latent reference set are unchanged (same checksums); only the robust centre/scale
    of log-distance and the threshold move, so this fixes threshold drift without retraining. The caller vouches that
    `chunks` (an iterable of DataFrames) is benign; attacks in it would inflate the threshold.
    """
    det = Detector(src, column_map)
    dist, dropped = [], 0
    for chunk in chunks:
        d, bad = det.benign_distances(chunk)
        dist.append(d)
        dropped += bad
    dist = np.concatenate(dist) if dist else np.zeros(0, np.float32)
    if len(dist) < MIN_RECALIBRATION_FLOWS:
        raise DataError(f"recalibration needs at least {MIN_RECALIBRATION_FLOWS} valid benign flows, got {len(dist)}"
                        + (f" ({dropped} rejected)" if dropped else ""))
    fpr = float(target_fpr or det.manifest["target_fpr"])
    if not 0 < fpr < 1:
        raise DataError("target_fpr must be in (0, 1)")
    logd = np.log(dist + _EPS)
    med = float(np.median(logd))
    mad = float(1.4826 * np.median(np.abs(logd - med)) + 1e-6)
    cal = dict(median=med, mad=mad)
    thr = float(np.quantile(knn_score(dist, cal), 1 - fpr))

    src, out = Path(src), Path(out)
    if out.resolve() == src.resolve():
        raise BundleError("write the recalibrated bundle to a new directory (keep the old one for rollback)")
    out.mkdir(parents=True, exist_ok=True)
    for f in FILES:
        shutil.copy2(src / f, out / f)
    m = read_manifest(src)
    m["calibration"], m["threshold"], m["target_fpr"] = cal, thr, fpr
    m["recalibrated"] = dict(source="deployment benign traffic", n_flows=int(len(dist)), rejected_rows=int(dropped),
                             previous_threshold=float(det.manifest["threshold"]),
                             previous_calibration=det.manifest["calibration"])
    m["created_utc"] = pd.Timestamp.now("UTC").isoformat(timespec="seconds")
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    return m
