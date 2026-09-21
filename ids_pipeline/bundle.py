"""Deployable model bundle: everything needed to score flows, with no pickle and no training data.

    bundle/
      manifest.json   format version, method, feature space, calibration, threshold, model config, sha256 of the files below
      weights.pt      torch state_dict (loaded with weights_only=True)
      reference.npz   benign latent reference embeddings of the kNN detector (global + per role)

The default detector is the proposed `ssl_mm_role_knn`: distance of a flow's fused embedding to its k nearest
benign embeddings of the same service role, calibrated to one pooled robust z-score, thresholded at the
benign-validation quantile. `export_from_workdir` rebuilds it from the artifacts of a finished `train` run.
"""
import hashlib
import json
import pickle
import platform
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch

from .features import N_ROLES, FeatureSpace
from .models import MLPAutoencoder, MultiModalSSL, batched_embed
from .scoring import Calibrator, LatentKNN

FORMAT_VERSION = 1
_EPS = 1e-8
FILES = ("weights.pt", "reference.npz")


class BundleError(RuntimeError):
    """The model bundle is missing, corrupt or incompatible."""


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_model(kind, slices, mcfg, use_role):
    return MLPAutoencoder(slices, mcfg) if kind == "ae" else MultiModalSSL(slices, mcfg, use_role)


def save_bundle(out_dir, *, method, fs, spec, idx, mcfg, model, knn, calib_global, thr, target_fpr, metrics=None):
    """write a bundle. `calib_global` = (median, MAD) of log(knn distance) on benign validation flows."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), out / "weights.pt")
    ref = {"global": knn.ref.numpy()}
    ref.update({f"role_{r}": v.numpy() for r, v in knn.role_ref.items()})
    np.savez_compressed(out / "reference.npz", **ref)
    _, sl = fs.subset(spec["mods"])
    manifest = dict(
        format_version=FORMAT_VERSION, method=method, created_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        kind=spec["kind"], use_role=bool(spec["use_role"]), modalities=list(spec["mods"]),
        feature_space=fs.get_state(), input_idx=[int(i) for i in idx], slices={m: list(v) for m, v in sl.items()},
        model=dict(mcfg), knn=dict(k=knn.k, per_role=knn.per_role),
        calibration=dict(median=float(calib_global[0]), mad=float(calib_global[1])),
        threshold=float(thr), target_fpr=float(target_fpr), metrics=metrics or {},
        runtime=dict(torch=torch.__version__, python=platform.python_version()),
        sha256={f: _sha256(out / f) for f in FILES})
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def read_manifest(bundle_dir):
    p = Path(bundle_dir) / "manifest.json"
    if not p.is_file():
        raise BundleError(f"no manifest.json in {bundle_dir} (run `ids-detect export` first)")
    try:
        m = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise BundleError(f"{p}: corrupt manifest: {e}") from e
    if m.get("format_version") != FORMAT_VERSION:
        raise BundleError(f"unsupported bundle format {m.get('format_version')} (this build reads {FORMAT_VERSION})")
    return m


def load_bundle(bundle_dir):
    """returns (manifest, feature_space, model, LatentKNN). Verifies the file checksums first."""
    d = Path(bundle_dir)
    m = read_manifest(d)
    for f in FILES:
        if not (d / f).is_file():
            raise BundleError(f"bundle file missing: {d / f}")
        if _sha256(d / f) != m["sha256"].get(f):
            raise BundleError(f"checksum mismatch for {f}: the bundle was modified or is corrupt")
    fs = FeatureSpace.from_state(m["feature_space"])
    sl = {k: tuple(v) for k, v in m["slices"].items()}
    model = build_model(m["kind"], sl, m["model"], m["use_role"])
    model.load_state_dict(torch.load(d / "weights.pt", map_location="cpu", weights_only=True))
    model.eval()
    knn = LatentKNN(m["knn"]["k"], per_role=m["knn"]["per_role"])
    with np.load(d / "reference.npz") as z:
        knn.ref = torch.from_numpy(z["global"])
        knn.role_ref = {r: torch.from_numpy(z[f"role_{r}"]) for r in range(N_ROLES) if f"role_{r}" in z.files}
    return m, fs, model, knn


def knn_score(dist, calibration):
    """pooled robust z-score of log(distance), identical to scoring.Calibrator with role_aware=False."""
    return ((np.log(dist + _EPS) - calibration["median"]) / calibration["mad"]).astype(np.float32)


def export_bundle(cfg, out_dir, method, fs, spec, idx, model, tr, va):
    """fit the latent-kNN reference on benign training embeddings, calibrate on benign validation flows."""
    scfg = cfg["scoring"]
    emb_tr = batched_embed(model, tr["X"][:, idx], tr["role"])
    knn = LatentKNN(scfg.get("knn_k", 5), scfg.get("knn_ref", 10000), scfg.get("knn_ref_role", 5000),
                    spec["role_aware"], scfg["min_role_samples"], cfg["data"]["seed"]).fit(emb_tr, tr["role"])
    vd = knn.distances(batched_embed(model, va["X"][:, idx], va["role"]), va["role"])
    zero = np.zeros(len(vd), np.float32)
    calib = Calibrator(0.0, False, scfg["min_role_samples"], scfg.get("min_scale_ratio", 0.5)).fit(
        {"rec": vd, "xmod": zero}, va["role"])
    g = tuple(calib.stats["rec"][0])
    val_scores = knn_score(vd, dict(median=g[0], mad=g[1]))
    thr = float(np.quantile(val_scores, 1 - scfg["target_fpr"]))
    metrics = dict(n_train_reference=int(len(knn.ref)), n_validation=int(len(va["X"])),
                   validation_alert_rate=float((val_scores > thr).mean()))
    return save_bundle(out_dir, method=method, fs=fs, spec=spec, idx=idx, mcfg=cfg["model"], model=model, knn=knn,
                       calib_global=g, thr=thr, target_fpr=scfg["target_fpr"], metrics=metrics)


def export_from_workdir(cfg, out_dir, method="ssl_mm_role_knn"):
    """rebuild a bundle from the artifacts of `run.py train` (work/models/<base>.pt|pkl + processed splits)."""
    from .data import load_feature_space, load_split
    base = method[:-4] if method.endswith("_knn") else method
    mdir = cfg["paths"]["work_dir"] / "models"
    if not (mdir / f"{base}.pt").is_file():
        raise BundleError(f"trained model not found: {mdir / (base + '.pt')} (run `run.py train` first)")
    with open(mdir / f"{base}.pkl", "rb") as f:                      # our own training artifact, not external input
        meta = pickle.load(f)
    fs = load_feature_space(cfg)
    if not isinstance(fs, FeatureSpace):
        raise BundleError("only CICFlowMeter (CSE-CIC-IDS2018 layout) models can be exported for serving")
    spec, idx = meta["spec"], meta["idx"]
    if spec["kind"] not in ("ssl", "ae"):
        raise BundleError(f"{base} is not a neural model")
    model = build_model(spec["kind"], meta["slices"], cfg["model"], spec["use_role"])
    model.load_state_dict(torch.load(mdir / f"{base}.pt", map_location="cpu", weights_only=True))
    model.eval()
    tr, va = load_split(cfg, "train"), load_split(cfg, "val")
    return export_bundle(cfg, out_dir, method if method.endswith("_knn") else f"{base}_knn", fs, spec, idx, model, tr, va)
