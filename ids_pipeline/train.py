"""Trains every method and writes anomaly scores for validation and each test day."""
import pickle
import time

import numpy as np
import torch

from .baselines import IForest, PCARecon, SupervisedRF
from .data import load_feature_space, load_split
from .models import MLPAutoencoder, MultiModalSSL, batched_components, batched_embed, batched_embed_modalities, train_model
from .scoring import Calibrator, LatentKNN
from .utils import get_logger, set_seed

log = get_logger()


def method_specs(fs):
    mods = list(fs.slices)
    s = {
        "ssl_mm_role": dict(kind="ssl", mods=mods, use_role=True, role_aware=True),
        "ssl_mm_global": dict(kind="ssl", mods=mods, use_role=False, role_aware=False),
        "ssl_no_contrastive": dict(kind="ssl", mods=mods, use_role=True, role_aware=True, lam=0.0),
        "ae_concat": dict(kind="ae", mods=mods, use_role=False, role_aware=False),
    }
    for m in mods:
        s[f"ssl_only_{m}"] = dict(kind="ssl", mods=[m], use_role=True, role_aware=True)
    s.update({"iforest": dict(kind="iforest"), "pca_recon": dict(kind="pca"), "rf_supervised": dict(kind="rf")})
    return s


def _save_scores(cfg, name, val, thr, test, lat, hist=None):
    out = cfg["paths"]["results_dir"] / "scores"
    out.mkdir(exist_ok=True)
    np.savez(out / f"{name}.npz", val=val, thr=thr, lat_ms_per_1k=lat,
             hist=np.array(hist if hist else [[0, 0]]), **{f"test_{d}": s for d, s in test.items()})


def _threshold(val_scores, fpr):
    return float(np.quantile(val_scores, 1 - fpr))


def train_neural(cfg, name, spec, fs, tr, va, tests):
    mcfg, scfg = cfg["model"], cfg["scoring"]
    idx, sl = fs.subset(spec["mods"])
    Xtr, Xva = tr["X"][:, idx], va["X"][:, idx]
    set_seed(cfg["data"]["seed"])
    if spec["kind"] == "ssl":
        model = MultiModalSSL(sl, mcfg, spec["use_role"], spec.get("lam"))
    else:
        model = MLPAutoencoder(sl, mcfg)
    t0 = time.time()
    hist = train_model(model, Xtr, tr["role"], Xva, va["role"], mcfg, log, tag=name)
    log.info("[%s] trained in %.0fs", name, time.time() - t0)

    w = 0.0 if spec.get("lam") == 0.0 else scfg["xmodal_weight"]
    val_comps = batched_components(model, Xva, va["role"])
    calib = Calibrator(w, spec["role_aware"], scfg["min_role_samples"], scfg.get("min_scale_ratio", 0.5)).fit(val_comps, va["role"])

    def score(X, role):
        return calib.transform(batched_components(model, X[:, idx], role), role)

    t0 = time.time()
    val = score(va["X"], va["role"])
    lat = (time.time() - t0) / len(val) * 1e6            # ms per 1000 flows
    thr = _threshold(val, scfg["target_fpr"])
    test = {d: score(t["X"], t["role"]) for d, t in tests.items()}
    _save_scores(cfg, name, val, thr, test, lat, hist)

    d = cfg["paths"]["work_dir"] / "models"
    d.mkdir(exist_ok=True)
    torch.save(model.state_dict(), d / f"{name}.pt")
    with open(d / f"{name}.pkl", "wb") as f:
        pickle.dump(dict(spec=spec, calibrator=calib, thr=thr, slices=sl, idx=idx), f)

    if scfg.get("latent_knn", True):
        # latent-space detector on the same encoder: role-aware if the method is role-aware (objective 4 + 6)
        variants = [(f"{name}_knn", spec["role_aware"])]
        if spec["kind"] == "ae":
            variants.append((f"{name}_knnrole", True))        # fairness: the baseline with the same role-aware search
        emb_tr, emb_va = batched_embed(model, Xtr, tr["role"]), batched_embed(model, Xva, va["role"])
        for vname, per_role in variants:
            t0 = time.time()
            knn = LatentKNN(scfg.get("knn_k", 5), scfg.get("knn_ref", 10000), scfg.get("knn_ref_role", 5000), per_role,
                            scfg["min_role_samples"], cfg["data"]["seed"]).fit(emb_tr, tr["role"])
            zero = lambda n: np.zeros(n, np.float32)
            vd = knn.distances(emb_va, va["role"])
            # one pooled calibration: the neighbour search is already role-specific, so per-role z-scores would count the role twice
            kc = Calibrator(0.0, False, scfg["min_role_samples"], scfg.get("min_scale_ratio", 0.5)).fit(
                {"rec": vd, "xmod": zero(len(vd))}, va["role"])

            def kscore(X, role, knn=knn, kc=kc):
                dd = knn.distances(batched_embed(model, X[:, idx], role), role)
                return kc.transform({"rec": dd, "xmod": zero(len(dd))}, role)

            kval = kscore(va["X"], va["role"])
            ktest = {dn: kscore(t["X"], t["role"]) for dn, t in tests.items()}
            _save_scores(cfg, vname, kval, _threshold(kval, scfg["target_fpr"]), ktest, (time.time() - t0) / len(kval) * 1e6)
            log.info("[%s] latent kNN scoring done in %.0fs", vname, time.time() - t0)

        if spec["kind"] == "ssl" and len(spec["mods"]) > 1:
            _train_latefuse_knn(cfg, name, model, spec, idx, tr, va, tests)


def _train_latefuse_knn(cfg, name, model, spec, idx, tr, va, tests):
    """Late-fusion latent-kNN: one role-aware LatentKNN per modality (same encoder), combined by
    taking the most anomalous modality's calibrated z-score. Motivation: ablations show a flow's
    anomaly is often visible strongly in a single modality (RQ2); the jointly fused embedding used
    by `{name}_knn` can dilute that signal when the other modalities look normal, so fusing scores
    after per-modality calibration keeps a strong single-modality signal instead of averaging it away.
    """
    scfg = cfg["scoring"]
    vname = f"{name}_latefuse_knn"
    t0 = time.time()
    mod_tr = batched_embed_modalities(model, tr["X"][:, idx], tr["role"])
    mod_va = batched_embed_modalities(model, va["X"][:, idx], va["role"])
    knns, calibs = {}, {}
    for m, e_tr in mod_tr.items():
        knn = LatentKNN(scfg.get("knn_k", 5), scfg.get("knn_ref", 10000), scfg.get("knn_ref_role", 5000),
                        spec["role_aware"], scfg["min_role_samples"], cfg["data"]["seed"]).fit(e_tr, tr["role"])
        d_va = knn.distances(mod_va[m], va["role"])
        zero = np.zeros(len(d_va), np.float32)
        calibs[m] = Calibrator(0.0, False, scfg["min_role_samples"], scfg.get("min_scale_ratio", 0.5)).fit(
            {"rec": d_va, "xmod": zero}, va["role"])
        knns[m] = knn

    def lf_score(X, role):
        mod_e = batched_embed_modalities(model, X[:, idx], role)
        zs = [calibs[m].transform({"rec": knns[m].distances(e, role), "xmod": np.zeros(len(e), np.float32)}, role)
              for m, e in mod_e.items()]
        return np.max(np.stack(zs, 0), 0)

    kval = lf_score(va["X"], va["role"])
    ktest = {dn: lf_score(t["X"], t["role"]) for dn, t in tests.items()}
    _save_scores(cfg, vname, kval, _threshold(kval, scfg["target_fpr"]), ktest, (time.time() - t0) / len(kval) * 1e6)
    log.info("[%s] late-fusion latent kNN scoring done in %.0fs", vname, time.time() - t0)


def train_baseline(cfg, name, spec, tr, va, sup, tests):
    b, seed = cfg["baselines"], cfg["data"]["seed"]
    if spec["kind"] == "rf":
        model, thr = SupervisedRF(b["rf_trees"], seed).fit(sup["X"], sup["y"]), 0.5
    elif spec["kind"] == "iforest":
        model = IForest(b["n_fit_rows"], b["iforest_trees"], seed).fit(tr["X"])
    else:
        model = PCARecon(b["n_fit_rows"], seed).fit(tr["X"])
    t0 = time.time()
    val = model.score(va["X"])
    lat = (time.time() - t0) / len(val) * 1e6
    if spec["kind"] != "rf":
        thr = _threshold(val, cfg["scoring"]["target_fpr"])
    _save_scores(cfg, name, val, thr, {d: model.score(t["X"]) for d, t in tests.items()}, lat)


def run_train(cfg, only=None):
    fs = load_feature_space(cfg)
    tr, va, sup = (load_split(cfg, n) for n in ("train", "val", "sup"))
    tests = {d: load_split(cfg, f"test_{d}") for d in cfg["data"]["test_days"]}
    for name, spec in method_specs(fs).items():
        if only and name not in only:
            continue
        log.info("=== %s ===", name)
        if spec["kind"] in ("ssl", "ae"):
            train_neural(cfg, name, spec, fs, tr, va, tests)
        else:
            train_baseline(cfg, name, spec, tr, va, sup, tests)
    if (not only or "suricata_signature" in only) and "sig" in va:
        log.info("=== suricata_signature (decisions of Suricata's ET rules, no training) ===")
        _save_scores(cfg, "suricata_signature", va["sig"].astype(np.float32), 0.5,
                     {d: t["sig"].astype(np.float32) for d, t in tests.items()}, 0.0)
