"""Label-free hyperparameter search for ssl_mm_role (MultiModalSSL, role-aware).

Selection criterion is a pseudo-anomaly test on BENIGN validation data only (no attack labels are
touched, preserving the zero-day protocol): synthetic anomalies are built by (a) shuffling one
modality's feature block across rows (breaks cross-modal consistency -> tests whether the
contrastive term is earning its keep) and (b) pushing a random subset of feature columns per row to
an extreme value (tests reconstruction sensitivity). For each candidate we train the model, fit a
role-aware LatentKNN on training embeddings (same detector used in production), and report the
ROC-AUC of real benign validation flows vs. each synthetic-anomaly set using that detector's score.

Usage:
    python scripts/hparam_search.py --config config_multiday.yaml --stage contrastive_weight
    python scripts/hparam_search.py --config config_multiday.yaml --stage mask_ratio --contrastive-weight 0.0
    python scripts/hparam_search.py --config config_multiday.yaml --stage latent_dim --contrastive-weight 0.0 --mask-ratio 0.25

Writes results/hparam_search_<stage>.csv (appended) and prints a ranked table.
"""
import argparse
import copy
import sys
import time
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ids_pipeline.data import load_feature_space, load_split
from ids_pipeline.models import MultiModalSSL, train_model
from ids_pipeline.scoring import LatentKNN
from ids_pipeline.utils import get_logger, load_config, set_seed

log = get_logger()
SEED = 0


def make_pseudo_anomalies(rs, X, slices, clip):
    """Two synthetic-anomaly sets built from real benign X (no labels used)."""
    n, d = X.shape
    out = {}
    # (a) modality shuffle: permute one whole modality block across rows independently per row-batch
    Xs = X.copy()
    mods = list(slices)
    m = mods[rs.randint(len(mods))]
    a, b = slices[m]
    perm = rs.permutation(n)
    Xs[:, a:b] = X[perm][:, a:b]
    out["modality_shuffle"] = Xs
    # (b) extreme features: push ~15% of columns per row to +-clip
    Xe = X.copy()
    k = max(1, int(d * 0.15))
    for i in range(n):
        cols = rs.choice(d, k, replace=False)
        Xe[i, cols] = np.where(rs.rand(k) < 0.5, -clip, clip)
    out["feature_extreme"] = Xe
    return out


def auc(benign_scores, anom_scores):
    y = np.concatenate([np.zeros(len(benign_scores)), np.ones(len(anom_scores))])
    s = np.concatenate([benign_scores, anom_scores])
    order = np.argsort(s)
    ranks = np.empty(len(s))
    ranks[order] = np.arange(1, len(s) + 1)
    n1, n0 = (y == 1).sum(), (y == 0).sum()
    return float((ranks[y == 1].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))


def run_candidate(cfg, fs, tr, va, overrides, n_pseudo=4000):
    mcfg = copy.deepcopy(cfg["model"])
    mcfg.update(overrides)
    idx, sl = fs.subset(list(fs.slices))
    Xtr, Xva = tr["X"][:, idx], va["X"][:, idx]
    set_seed(SEED)
    model = MultiModalSSL(sl, mcfg, use_role=True)
    t0 = time.time()
    hist = train_model(model, Xtr, tr["role"], Xva, va["role"], mcfg, log, tag=str(overrides))
    train_s = time.time() - t0

    from ids_pipeline.models import batched_embed
    emb_tr = batched_embed(model, Xtr, tr["role"])
    knn = LatentKNN(cfg["scoring"].get("knn_k", 5), cfg["scoring"].get("knn_ref", 10000),
                    cfg["scoring"].get("knn_ref_role", 5000), True, cfg["scoring"]["min_role_samples"], cfg["data"]["seed"])
    knn.fit(emb_tr, tr["role"])

    rs = np.random.RandomState(1)
    n = min(n_pseudo, len(Xva))
    pick = rs.choice(len(Xva), n, replace=False)
    Xb, rb = Xva[pick], va["role"][pick]
    d_benign = knn.distances(batched_embed(model, Xb, rb), rb)

    aucs = {}
    for name, Xp in make_pseudo_anomalies(rs, Xb, sl, mcfg.get("clip", cfg["data"]["clip"])).items():
        d_anom = knn.distances(batched_embed(model, Xp, rb), rb)
        aucs[name] = auc(d_benign, d_anom)
    aucs["mean"] = float(np.mean(list(aucs.values())))
    aucs["train_s"] = round(train_s, 1)
    aucs["epochs_run"] = len(hist)
    return aucs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config_multiday.yaml")
    ap.add_argument("--stage", required=True, choices=["contrastive_weight", "mask_ratio", "latent_dim", "modality_dropout", "epochs"])
    ap.add_argument("--contrastive-weight", type=float, default=None)
    ap.add_argument("--mask-ratio", type=float, default=None)
    ap.add_argument("--latent-dim", type=int, default=None)
    ap.add_argument("--modality-dropout", type=float, default=None)
    ap.add_argument("--epochs", type=int, default=None)
    a = ap.parse_args()

    cfg = load_config(a.config)
    fs = load_feature_space(cfg)
    tr, va = load_split(cfg, "train"), load_split(cfg, "val")

    fixed = {}
    if a.contrastive_weight is not None:
        fixed["contrastive_weight"] = a.contrastive_weight
    if a.mask_ratio is not None:
        fixed["mask_ratio"] = a.mask_ratio
    if a.latent_dim is not None:
        fixed["latent_dim"] = a.latent_dim
    if a.modality_dropout is not None:
        fixed["modality_dropout"] = a.modality_dropout
    if a.epochs is not None:
        fixed["epochs"] = a.epochs

    grids = {
        "contrastive_weight": [0.0, 0.05, 0.1, 0.2, 0.4],
        "mask_ratio": [0.15, 0.25, 0.35],
        "latent_dim": [32, 64],
        "modality_dropout": [0.0, 0.15, 0.25],
        "epochs": [10, 20],
    }
    rows = []
    for val in grids[a.stage]:
        overrides = dict(fixed)
        overrides[a.stage] = val
        if a.stage == "epochs":
            overrides["patience"] = 4
        log.info("=== %s=%s (fixed=%s) ===", a.stage, val, fixed)
        r = run_candidate(cfg, fs, tr, va, overrides)
        r[a.stage] = val
        rows.append(r)
        log.info("    -> %s", r)

    import pandas as pd
    df = pd.DataFrame(rows).sort_values("mean", ascending=False)
    out = cfg["paths"]["results_dir"] / f"hparam_search_{a.stage}.csv"
    df.to_csv(out, index=False)
    log.info("\n%s\nwritten to %s", df.to_string(index=False), out)


if __name__ == "__main__":
    main()
