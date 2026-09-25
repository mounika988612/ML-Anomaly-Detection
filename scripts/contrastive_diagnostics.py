"""Why does the cross-modal contrastive term not help? Diagnostics on trained `ssl_mm_role` vs `ssl_no_contrastive` models (no retraining).

    python scripts/contrastive_diagnostics.py --config config_suricata2017.yaml --seeds 42 1 2 3 4

Seed 42 = the config's own run (work_dir/models, results_dir); seed N = `<results_dir>_seed<N>/` from scripts/multiseed.py.
Label-free (benign train/val only):
  D1 data  in-batch false negatives of the InfoNCE: share of flows in a random 256-flow batch that share one modality block
           exactly with another flow of the batch (same block, different partner -> the two "negatives" cannot be told apart)
  D2 loss  masked reconstruction loss and InfoNCE on validation flows (same masks for both models)
  D3 space fused latent embedding (the kNN input): effective rank, benign kNN distance scale, sensitivity to input noise
  D4 info  ridge R^2 of each modality's own input from its encoder output (retained modality-specific information) and of the
           other modalities' inputs (what the alignment makes shared)
Label-using (test days; diagnosis only, never used to choose anything):
  D5 score ROC-AUC of the latent-kNN score, of the cross-modal inconsistency `xmod` the contrastive head produces but the kNN
           score ignores, and of their min-p fusion; per-attack AUC of the kNN score.
Writes <results_dir>/contrastive_diagnostics{,_per_attack}.csv
"""
import argparse
import itertools
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.linear_model import Ridge
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_pipeline.data import load_split          # noqa: E402
from ids_pipeline.evaluate import min_p           # noqa: E402
from ids_pipeline.models import MultiModalSSL     # noqa: E402
from ids_pipeline.utils import load_config        # noqa: E402

MODELS = ["ssl_mm_role", "ssl_no_contrastive", "ssl_mm_role_fnmask"]
torch.set_num_threads(3)


def dirs(cfg, seed):
    base = cfg["paths"]["results_dir"]
    if seed == cfg["data"]["seed"]:
        return cfg["paths"]["work_dir"] / "models", base
    d = base.parent / f"{base.name}_seed{seed}"
    return d / "models", d


def load_model(mdir, name, cfg):
    with open(mdir / f"{name}.pkl", "rb") as f:
        meta = pickle.load(f)
    spec = meta["spec"]
    m = MultiModalSSL(meta["slices"], cfg["model"], spec["use_role"], spec.get("lam"), spec.get("fn_mask", False))
    m.load_state_dict(torch.load(mdir / f"{name}.pt", map_location="cpu"))
    return m.eval(), meta["idx"], meta["slices"]


def eff_rank(e):
    s = np.linalg.svd(e - e.mean(0), compute_uv=False)
    p = s / s.sum()
    return float(np.exp(-(p * np.log(p + 1e-12)).sum()))


def batch_duplicates(X, sl, rs, n_batches=40, bs=256):
    """share of flows with an exact duplicate of modality block m elsewhere in the batch whose full flow differs"""
    out = {m: [] for m in sl}
    for _ in range(n_batches):
        b = X[rs.choice(len(X), bs, replace=False)]
        full = pd.util.hash_pandas_object(pd.DataFrame(b), index=False).to_numpy()
        for m, (a, c) in sl.items():
            blk = pd.util.hash_pandas_object(pd.DataFrame(b[:, a:c]), index=False).to_numpy()
            dup = np.zeros(bs, bool)
            for i in range(bs):
                same = (blk == blk[i]) & (full != full[i])
                dup[i] = same.any()
            out[m].append(dup.mean())
    return {f"dup_{m}": float(np.mean(v)) for m, v in out.items()}


def ridge_r2(Z, Y, rs):
    ix = rs.permutation(len(Z))
    a, b = ix[: len(ix) // 2], ix[len(ix) // 2:]
    r = Ridge(1.0).fit(Z[a], Y[a])
    res = ((r.predict(Z[b]) - Y[b]) ** 2).sum(0)
    tot = ((Y[b] - Y[b].mean(0)) ** 2).sum(0) + 1e-9
    keep = tot > 1e-6                                   # constant columns carry no information
    return float(1 - res[keep].sum() / tot[keep].sum())


@torch.no_grad()
def forward_parts(model, X, role, bs=16384):
    zs, h, xm = {m: [] for m in model.slices}, [], []
    for i in range(0, len(X), bs):
        x, r = torch.from_numpy(X[i:i + bs]), torch.from_numpy(role[i:i + bs])
        rr = model._role(r, len(x))
        z = [model.enc[m](x[:, a:b]) for m, (a, b) in model.slices.items()]
        ps = [torch.nn.functional.normalize(model.proj[m](zz), dim=-1) for m, zz in zip(model.mods, z)]
        for m, zz in zip(model.mods, z):
            zs[m].append(zz.numpy())
        h.append(model.fuse(torch.cat(z + [rr], 1)).numpy())
        xm.append(torch.stack([1 - (ps[a] * ps[b]).sum(-1) for a, b in itertools.combinations(range(len(ps)), 2)]).mean(0).numpy())
    return {m: np.concatenate(v) for m, v in zs.items()}, np.concatenate(h), np.concatenate(xm)


def knn_dist(q, ref, k=5, bs=4096):
    ref = torch.from_numpy(ref)
    return np.concatenate([torch.cdist(torch.from_numpy(q[i:i + bs]), ref).topk(k, largest=False).values.mean(1).numpy()
                           for i in range(0, len(q), bs)])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--seeds", type=int, nargs="+", required=True)
    ap.add_argument("--n", type=int, default=20000, help="benign flows per label-free diagnostic")
    args = ap.parse_args()
    cfg = load_config(args.config)
    days = cfg["data"]["test_days"]
    tr, va = load_split(cfg, "train"), load_split(cfg, "val")
    tests = {d: load_split(cfg, f"test_{d}") for d in days}
    y = np.concatenate([tests[d]["y"] for d in days])
    lab = np.concatenate([tests[d]["label"] for d in days])
    rows, arows, dup_done = [], [], False
    for seed in args.seeds:
        mdir, rdir = dirs(cfg, seed)
        for name in MODELS:
            if not (mdir / f"{name}.pt").exists():
                print(f"missing {mdir / name}.pt")
                continue
            model, idx, sl = load_model(mdir, name, cfg)
            rs = np.random.RandomState(0)
            row = dict(seed=seed, model=name)
            Xva, rva = va["X"][:, idx], va["role"]
            if not dup_done:
                dup = batch_duplicates(tr["X"][:, idx], sl, rs)
                dup_done = True
            row.update(dup)
            # D2 losses with identical masks
            probe = MultiModalSSL(sl, cfg["model"], True, 0.1)       # only used for its _contrast on this model's projections
            probe_fn = MultiModalSSL(sl, cfg["model"], True, 0.1, fn_mask=True)
            with torch.no_grad():
                torch.manual_seed(0)
                sub = rs.choice(len(Xva), min(len(Xva), 65536), replace=False)
                xv, rv = torch.from_numpy(Xva[sub]), torch.from_numpy(rva[sub])
                _, parts = model.loss(xv, rv)
                recon, ps = model._forward(xv, rv)
                row.update(val_rec_masked=parts["rec"], val_rec_clean=float(((recon - xv) ** 2).mean()),
                           val_infonce=float(np.mean([probe._contrast([p[i:i + 256] for p in ps]).item()
                                                      for i in range(0, len(xv) - 255, 256)])),
                           val_infonce_fnmasked=float(np.mean([probe_fn._contrast([p[i:i + 256] for p in ps], xv[i:i + 256]).item()
                                                               for i in range(0, len(xv) - 255, 256)])),
                           infonce_chance=float(np.log(256)))
            # D3 geometry of the fused embedding
            s_tr = rs.choice(len(tr["X"]), min(len(tr["X"]), 10000), replace=False)
            s_va = rs.choice(len(Xva), min(len(Xva), args.n), replace=False)
            z_va, h_va, xm_va = forward_parts(model, Xva[s_va], rva[s_va])
            _, h_tr, _ = forward_parts(model, tr["X"][s_tr][:, idx], tr["role"][s_tr])
            d_nn = knn_dist(h_va, h_tr)
            noise = Xva[s_va] + rs.normal(0, 0.05, Xva[s_va].shape).astype(np.float32)
            _, h_no, _ = forward_parts(model, noise, rva[s_va])
            pair = np.linalg.norm(h_va[rs.choice(len(h_va), 5000)] - h_va[rs.choice(len(h_va), 5000)], axis=1)
            row.update(emb_eff_rank=eff_rank(h_va), emb_dim=h_va.shape[1],
                       knn_dist_median_over_pair_median=float(np.median(d_nn) / np.median(pair)),
                       knn_dist_p99_over_median=float(np.quantile(d_nn, .99) / np.median(d_nn)),
                       noise_shift_over_knn_median=float(np.median(np.linalg.norm(h_no - h_va, axis=1)) / np.median(d_nn)))
            # D4 information retained per modality
            own, cross = [], []
            for m, (a, b) in sl.items():
                own.append(ridge_r2(z_va[m], Xva[s_va][:, a:b], rs))
                for m2, (a2, b2) in sl.items():
                    if m2 != m:
                        cross.append(ridge_r2(z_va[m], Xva[s_va][:, a2:b2], rs))
                row[f"own_r2_{m}"] = own[-1]
            row.update(own_r2_mean=float(np.mean(own)), cross_r2_mean=float(np.mean(cross)),
                       mod_eff_rank_mean=float(np.mean([eff_rank(z) for z in z_va.values()])))
            # D5 label-using: which score carries the signal
            kz = np.load(rdir / "scores" / f"{name}_knn.npz")
            knn_te = np.concatenate([kz[f"test_{d}"].astype(float) for d in days])
            _, _, xm_ref = forward_parts(model, Xva, rva)
            xm_te = np.concatenate([forward_parts(model, tests[d]["X"][:, idx], tests[d]["role"])[2] for d in days])
            row.update(auc_knn=roc_auc_score(y, knn_te), auc_xmod=roc_auc_score(y, xm_te),
                       auc_knn_minp_xmod=roc_auc_score(y, min_p([knn_te, xm_te], [kz["val"].astype(float), xm_ref])))
            for a in sorted(set(lab[y == 1])):
                k = (lab == a) | (y == 0)
                arows.append(dict(seed=seed, model=name, attack=a, n=int((lab == a).sum()),
                                  auc_knn=roc_auc_score(lab[k] == a, knn_te[k]), auc_xmod=roc_auc_score(lab[k] == a, xm_te[k])))
            rows.append(row)
            print(pd.Series(row).to_string(), flush=True)
    out = pd.DataFrame(rows)
    res = cfg["paths"]["results_dir"]
    out.round(4).to_csv(res / "contrastive_diagnostics.csv", index=False)
    pa = pd.DataFrame(arows)
    pa.round(4).to_csv(res / "contrastive_diagnostics_per_attack.csv", index=False)
    pd.set_option("display.width", 250)
    num = out.drop(columns=["seed"]).groupby("model").agg(["mean", "std"]).T
    print("\n", num.round(4).to_string())
    print("\n", pa.groupby(["attack", "model"])[["auc_knn", "auc_xmod"]].mean().unstack().round(3).to_string())


if __name__ == "__main__":
    main()
