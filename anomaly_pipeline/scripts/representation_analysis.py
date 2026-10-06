"""X3 (results_comparison/PREREGISTRATION.md): representation analysis on CIC-IDS2017 P1, POST HOC and descriptive.

    python scripts/representation_analysis.py

Saved models of seeds 42 / 1 / 2 (work_cic2017_monday/models, results_cic2017_monday_seed<N>/models), no retraining. Spaces: the
standardised input features and the latent embeddings of ssl_mm_role, ssl_no_contrastive, ssl_mm_global and ae_concat. Sample: 20,000
benign training flows (reference) and up to 2,000 test flows per label (seed 0). Output: results_comparison/representation/.
"""
import pickle
import sys
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.manifold import TSNE
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_pipeline.data import load_split                       # noqa: E402
from ids_pipeline.features import ROLE_NAMES                    # noqa: E402
from ids_pipeline.models import MLPAutoencoder, MultiModalSSL, batched_embed  # noqa: E402
from ids_pipeline.utils import load_config                      # noqa: E402

OUT = ROOT / "results_comparison" / "representation"
MODELS = ["ssl_mm_role", "ssl_no_contrastive", "ssl_mm_global", "ae_concat"]
SEEDS = {42: ROOT / "work_cic2017_monday" / "models", 1: ROOT / "results_cic2017_monday_seed1" / "models",
         2: ROOT / "results_cic2017_monday_seed2" / "models"}
N_REF, N_PER_LABEL, K = 20_000, 2_000, 10


def load_model(cfg, name, seed):
    d = SEEDS[seed]
    meta = pickle.load(open(d / f"{name}.pkl", "rb"))
    spec = meta["spec"]
    if spec["kind"] == "ssl":
        m = MultiModalSSL(meta["slices"], cfg["model"], spec["use_role"], spec.get("lam"), spec.get("fn_mask", False))
    else:
        m = MLPAutoencoder(meta["slices"], cfg["model"])
    m.load_state_dict(torch.load(d / f"{name}.pt", map_location="cpu"))
    m.eval()
    return m, meta["idx"]


def knn_idx(Q, R, k, exclude_self=False):
    out = []
    for i in range(0, len(Q), 2048):
        d = torch.cdist(torch.from_numpy(Q[i:i + 2048]), torch.from_numpy(R))
        if exclude_self:
            d[torch.arange(d.shape[0]), torch.arange(i, i + d.shape[0])] = np.inf
        out.append(d.topk(k, largest=False))
    return torch.cat([o.values for o in out]).numpy(), torch.cat([o.indices for o in out]).numpy()


def knn_dist(Q, R, k=5):
    return knn_idx(Q, R, k)[0].mean(1)


def linear_cka(A, B):
    A, B = A - A.mean(0), B - B.mean(0)
    return float(np.linalg.norm(B.T @ A) ** 2 / (np.linalg.norm(A.T @ A) * np.linalg.norm(B.T @ B)))


def participation_ratio(E):
    ev = np.clip(np.linalg.eigvalsh(np.cov(E.T)), 0, None)
    return float(ev.sum() ** 2 / (ev ** 2).sum())


def main():
    cfg = load_config(ROOT / "config_cic2017_monday.yaml")
    rs = np.random.RandomState(0)
    tr = load_split(cfg, "train")
    ref = rs.choice(len(tr["X"]), min(N_REF, len(tr["X"])), replace=False)
    Xr, rr = tr["X"][ref], tr["role"][ref]
    parts = [load_split(cfg, f"test_{d}") for d in cfg["data"]["test_days"]]
    X, role, label = (np.concatenate([p[k] for p in parts]) for k in ("X", "role", "label"))
    pick = np.concatenate([rs.choice(np.flatnonzero(label == lab), min(N_PER_LABEL, int((label == lab).sum())), replace=False)
                           for lab in np.unique(label)])
    Xt, rt, lt = X[pick], role[pick], label[pick]
    yt = (lt != "Benign").astype(int)
    del parts, X, role, label

    spaces = {("input", 0): (Xr, Xt)}
    for name in MODELS:
        for seed in SEEDS:
            m, idx = load_model(cfg, name, seed)
            spaces[(name, seed)] = (batched_embed(m, Xr[:, idx], rr), batched_embed(m, Xt[:, idx], rt))
    rows, role_rows = [], []
    cv = StratifiedKFold(5, shuffle=True, random_state=0)
    for (name, seed), (Er, Et) in spaces.items():
        Er, Et = np.ascontiguousarray(Er, np.float32), np.ascontiguousarray(Et, np.float32)
        _, nb = knn_idx(Et, Et, K, exclude_self=True)
        same_label = (lt[nb] == lt[:, None]).mean(1)
        same_role = (rt[nb] == rt[:, None]).mean(1)
        d_glob = knn_dist(Et, Er)
        d_role = np.zeros(len(Et), np.float32)
        for r in np.unique(rt):
            m = rt == r
            pool = Er[rr == r] if (rr == r).sum() >= 50 else Er
            d_role[m] = knn_dist(Et[m], pool)
        probe = cross_val_predict(make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)), Et, yt, cv=cv,
                                  method="predict_proba")[:, 1]
        rows.append(dict(space=name, seed=seed, dim=Et.shape[1],
                         label_purity_at10_attacks=float(same_label[yt == 1].mean()),
                         label_purity_at10_benign=float(same_label[yt == 0].mean()),
                         macro_label_purity_at10=float(pd.Series(same_label).groupby(lt).mean().mean()),
                         role_purity_at10=float(same_role.mean()),
                         knn_auc_global=roc_auc_score(yt, d_glob), knn_auc_same_role=roc_auc_score(yt, d_role),
                         linear_probe_auc=roc_auc_score(yt, probe), participation_ratio=participation_ratio(Er)))
        for r in np.unique(rt):
            m = rt == r
            if 0 < yt[m].sum() < m.sum() and min(yt[m].sum(), (1 - yt[m]).sum()) >= 50:
                role_rows.append(dict(space=name, seed=seed, role=ROLE_NAMES[r], attacks=int(yt[m].sum()), benign=int((1 - yt[m]).sum()),
                                      knn_auc_same_role=roc_auc_score(yt[m], d_role[m]), knn_auc_global=roc_auc_score(yt[m], d_glob[m])))
        print(rows[-1], flush=True)

    stab = []
    for name in MODELS:
        for a, b in combinations(SEEDS, 2):
            Ea, Eb = spaces[(name, a)][1], spaces[(name, b)][1]
            _, na = knn_idx(np.ascontiguousarray(Ea), np.ascontiguousarray(Ea), K, True)
            _, nb = knn_idx(np.ascontiguousarray(Eb), np.ascontiguousarray(Eb), K, True)
            jac = np.mean([len(set(x) & set(y)) / len(set(x) | set(y)) for x, y in zip(na, nb)])
            stab.append(dict(space=name, seeds=f"{a}-{b}", linear_cka=linear_cka(Ea, Eb), knn10_jaccard=float(jac)))

    OUT.mkdir(parents=True, exist_ok=True)
    met = pd.DataFrame(rows)
    met.round(4).to_csv(OUT / "metrics_per_seed.csv", index=False)
    summ = met.drop(columns="seed").groupby("space", sort=False).agg(["mean", "std"])
    summ.columns = [f"{a}_{b}" for a, b in summ.columns]
    summ.round(4).to_csv(OUT / "metrics_summary.csv")
    pd.DataFrame(role_rows).round(4).to_csv(OUT / "per_role.csv", index=False)
    pd.DataFrame(stab).round(4).to_csv(OUT / "stability.csv", index=False)
    print(summ.round(3).T.to_string())
    print(pd.DataFrame(stab).groupby("space").mean(numeric_only=True).round(3).to_string())
    tsne_figure(spaces, lt, rs)


# attack families for the figure (15 labels cannot be told apart by colour); fixed categorical order, benign as neutral context
FAMILIES = {"DoS": ["DoS Hulk", "DoS GoldenEye", "DoS Slowloris", "DoS Slowhttptest", "Heartbleed"], "DDoS": ["DDoS"],
            "Brute force (FTP/SSH)": ["FTP-Patator", "SSH-Patator"],
            "Web attack": ["Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - SQL Injection"],
            "Scan": ["Portscan", "Infiltration - Portscan"], "Botnet / infiltration": ["Botnet", "Infiltration"]}
FAMILY_COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#4a3aa7"]   # reference palette slots 1-6
BENIGN, SURFACE, INK, MUTED = "#c3c2b7", "#fcfcfb", "#0b0b0b", "#52514e"


def tsne_figure(spaces, lt, rs):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    sub = np.concatenate([rs.choice(np.flatnonzero(lt == lab), min(400, int((lt == lab).sum())), replace=False) for lab in np.unique(lt)])
    fam = np.full(len(lt), "Benign", dtype=object)
    for f, labs in FAMILIES.items():
        fam[np.isin(lt, labs)] = f
    show = [("input", 0), ("ssl_mm_role", 42), ("ssl_no_contrastive", 42), ("ae_concat", 42)]
    titles = {"input": "Input features (70)", "ssl_mm_role": "SSL, role-aware", "ssl_no_contrastive": "SSL, no contrastive term",
              "ae_concat": "Autoencoder"}
    fig, axes = plt.subplots(1, 4, figsize=(20, 5.6), facecolor=SURFACE)
    for ax, key in zip(axes, show):
        Z = TSNE(2, init="pca", random_state=0, perplexity=30).fit_transform(spaces[key][1][sub])
        f = fam[sub]
        ax.scatter(*Z[f == "Benign"].T, s=5, color=BENIGN, linewidths=0, label="Benign")
        for name, col in zip(FAMILIES, FAMILY_COLORS):
            m = f == name
            ax.scatter(*Z[m].T, s=9, color=col, edgecolors=SURFACE, linewidths=0.3, label=name)
        ax.set_facecolor(SURFACE)
        ax.set_title(titles[key[0]] + ("" if key[0] == "input" else f" (seed {key[1]})"), color=INK, fontsize=11, loc="left")
        ax.set_xticks([])
        ax.set_yticks([])
        for sp in ax.spines.values():
            sp.set_color("#e1e0d9")
    leg = axes[-1].legend(markerscale=2.5, fontsize=9, bbox_to_anchor=(1.02, 1), loc="upper left", frameon=False)
    for t in leg.get_texts():
        t.set_color(MUTED)
    fig.suptitle("CIC-IDS2017 P1 test flows: t-SNE of the inputs and of the latent spaces (up to 400 flows per label)",
                 color=INK, fontsize=12, x=0.01, ha="left")
    fig.tight_layout()
    fig.savefig(OUT / "tsne_latent_spaces.png", dpi=130, facecolor=SURFACE)


def tsne_only():
    cfg = load_config(ROOT / "config_cic2017_monday.yaml")
    rs = np.random.RandomState(0)
    tr = load_split(cfg, "train")
    rs.choice(len(tr["X"]), min(N_REF, len(tr["X"])), replace=False)            # keep the RNG stream of main()
    parts = [load_split(cfg, f"test_{d}") for d in cfg["data"]["test_days"]]
    X, role, label = (np.concatenate([p[k] for p in parts]) for k in ("X", "role", "label"))
    pick = np.concatenate([rs.choice(np.flatnonzero(label == lab), min(N_PER_LABEL, int((label == lab).sum())), replace=False)
                           for lab in np.unique(label)])
    Xt, rt, lt = X[pick], role[pick], label[pick]
    spaces = {("input", 0): (None, Xt)}
    for name in ("ssl_mm_role", "ssl_no_contrastive", "ae_concat"):
        m, idx = load_model(cfg, name, 42)
        spaces[(name, 42)] = (None, batched_embed(m, Xt[:, idx], rt))
    tsne_figure(spaces, lt, rs)


if __name__ == "__main__":
    tsne_only() if "--tsne-only" in sys.argv else main()
