"""EXPLORATORY / POST HOC (not pre-registered): score-level variants of the proposed SSL-MM detector.

Uses only saved score files (`<results dir>/scores/*.npz`); nothing is retrained. Every variant is calibrated on benign
validation scores only (robust z on val, threshold = 1 - target_fpr quantile of val), but the variants were compared on
CIC-IDS2017 P1 after its Tue-Fri labels were known, so the P1 numbers are post hoc. The other datasets (P2, CSE-CIC-IDS2018,
UNSW-NB15) get the same recipe unchanged, which is a weaker but useful check that it is not specific to P1.

  python scripts/explore_fusion.py [--out results_explore]
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, matthews_corrcoef, roc_auc_score

STUDIES = {
    "CIC-IDS2017 P1": ["results_cic2017_monday", "results_cic2017_monday_seed1", "results_cic2017_monday_seed2"],
    "CIC-IDS2017 P2": ["results_suricata2017_rebuilt", "results_suricata2017_rebuilt_seed1", "results_suricata2017_rebuilt_seed2"],
    "CSE-CIC-IDS2018": ["results"],
    "UNSW-NB15": ["results_unsw"],
}
TARGET_FPR = 0.01
MATCHED_FPR = 0.01        # equal realised test FPR for every method (oracle operating point, same for all)


def load(root, name):
    z = np.load(Path(root) / "scores" / f"{name}.npz", allow_pickle=True)
    days = sorted(k[5:] for k in z.files if k.startswith("test_"))
    return (z["val"].astype(np.float64), np.concatenate([z[f"test_{d}"] for d in days]).astype(np.float64),
            np.concatenate([z[f"y_{d}"] for d in days]), z["label_names"][np.concatenate([z[f"label_{d}"] for d in days])])


def modalities(root):
    return sorted(p.stem[9:] for p in (Path(root) / "scores").glob("ssl_only_*.npz") if not p.stem.endswith("_knn"))


def z(val, test):
    """robust z-score fitted on benign validation scores only"""
    med = np.median(val)
    mad = 1.4826 * np.median(np.abs(val - med)) + 1e-9
    return (val - med) / mad, (test - med) / mad


def tail(val, test):
    """-log benign upper-tail probability (as evaluate.tail_score): scale-free, so experts whose benign scores are mostly tied
    (MAD = 0) cannot dominate the fusion"""
    r = np.sort(val)
    f = lambda s: -np.log((len(r) - np.searchsorted(r, s, "right") + 1) / (len(r) + 1))
    return f(val), f(test)


def combine_tail(parts, how="mean"):
    vs, ts = zip(*[tail(v, t) for v, t in parts])
    f = {"mean": np.mean, "max": np.max}[how]
    return f(np.stack(vs), 0), f(np.stack(ts), 0)


def combine(parts, how="mean"):
    vs, ts = zip(*[z(v, t) for v, t in parts])
    f = {"mean": np.mean, "max": np.max}[how]
    return f(np.stack(vs), 0), f(np.stack(ts), 0)


def metrics(val, test, y):
    p = test > np.quantile(val, 1 - TARGET_FPR)
    m = dict(roc_auc=roc_auc_score(y, test), pr_auc=average_precision_score(y, test), recall=p[y == 1].mean(),
             fpr=p[y == 0].mean(), mcc=matthews_corrcoef(y, p))
    pm = test > np.quantile(test[y == 0], 1 - MATCHED_FPR)
    m["recall@fpr1%"], m["mcc@fpr1%"] = pm[y == 1].mean(), matthews_corrcoef(y, pm)
    return m


def variants(root):
    S = lambda n: load(root, n)[:2]
    mods = modalities(root)
    v = {"baseline: iforest": S("iforest"), "baseline: ae_concat_knnrole": S("ae_concat_knnrole"),
         "proposed (E7): ssl_mm_role_knn": S("ssl_mm_role_knn")}
    if (Path(root) / "scores" / "pca_recon.npz").exists():
        v["baseline: pca_recon"] = S("pca_recon")
    if len(mods) > 1:
        v["V5 modality experts (mean z)"] = combine([S(f"ssl_only_{m}") for m in mods])
        v["V4 modality experts (max z)"] = combine([S(f"ssl_only_{m}") for m in mods], "max")
        v["T1 modality experts (mean tail)"] = combine_tail([S(f"ssl_only_{m}") for m in mods])
        v["T2 modality experts (min-p)"] = combine_tail([S(f"ssl_only_{m}") for m in mods], "max")
        for m in mods:
            v[f"  V5 without {m}"] = combine([S(f"ssl_only_{o}") for o in mods if o != m])
            v[f"  single expert {m}"] = S(f"ssl_only_{m}")
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results_explore")
    out = Path(ap.parse_args().out)
    out.mkdir(exist_ok=True)
    pd.set_option("display.width", 220)

    rows, per_attack = [], []
    for study, roots in STUDIES.items():
        y_ref = None
        for seed_i, root in enumerate(roots):
            _, _, y, lab = load(root, "iforest")
            assert y_ref is None or np.array_equal(y, y_ref), f"{study}: test rows differ between seeds"
            y_ref = y
            for name, (vv, tt) in variants(root).items():
                rows.append(dict(study=study, method=name, seed=seed_i, **metrics(vv, tt, y)))
                if name.startswith(("proposed", "V5 ", "T1 ", "T2 ", "baseline")):
                    p = tt > np.quantile(vv, 1 - TARGET_FPR)
                    for a in np.unique(lab[y == 1]):
                        per_attack.append(dict(study=study, method=name, seed=seed_i, attack=a, recall=p[lab == a].mean()))

    df = pd.DataFrame(rows)
    df.to_csv(out / "explore_fusion_per_seed.csv", index=False)
    cols = ["roc_auc", "pr_auc", "recall", "fpr", "mcc", "recall@fpr1%", "mcc@fpr1%"]
    agg = df.groupby(["study", "method"], sort=False)[cols].agg(["mean", "std"]).round(3)
    agg.columns = [f"{a}_{b}" for a, b in agg.columns]
    agg.to_csv(out / "explore_fusion_summary.csv")
    pa = pd.DataFrame(per_attack).groupby(["study", "attack", "method"], sort=False).recall.mean().unstack().round(3)
    pa.to_csv(out / "explore_fusion_recall_per_attack.csv")

    print(agg[[c for c in agg.columns if c.endswith("_mean") or c in ("roc_auc_std", "recall_std")]].to_string())
    print("\n== recall per attack (fixed threshold, seed mean) ==")
    print(pa.to_string())


if __name__ == "__main__":
    main()
