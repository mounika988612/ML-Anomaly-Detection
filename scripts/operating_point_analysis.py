"""Threshold-free analysis from saved scores (no retraining).

For each config: pooled ROC-AUC with bootstrap 95% CI, per-attack ROC-AUC (attack vs all benign),
and recall at 1/2/5% FPR where the threshold is taken on TEST benign scores (label-using upper bound,
not deployable - it separates ranking quality from calibration/drift).
Usage: python scripts/operating_point_analysis.py [config.yaml ...]
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_pipeline.data import load_split          # noqa: E402
from ids_pipeline.utils import load_config        # noqa: E402

KEY = ["ssl_mm_role_knn", "ssl_mm_global_knn", "ssl_no_contrastive_knn", "ae_concat_knnrole", "ae_concat_knn",
       "ssl_mm_role", "ae_concat", "iforest", "pca_recon", "rf_supervised", "suricata_signature"]
rng = np.random.default_rng(0)


def boot_auc(y, s, n=200, cap=200_000):
    idx = rng.choice(len(y), min(cap, len(y)), replace=False)
    y, s = y[idx], s[idx]
    a = [roc_auc_score(y[b], s[b]) for b in (rng.integers(0, len(y), len(y)) for _ in range(n))]
    return roc_auc_score(y, s), *np.percentile(a, [2.5, 97.5])


def main(cfgs):
    for c in cfgs:
        cfg = load_config(c)
        res, days = cfg["paths"]["results_dir"], cfg["data"]["test_days"]
        tests = {d: load_split(cfg, f"test_{d}") for d in days}
        y = np.concatenate([tests[d]["y"] for d in days])
        lab = np.concatenate([tests[d]["label"] for d in days])
        rows, arows = [], []
        for name in KEY:
            f = res / "scores" / f"{name}.npz"
            if not f.exists():
                continue
            z = np.load(f)
            s = np.concatenate([z[f"test_{d}"].astype(float) for d in days])
            auc, lo, hi = boot_auc(y, s)
            r = dict(method=name, auc=auc, auc_lo=lo, auc_hi=hi)
            for fpr in (0.01, 0.02, 0.05):
                r[f"recall@{int(fpr*100)}%FPR_oracle"] = float((s[y == 1] > np.quantile(s[y == 0], 1 - fpr)).mean())
            rows.append(r)
            for a in sorted(set(lab[y == 1])):
                k = (lab == a) | (y == 0)
                arows.append(dict(method=name, attack=a, n=int((lab == a).sum()), auc=roc_auc_score(y[k] * 0 + (lab[k] == a), s[k])))
        out = pd.DataFrame(rows).round(4)
        out.to_csv(res / "operating_point_oracle.csv", index=False)
        pa = pd.DataFrame(arows).pivot(index=["attack", "n"], columns="method", values="auc").round(3)
        pa.to_csv(res / "per_attack_auc.csv")
        print(f"\n=== {c}\n{out.to_string(index=False)}\n\nper-attack AUC\n{pa.to_string()}")


if __name__ == "__main__":
    main(sys.argv[1:] or ["config.yaml", "config_multiday.yaml", "config_suricata2017.yaml", "config_unsw.yaml"])
