"""E9 (results_comparison/PREREGISTRATION.md): dev/test round on CIC-IDS2017 P1 score files, no retraining.

    python scripts/e9_devtest.py dev                  # Tuesday only: candidate metrics + the pre-registered selection
    python scripts/e9_devtest.py test --select C3     # Wednesday-Friday, once, after the selection is recorded

Candidates: C0 ssl_mm_role_knn; C1 3-seed ensemble of C0; C2 ssl_mm_experts (min-p of the ssl_only_<modality> experts);
C3 ensemble of C2; C4 min-p(C0, C2); C5 ensemble of C4. Fusions and ensembles use tail scores (-log upper-tail probability
among the method's own benign validation scores). Threshold: 1 - 0.01 quantile of the (fused) validation scores.
Test CIs: paired block bootstrap, 600 s blocks resampled within each test day (scripts/clean_eval.Ranked).
Outputs: results_comparison/E9_dev.csv, E9_test.csv.
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from clean_eval import Ranked                        # noqa: E402
from ids_pipeline.scoring import tail_score          # noqa: E402

SEEDS = ["results_cic2017_monday", "results_cic2017_monday_seed1", "results_cic2017_monday_seed2"]
PROCESSED = ROOT / "work_cic2017_monday" / "processed"
MODS = ["flow", "tcp", "dns", "http", "session"]
DEV, TEST = ["Tuesday"], ["Wednesday", "Thursday", "Friday"]
BASELINES = ["iforest", "ae_concat_knnrole", "pca_recon"]
FPR = 0.01
OUT = ROOT / "results_comparison"


def load(root, name, days):
    z = np.load(ROOT / root / "scores" / f"{name}.npz")
    return z["val"].astype(np.float64), np.concatenate([z[f"test_{d}"] for d in days]).astype(np.float64)


def to_tail(v, t):
    r = np.sort(v)
    return tail_score(v, r, presorted=True), tail_score(t, r, presorted=True)


def min_p(parts):
    tails = [to_tail(v, t) for v, t in parts]
    return np.max([a for a, _ in tails], 0), np.max([b for _, b in tails], 0)


def per_seed(root, days):
    """single-seed score pairs (val, test) of every method"""
    out = {m: load(root, m, days) for m in ["ssl_mm_role_knn"] + BASELINES}
    out["experts"] = min_p([load(root, f"ssl_only_{m}", days) for m in MODS])
    out["knn+experts"] = min_p([out["ssl_mm_role_knn"], out["experts"]])
    return out


def ensemble(pairs):
    tails = [to_tail(v, t) for v, t in pairs]
    return np.mean([a for a, _ in tails], 0), np.mean([b for _, b in tails], 0)


def methods(days):
    seeds = [per_seed(r, days) for r in SEEDS]
    S = lambda k: [s[k] for s in seeds]
    M = {"C0 ssl_mm_role_knn": S("ssl_mm_role_knn"), "C1 ens3(C0)": [ensemble(S("ssl_mm_role_knn"))],
         "C2 ssl_mm_experts": S("experts"), "C3 ens3(C2)": [ensemble(S("experts"))],
         "C4 minp(C0,C2)": S("knn+experts"), "C5 ens3(C4)": [ensemble(S("knn+experts"))]}
    for b in BASELINES:
        M[b] = S(b)
        M[f"{b} ens3"] = [ensemble(S(b))]
    v, t = load(SEEDS[0], "suricata_signature", days)
    M["suricata_signature"] = [(np.zeros_like(v), t)]          # threshold 0.5 below
    return M


def labels(days):
    z = np.load(ROOT / SEEDS[0] / "scores" / "iforest.npz")
    y = np.concatenate([z[f"y_{d}"] for d in days])
    lab = np.concatenate([z[f"label_{d}"] for d in days]).astype(int)
    ts, day_of = [], []
    for d in days:
        p = np.load(PROCESSED / f"test_{d}.npz", allow_pickle=True)
        assert np.array_equal(p["y"], z[f"y_{d}"]), f"processed/score row misalignment on {d}"
        ts.append(p["ts"]), day_of.append(np.full(len(p["ts"]), d))
    return y, lab, len(z["label_names"]), np.concatenate(ts), np.concatenate(day_of)


def thr(name, v):
    return 0.5 if name == "suricata_signature" else np.quantile(v, 1 - FPR)


def mcc_w(w, pred, y):
    tp, fp = (w * pred * (y == 1)).sum(), (w * pred * (y == 0)).sum()
    fn, tn = (w * ~pred * (y == 1)).sum(), (w * ~pred * (y == 0)).sum()
    d = np.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return float((tp * tn - fp * fn) / d) if d > 0 else 0.0


def point(name, pairs, y):
    rows = []
    for v, t in pairs:
        p = t > thr(name, v)
        w = np.ones(len(y))
        rows.append(dict(roc_auc=Ranked(t, y, np.zeros(len(y), int), 1, p).metrics(w)["roc_auc"],
                         pr_auc=average_precision_score(y, t), recall=p[y == 1].mean(), fpr=p[y == 0].mean(),
                         mcc=mcc_w(w, p, y)))
    return pd.DataFrame(rows).mean().to_dict()


def dev():
    y, *_ = labels(DEV)
    M = methods(DEV)
    rows = [dict(method=k, **point(k, v, y)) for k, v in M.items() if k[:2] in ("C0", "C1", "C2", "C3", "C4", "C5")]
    df = pd.DataFrame(rows)
    df.round(4).to_csv(OUT / "E9_dev.csv", index=False)
    print(f"== E9 dev: Tuesday only ({len(y)} flows, {int(y.sum())} attacks) ==")
    print(df.round(3).to_string(index=False))
    best = df.pr_auc.max()
    tied = df[df.pr_auc >= best - 0.005].sort_values("mcc", ascending=False)
    print(f"\nselection rule (highest PR-AUC, ties < 0.005 broken by MCC): {tied.iloc[0].method}")


def test(select):
    y, lab, n_att, ts, day_of = labels(TEST)
    M = methods(TEST)
    sel = next(k for k in M if k.startswith(select + " "))
    ens = "ens3" in sel
    comp = [sel, "C0 ssl_mm_role_knn"] + [f"{b} ens3" if ens else b for b in BASELINES] + ["suricata_signature"]
    comp = list(dict.fromkeys(comp))
    ranked = {k: [Ranked(t, y, lab, n_att, t > thr(k, v)) for v, t in M[k]] for k in comp}
    pts = {k: point(k, M[k], y) for k in comp}
    blk = pd.factorize(pd.Series(day_of).astype(str) + ":" + (ts // 600).astype(np.int64).astype(str))[0]
    blk_day = pd.Series(day_of).groupby(blk).first().to_numpy()
    rng = np.random.default_rng(0)
    boot = {k: {"roc_auc": [], "mcc": []} for k in comp}
    for _ in range(500):
        cnt = np.zeros(blk.max() + 1)
        for d in np.unique(blk_day):
            ids = np.where(blk_day == d)[0]
            cnt += np.bincount(rng.choice(ids, len(ids)), minlength=len(cnt))
        w = cnt[blk]
        for k in comp:
            boot[k]["roc_auc"].append(np.mean([r.metrics(w)["roc_auc"] for r in ranked[k]]))
            boot[k]["mcc"].append(np.mean([mcc_w(w, r.pred, y) for r in ranked[k]]))
    rows = []
    for k in comp:
        r = dict(method=k, **pts[k])
        if k != sel:
            for met in ("roc_auc", "mcc"):
                diff = np.array(boot[sel][met]) - np.array(boot[k][met])
                r[f"sel_minus_{met}"] = pts[sel][met] - pts[k][met]
                r[f"sel_minus_{met}_lo"], r[f"sel_minus_{met}_hi"] = np.percentile(diff, [2.5, 97.5])
        rows.append(r)
    df = pd.DataFrame(rows)
    df.round(4).to_csv(OUT / "E9_test.csv", index=False)
    pd.set_option("display.width", 250)
    print(f"== E9 test: Wednesday-Friday ({len(y)} flows, {int(y.sum())} attacks), selected {sel} ==")
    print(df.round(3).to_string(index=False))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["dev", "test"])
    ap.add_argument("--select", help="test: the candidate chosen on dev, e.g. C3")
    a = ap.parse_args()
    dev() if a.stage == "dev" else test(a.select)
