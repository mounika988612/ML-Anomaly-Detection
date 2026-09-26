"""E4 / E6 analysis (results_comparison/PREREGISTRATION.md): seed-averaged metrics with paired block-bootstrap CIs.

    python scripts/clean_eval.py --config config_multiday_context_clean.yaml --seeds 42 1 2 --ref ssl_mm_twoview_knn
    python scripts/clean_eval.py --config config_suricata2017.yaml --seeds 42 1 2 3 4 --ref ssl_mm_role_fnmask_knn --methods ...

Seed 42 = the config's own results_dir, seed N = `<results_dir>_seed<N>/` (scripts/multiseed.py). Scores are the final ones of
evaluate.collect_scores (adapted and fixed). Metrics per method and seed:
  roc_auc            pooled ROC-AUC
  macro_attack_auc   mean over attack types of ROC-AUC(that attack vs all benign): each attack type counts once, whatever its size
  recall_at_1pct     recall at the 99th percentile of the TEST benign scores (label-using oracle: ranking quality at 1% FPR)
  recall, fpr        at the deployable threshold (validation or unlabeled day start, 1% target); realized FPR shows calibration
CIs: 10-minute time blocks resampled with replacement within each test day, the same resamples for every method and seed;
the statistic is the seed-mean of each metric and of the paired difference ref - method.
Writes <results_dir>/clean_eval{_adapted,_fixed}[_<tag>].csv
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_pipeline.evaluate import collect_scores   # noqa: E402
from ids_pipeline.utils import load_config          # noqa: E402

DEFAULT = ["ssl_mm_twoview_knn", "ssl_mm_flow_knn", "ssl_only_temporal_context_knn", "ssl_mm_role_knn", "ssl_no_contrastive_knn",
           "ae_twoview_knnrole", "ae_flow_knnrole", "ae_only_temporal_context_knnrole", "ae_concat_knnrole", "iforest", "pca_recon",
           "rf_supervised"]
METRICS = ["roc_auc", "macro_attack_auc", "recall_at_1pct", "recall", "fpr"]


class Ranked:
    """one score vector prepared for fast weighted metrics: ties grouped, groups in ascending score order."""

    def __init__(self, s, y, att, n_att, pred, bins=20000):
        u, self.g = np.unique(s, return_inverse=True)
        self.G = len(u)
        if self.G > bins:
            # rank bins: flows in one bin count as tied, which moves AUC by < 1/bins; keeps every bootstrap resample cheap
            rank = np.cumsum(np.bincount(self.g, minlength=self.G)) - 1       # last rank of each tie group
            self.g = np.minimum(rank[self.g] * bins // len(s), bins - 1)
            self.G = bins
        self.y, self.att, self.n_att, self.pred = y, att, n_att, pred

    def _auc(self, wp, wn):
        """weighted ROC-AUC from per-group positive / negative weights (ties count 1/2)"""
        below = np.cumsum(wn) - wn
        tot = wp.sum() * wn.sum()
        return float((wp * (below + 0.5 * wn)).sum() / tot) if tot > 0 else np.nan

    def metrics(self, w):
        # one bincount over (score group, class): class 0 = benign, 1 + a = attack type a
        if not hasattr(self, "cell"):
            self.cell = self.g * (self.n_att + 1) + np.where(self.y == 1, self.att + 1, 0)
        tab = np.bincount(self.cell, w, self.G * (self.n_att + 1)).reshape(self.G, self.n_att + 1)
        wn, wp = tab[:, 0], tab[:, 1:].sum(1)
        out = dict(roc_auc=self._auc(wp, wn))
        aucs = [self._auc(tab[:, 1 + a], wn) for a in range(self.n_att) if tab[:, 1 + a].sum() > 0]
        out["macro_attack_auc"] = float(np.mean(aucs))
        # oracle threshold: smallest score group such that the benign weight strictly above it is <= 1%
        above_n = wn[::-1].cumsum()[::-1] - wn                # benign weight strictly above each group
        ok = np.where(above_n <= 0.01 * wn.sum())[0]
        t = ok.min() if len(ok) else self.G - 1
        out["recall_at_1pct"] = float(wp[t + 1:].sum() / max(wp.sum(), 1e-12))
        out["recall"] = float((w * self.pred * (self.y == 1)).sum() / max((w * (self.y == 1)).sum(), 1e-12))
        out["fpr"] = float((w * self.pred * (self.y == 0)).sum() / max((w * (self.y == 0)).sum(), 1e-12))
        return out


def seed_cfg(config, seed, results_dir=None):
    cfg = load_config(config)
    if results_dir:
        cfg["paths"]["results_dir"] = Path(results_dir).resolve()
    if seed != cfg["data"]["seed"]:
        base = cfg["paths"]["results_dir"]
        cfg["paths"]["results_dir"] = base.parent / f"{base.name}_seed{seed}"
    return cfg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--seeds", type=int, nargs="+", required=True)
    ap.add_argument("--ref", default="ssl_mm_twoview_knn")
    ap.add_argument("--methods", nargs="*", default=DEFAULT)
    ap.add_argument("--boot", type=int, default=500)
    ap.add_argument("--block-sec", type=int, default=600)
    ap.add_argument("--tag", default="")
    ap.add_argument("--modes", nargs="*", default=["adapted", "fixed"])
    ap.add_argument("--results-dir", help="evaluate scores in this directory instead of the config's (e.g. a knn_reference.py variant)")
    args = ap.parse_args()
    base_cfg = load_config(args.config)
    res = Path(args.results_dir).resolve() if args.results_dir else base_cfg["paths"]["results_dir"]
    for mode in args.modes:
        adapt = mode == "adapted"
        if adapt and base_cfg["scoring"].get("adapt_window_sec", 1800) <= 0:
            continue
        ranked, t = {}, None
        for seed in args.seeds:
            scores, tt = collect_scores(seed_cfg(args.config, seed, args.results_dir), adapt)
            if t is None:
                t = tt
                names = np.array(sorted(set(t["label"][t["y"] == 1])))
                att = np.where(t["y"] == 1, np.searchsorted(names, t["label"]), -1)
            assert np.array_equal(t["y"], tt["y"]), "seeds evaluated on different rows"
            for m in args.methods:
                if m in scores:
                    ranked[(m, seed)] = Ranked(scores[m]["s"], t["y"], att, len(names), scores[m]["s"] > scores[m]["thr"])
        methods = [m for m in args.methods if all((m, s) in ranked for s in args.seeds)]
        missing = [m for m in args.methods if m not in methods]
        if missing:
            print(f"[{mode}] not in every seed, skipped: {missing}")
        # blocks: (day, 10-min bin); resampled within each day
        blk = pd.factorize(pd.Series(t["day_of"]).astype(str) + ":" + (t["ts"] // args.block_sec).astype(np.int64).astype(str))[0]
        blk_day = pd.Series(t["day_of"]).groupby(blk).first().to_numpy()
        rng = np.random.default_rng(0)
        point = {k: v.metrics(np.ones(len(t["y"]))) for k, v in ranked.items()}
        boot = {k: [] for k in ranked}
        for _ in range(args.boot):
            cnt = np.zeros(blk.max() + 1)
            for d in np.unique(blk_day):
                ids = np.where(blk_day == d)[0]
                cnt += np.bincount(rng.choice(ids, len(ids)), minlength=len(cnt))
            w = cnt[blk]
            for k, v in ranked.items():
                boot[k].append(v.metrics(w))
        rows = []
        for m in methods:
            r = dict(method=m)
            for met in METRICS:
                vals = np.array([point[(m, s)][met] for s in args.seeds])
                r[f"{met}"], r[f"{met}_seed_std"] = vals.mean(), vals.std(ddof=1) if len(vals) > 1 else 0.0
                b = np.mean([[bb[met] for bb in boot[(m, s)]] for s in args.seeds], 0)
                r[f"{met}_lo"], r[f"{met}_hi"] = np.percentile(b, [2.5, 97.5])
                if args.ref in methods and m != args.ref:
                    ref_pt = np.mean([point[(args.ref, s)][met] for s in args.seeds])
                    rb = np.mean([[bb[met] for bb in boot[(args.ref, s)]] for s in args.seeds], 0)
                    diff = rb - b
                    r[f"d_{met}"] = ref_pt - vals.mean()
                    r[f"d_{met}_lo"], r[f"d_{met}_hi"] = np.percentile(diff, [2.5, 97.5])
            rows.append(r)
        out = pd.DataFrame(rows)
        sfx = f"_{mode}" + (f"_{args.tag}" if args.tag else "")
        out.round(4).to_csv(res / f"clean_eval{sfx}.csv", index=False)
        pd.set_option("display.width", 300)
        show = ["method"] + [c for c in out.columns if c in METRICS or (c.startswith("d_") and not c.endswith(("_lo", "_hi")))]
        print(f"\n=== {args.config} [{mode}] seeds {args.seeds}, ref {args.ref}, {args.boot} block resamples")
        print(out[show].round(3).to_string(index=False))
        dcols = [c for c in out.columns if c.startswith("d_") and c.endswith(("_lo", "_hi"))]
        if dcols:
            print("\npaired difference CIs (ref - method):")
            print(out[["method"] + dcols].round(3).to_string(index=False))


if __name__ == "__main__":
    main()
