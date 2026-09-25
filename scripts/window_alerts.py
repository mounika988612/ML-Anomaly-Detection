"""E5 (results_comparison/PREREGISTRATION.md): window-level alerting at a controlled false-alert rate.

    python scripts/window_alerts.py --config config_multiday_context_clean.yaml --seeds 42 1 2

Flow-level alerting at a 1% FPR puts an alert in almost every busy (role, 5-min) window: benign traffic of thousands of flows per
window always has some flows above a 1% threshold. The window test instead asks whether a window has MORE exceedances than benign
traffic would give. For window w of one service role: n = flows, k = flows above the flow-level validation threshold at
`scoring.target_fpr` (q); window score = -log P(Binomial(n, q) >= k); alert if it exceeds the (1 - q) quantile of the window scores of
the benign validation data. The window width is `scoring.incident_gap_sec`. Nothing is tuned and no test label is used for calibration.
It is compared with the current practice: a window alerts if it contains any flow above the flow threshold.
Fixed (validation) calibration only: the adapted protocol's 30-min reference holds too few windows per role.
Metrics: benign-window FPR and false alerts per hour (a window without attack flows that alerts), attack-window recall,
and per attack type the share of its flows that lie in an alerted window.
Writes <results_dir>/window_alerts.csv (per seed) and window_alerts_summary.csv (mean and std over seeds).
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import binom

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_pipeline.data import load_split                 # noqa: E402
from ids_pipeline.evaluate import TWO_VIEW, min_p        # noqa: E402
from ids_pipeline.utils import load_config               # noqa: E402

DEFAULT = ["ssl_mm_twoview_knn", "ae_twoview_knnrole", "ssl_mm_flow_knn", "ssl_only_temporal_context_knn", "ssl_mm_role_knn",
           "ssl_no_contrastive_knn", "ae_concat_knnrole", "iforest"]


def window_counts(ts, role, s, thr, width):
    df = pd.DataFrame({"r": role.astype(np.int64), "w": (ts // width).astype(np.int64), "f": s > thr})
    g = df.groupby(["r", "w"]).f.agg(["sum", "size"])
    return g, pd.MultiIndex.from_frame(df[["r", "w"]])


def window_score(g, q):
    return pd.Series(-binom.logsf(g["sum"].to_numpy() - 1, g["size"].to_numpy(), q), index=g.index)


def load_scores(res, days, name):
    """validation and per-day test scores of a saved method, or of a two-view fusion of two saved methods"""
    if name in TWO_VIEW:
        parts = [load_scores(res, days, p) for p in TWO_VIEW[name]]
        refs = [p[0] for p in parts]
        return min_p(refs, refs), {d: min_p([p[1][d] for p in parts], refs) for d in days}
    z = np.load(res / "scores" / f"{name}.npz")
    return z["val"].astype(np.float64), {d: z[f"test_{d}"].astype(np.float64) for d in days}


def evaluate_method(sv, st, va, tests, q, width):
    thr = np.quantile(sv, 1 - q)
    gv, _ = window_counts(va["ts"], va["role"], sv, thr, width)
    wthr = np.quantile(window_score(gv, q), 1 - q)
    c = dict(tp=0, fp=0, att=0, ben=0, any_tp=0, any_fp=0, hours=0.0)
    cover = {}
    for d, t in tests.items():
        g, idx = window_counts(t["ts"], t["role"], st[d], thr, width)
        att = pd.Series(t["y"], index=idx).groupby(level=[0, 1]).max().reindex(g.index).to_numpy() == 1
        alert = (window_score(g, q) > wthr).to_numpy()
        anyf = g["sum"].to_numpy() > 0
        c["tp"] += int((alert & att).sum()); c["fp"] += int((alert & ~att).sum())
        c["any_tp"] += int((anyf & att).sum()); c["any_fp"] += int((anyf & ~att).sum())
        c["att"] += int(att.sum()); c["ben"] += int((~att).sum())
        c["hours"] += (t["ts"].max() - t["ts"].min()) / 3600
        flow_alert = pd.Series(alert, index=g.index).reindex(idx).to_numpy()
        for a in np.unique(t["label"][t["y"] == 1]):
            k = t["label"] == a
            n0, n1 = cover.get(a, (0, 0))
            cover[a] = (n0 + int(flow_alert[k].sum()), n1 + int(k.sum()))
    out = dict(window_fpr=c["fp"] / max(c["ben"], 1), false_alerts_per_h=c["fp"] / c["hours"], window_recall=c["tp"] / max(c["att"], 1),
               any_window_fpr=c["any_fp"] / max(c["ben"], 1), any_false_alerts_per_h=c["any_fp"] / c["hours"],
               any_window_recall=c["any_tp"] / max(c["att"], 1),
               val_windows=len(gv), benign_test_windows=c["ben"], attack_test_windows=c["att"])
    out.update({f"covered:{a}": n0 / n1 for a, (n0, n1) in cover.items()})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--seeds", type=int, nargs="+", required=True)
    ap.add_argument("--methods", nargs="*", default=DEFAULT)
    args = ap.parse_args()
    cfg = load_config(args.config)
    days, q = cfg["data"]["test_days"], cfg["scoring"]["target_fpr"]
    width = cfg["scoring"].get("incident_gap_sec", 300)
    va = load_split(cfg, "val")
    tests = {d: load_split(cfg, f"test_{d}") for d in days}
    base = cfg["paths"]["results_dir"]
    rows = []
    for seed in args.seeds:
        res = base if seed == cfg["data"]["seed"] else base.parent / f"{base.name}_seed{seed}"
        for m in args.methods:
            try:
                sv, st = load_scores(res, days, m)
            except FileNotFoundError:
                print(f"seed {seed}: {m} missing, skipped")
                continue
            rows.append(dict(seed=seed, method=m, **evaluate_method(sv, st, va, tests, q, width)))
    out = pd.DataFrame(rows)
    out.round(4).to_csv(base / "window_alerts.csv", index=False)
    num = out.drop(columns="seed").groupby("method", sort=False).agg(["mean", "std"])
    num.columns = [f"{a}_{b}" for a, b in num.columns]
    num.round(4).to_csv(base / "window_alerts_summary.csv")
    pd.set_option("display.width", 300)
    show = [c for c in num.columns if c.endswith("_mean") and not c.startswith(("val_", "benign_", "attack_"))]
    print(num[show].round(3).to_string())


if __name__ == "__main__":
    main()
