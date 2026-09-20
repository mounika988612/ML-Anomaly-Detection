"""Evaluation: detection metrics, per-attack recall, FPR trade-off, latency and plots."""
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, matthews_corrcoef, precision_recall_curve,
                             roc_auc_score, roc_curve)

from .data import load_split
from .utils import get_logger

log = get_logger()
MAIN = ["ssl_mm_role_knn", "ssl_mm_global_knn", "ae_concat_knn", "ae_concat_knnrole", "ssl_mm_role", "ssl_mm_global", "ae_concat",
        "iforest", "pca_recon", "rf_supervised"]
ABLATION = ["ssl_mm_role_knn", "ssl_mm_global_knn", "ssl_no_contrastive_knn", "ssl_mm_role", "ssl_mm_global", "ssl_no_contrastive",
            "ssl_only_volume_timing", "ssl_only_packet_size", "ssl_only_protocol_flags", "ssl_only_bulk_subflow"]


def binary_metrics(y, s, thr):
    pred = s > thr
    tp, fp = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum())
    fn, tn = int((~pred & (y == 1)).sum()), int((~pred & (y == 0)).sum())
    prec = tp / max(tp + fp, 1)
    rec = tp / max(tp + fn, 1)
    return dict(
        roc_auc=roc_auc_score(y, s), pr_auc=average_precision_score(y, s),
        accuracy=(tp + tn) / len(y), precision=prec, recall=rec,
        f1=2 * prec * rec / max(prec + rec, 1e-12), fpr=fp / max(fp + tn, 1),
        mcc=matthews_corrcoef(y, pred), attack_rate=float(y.mean()))


def time_to_detect(ts, y, label, pred):
    """seconds between the first flow of each attack type and the first flow flagged for it."""
    out = {}
    for lab in sorted(set(label[y == 1])):
        m = label == lab
        first = ts[m].min()
        hit = m & pred
        out[lab] = float(ts[hit].min() - first) if hit.any() else np.nan
    return out


def run_evaluate(cfg):
    for adapt in (False, True):
        if adapt and cfg["scoring"].get("adapt_window_sec", 1800) <= 0:
            continue                                     # dataset without usable timestamps
        _evaluate(cfg, adapt)


def _evaluate(cfg, adapt):
    """adapt=True: per-day recalibration on the first `adapt_window_sec` seconds of each test day
    (treated as unlabeled, robust median/MAD), then that window is excluded from the metrics."""
    sfx = "_adapted" if adapt else ""
    res = cfg["paths"]["results_dir"]
    days = cfg["data"]["test_days"]
    win = cfg["scoring"].get("adapt_window_sec", 1800)
    tests = {d: load_split(cfg, f"test_{d}") for d in days}
    ref = {d: tests[d]["ts"] < tests[d]["ts"].min() + win for d in days}
    keep = {d: ~ref[d] if adapt else np.ones(len(tests[d]["y"]), bool) for d in days}
    cat = lambda key: np.concatenate([tests[d][key][keep[d]] for d in days])
    y, label, ts = cat("y"), cat("label"), cat("ts")
    day_of = np.concatenate([[d] * int(keep[d].sum()) for d in days])
    fpr0 = cfg["scoring"]["target_fpr"]

    scores = {}
    for f in sorted((res / "scores").glob("*.npz")):
        name, z = f.stem, np.load(f)
        do_adapt = adapt and name not in ("rf_supervised", "suricata_signature")      # a supervised classifier is not recalibrated
        s_parts, thr_parts = [], []
        for d in days:
            s = z[f"test_{d}"].astype(np.float64)
            if do_adapt:
                r = s[ref[d]]
                med = np.median(r)
                s = (s - med) / (1.4826 * np.median(np.abs(r - med)) + 1e-6)
            s_parts.append(s[keep[d]])
            thr_parts.append(s[ref[d]] if do_adapt else None)
        def thr_for(fpr, z=z, do_adapt=do_adapt, name=name, thr_parts=thr_parts, s_parts=s_parts):
            if do_adapt:
                return np.concatenate([np.full(len(sp), np.quantile(rp, 1 - fpr))
                                       for sp, rp in zip(s_parts, thr_parts)])
            t = 0.5 if name == "rf_supervised" else float(np.quantile(z["val"], 1 - fpr))
            return np.full(sum(len(sp) for sp in s_parts), t)
        scores[name] = dict(s=np.concatenate(s_parts), thr=thr_for(fpr0), thr_for=thr_for, lat=float(z["lat_ms_per_1k"]))
    if "suricata_signature" in scores:                   # hybrid: Suricata signature alert OR ML alert
        sig = scores["suricata_signature"]["s"]
        for base in ("ssl_mm_role_knn", "ssl_mm_global_knn", "ae_concat_knn", "ssl_mm_role", "ssl_mm_global", "ae_concat"):
            if base in scores:
                m = scores[base]
                scores[f"hybrid_sig_or_{base}"] = dict(s=m["s"] + 1e6 * sig, thr=m["thr"], lat=m["lat"],
                                                        thr_for=lambda fpr, m=m: m["thr_for"](fpr))
    log.info("[%s] evaluating %d methods on %d test flows (%d attacks)",
             "adapted" if adapt else "fixed", len(scores), len(y), y.sum())

    overall, per_day, per_attack, ttd, tradeoff = [], [], [], [], []
    for name, m in scores.items():
        s, thr = m["s"], m["thr"]
        overall.append(dict(method=name, **binary_metrics(y, s, thr), latency_ms_per_1k_flows=m["lat"]))
        pred = s > thr
        for d in days:
            k = day_of == d
            if y[k].sum() and (y[k] == 0).sum():
                per_day.append(dict(method=name, day=d, **binary_metrics(y[k], s[k], thr[k])))
        for lab in sorted(set(label[y == 1])):
            k = label == lab
            per_attack.append(dict(method=name, attack=lab, n=int(k.sum()), recall=float(pred[k].mean())))
        for d in days:
            k = day_of == d
            for lab, t in time_to_detect(ts[k], y[k], label[k], pred[k]).items():
                ttd.append(dict(method=name, day=d, attack=lab, seconds_to_first_detection=t))
        for fpr in (0.001, 0.005, 0.01, 0.02, 0.05):
            p = s > m["thr_for"](fpr)
            tradeoff.append(dict(method=name, fpr_target=fpr, recall=float(p[y == 1].mean()),
                                 precision=float(y[p].mean()) if p.any() else 0.0, test_fpr=float(p[y == 0].mean())))
    pd.DataFrame(overall).round(4).to_csv(res / f"metrics_overall{sfx}.csv", index=False)
    pd.DataFrame(per_day).round(4).to_csv(res / f"metrics_per_day{sfx}.csv", index=False)
    pa = pd.DataFrame(per_attack).pivot(index="attack", columns="method", values="recall").round(4)
    pa.insert(0, "n_flows", pd.DataFrame(per_attack).groupby("attack")["n"].first())
    pa.to_csv(res / f"recall_per_attack{sfx}.csv")
    pd.DataFrame(ttd).round(1).to_csv(res / f"time_to_detection{sfx}.csv", index=False)
    pd.DataFrame(tradeoff).round(4).to_csv(res / f"fpr_recall_tradeoff{sfx}.csv", index=False)
    log.info("\n%s", pd.DataFrame(overall).round(3).to_string(index=False))
    log.info("\nrecall per attack:\n%s", pa[["n_flows"] + [c for c in MAIN if c in pa]].to_string())
    _plots(res, scores, y, pd.DataFrame(overall), sfx)


def _plots(res, scores, y, overall, sfx=""):
    main = [m for m in MAIN if m in scores] + [m for m in scores if m == "suricata_signature" or m.startswith("hybrid_")]
    fig, ax = plt.subplots(1, 2, figsize=(11, 4.5))
    for m in main:
        fpr, tpr, _ = roc_curve(y, scores[m]["s"])
        p, r, _ = precision_recall_curve(y, scores[m]["s"])
        ax[0].plot(fpr, tpr, label=m)
        ax[1].plot(r, p, label=m)
    ax[0].plot([0, 1], [0, 1], "k:", lw=.8)
    ax[0].set(xlabel="FPR", ylabel="TPR", title="ROC (pooled test days)")
    ax[1].set(xlabel="Recall", ylabel="Precision", title="Precision-Recall (pooled test days)")
    ax[0].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(res / f"roc_pr_curves{sfx}.png", dpi=150)
    plt.close(fig)

    if "ssl_mm_role" in scores:
        s = scores["ssl_mm_role"]
        fig, ax = plt.subplots(figsize=(7, 4))
        lo, hi = np.percentile(s["s"], [0.5, 99.5])
        bins = np.linspace(lo, hi, 80)
        ax.hist(s["s"][y == 0], bins, alpha=.6, density=True, label="benign")
        ax.hist(s["s"][y == 1], bins, alpha=.6, density=True, label="attack")
        ax.axvline(float(np.median(s["thr"])), color="k", ls="--", label="threshold (1% val FPR)")
        ax.set(xlabel="anomaly score", ylabel="density", title="ssl_mm_role score distribution")
        ax.legend()
        fig.tight_layout()
        fig.savefig(res / f"score_distribution{sfx}.png", dpi=150)
        plt.close(fig)

    names = [m for m in ABLATION[:6] if m in set(overall.method)] + [m for m in overall.method if m.startswith("ssl_only_")]
    abl = overall[overall.method.isin(names)].set_index("method").reindex(names)
    if len(abl):
        fig, ax = plt.subplots(figsize=(9, 4))
        abl[["roc_auc", "pr_auc", "mcc"]].plot.bar(ax=ax)
        ax.set(title="Ablation: modalities / contrastive term / role awareness", ylabel="score")
        plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
        fig.tight_layout()
        fig.savefig(res / f"ablation{sfx}.png", dpi=150)
        plt.close(fig)
