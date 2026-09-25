"""Proposed SSL (two-view latent-kNN) vs ML baselines vs Suricata/Zeek signatures: tables + figures.

Reads only saved outputs (results*/ CSVs, results_context/scores/*.npz, ../external/pcap/thu22 Suricata/Zeek logs);
nothing is retrained. Writes to results_comparison/.
    python scripts/compare_proposed_vs_baselines.py
"""
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_pipeline.data import T0, load_split          # noqa: E402
from ids_pipeline.evaluate import min_p                # noqa: E402
from ids_pipeline.signature_compare import UTC_OFFSET_S, read_zeek   # noqa: E402
from ids_pipeline.utils import load_config            # noqa: E402

OUT = ROOT / "results_comparison"
OUT.mkdir(exist_ok=True)
CTX, FLOW = ROOT / "results_context", ROOT / "results"
CAPTURE = ROOT.parent / "external" / "pcap" / "thu22"
DAY, ATTACKER = "Thursday-22-02-2018", "18.218.115.60"

# display name, family
METHODS = {
    "ssl_mm_twoview_knn": ("Proposed: two-view SSL (kNN)", "proposed"),
    "ae_concat_knnrole": ("Autoencoder + same role-kNN scorer", "ml"),
    "ae_concat": ("Autoencoder (recon. error)", "ml"),
    "pca_recon": ("PCA reconstruction", "ml"),
    "iforest": ("Isolation Forest", "ml"),
    "rf_supervised": ("Random Forest (supervised)", "sup"),
}
FAMILY = {"proposed": ("#2a78d6", "Proposed SSL"), "ml": ("#eb6834", "Unsupervised ML baseline"),
          "sup": ("#1baf7a", "Supervised ML baseline"), "sig": ("#eda100", "Signature IDS")}
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
plt.rcParams.update({"font.size": 10, "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2,
                     "ytick.color": INK, "axes.spines.top": False, "axes.spines.right": False,
                     "savefig.dpi": 200, "savefig.bbox": "tight", "figure.facecolor": "white"})


def legend_handles(fams):
    return [plt.Rectangle((0, 0), 1, 1, color=FAMILY[f][0], label=FAMILY[f][1]) for f in fams]


def hbar(ax, names, vals, fams, title, xmax=1.0, fmt="{:.3f}"):
    y = np.arange(len(names))[::-1]
    ax.barh(y, vals, color=[FAMILY[f][0] for f in fams], height=0.62, edgecolor="white", linewidth=2)
    for yi, v in zip(y, vals):
        ax.text(v + xmax * 0.01, yi, fmt.format(v), va="center", fontsize=9, color=INK)
    ax.set_yticks(y, names)
    ax.set_xlim(0, xmax * 1.15)
    ax.set_title(title, loc="left", fontsize=11, color=INK)
    ax.xaxis.grid(True, color=GRID, lw=0.8)
    ax.set_axisbelow(True)


# ---------------------------------------------------------------- 1. overall tables
def overall_table():
    rows = []
    for proto, d, prop in (("2-day + context (headline)", CTX, "ssl_mm_twoview_knn"),
                           ("2-day flow-only", FLOW, "ssl_mm_role_knn")):
        for thr, suf in (("per-day recalibrated", "_adapted"), ("fixed (validation)", "")):
            m = pd.read_csv(d / f"metrics_overall{suf}.csv").set_index("method")
            for k in [prop] + [k for k in METHODS if k != "ssl_mm_twoview_knn"]:
                r = m.loc[k]
                name = METHODS.get(k, ("Proposed: SSL-MM role-kNN", "proposed"))[0]
                rows.append(dict(protocol=proto, threshold=thr, method=name, roc_auc=r.roc_auc, pr_auc=r.pr_auc,
                                 precision=r.precision, recall=r.recall, f1=r.f1, fpr=r.fpr, mcc=r.mcc,
                                 incident_recall=r.incident_recall, false_alerts_per_hour=r.false_alerts_per_hour))
    t = pd.DataFrame(rows).round(4)
    t.to_csv(OUT / "table_overall.csv", index=False)
    return t


# ---------------------------------------------------------------- 2. per-attack recall incl. signatures
def signature_flags():
    """Per-flow Suricata / Zeek / proposed flags for the labelled Thu-22 attack flows (same matching as run.py compare)."""
    cfg = load_config(ROOT / "config_context.yaml")
    conn = read_zeek(CAPTURE / "zeek" / "conn.log")
    conn["ts"] = conn.ts.astype(float)
    conn["dur"] = pd.to_numeric(conn.duration, errors="coerce").fillna(0)
    conn = conn[conn["id.orig_h"] == ATTACKER].sort_values("ts").reset_index(drop=True)
    conn["orig_p"] = conn["id.orig_p"].astype(int)
    al = []
    for line in open(CAPTURE / "suri" / "eve.json", encoding="utf-8"):
        e = json.loads(line)
        if e["event_type"] == "alert" and e["alert"]["signature"].startswith("ET "):
            al.append(dict(ts=pd.Timestamp(e["timestamp"]).timestamp(), src=e["src_ip"], sport=e.get("src_port", -1)))
    al = pd.DataFrame(al)
    conn["suricata"] = conn.orig_p.isin(set(al[al.src == ATTACKER].sport))
    notice = read_zeek(CAPTURE / "zeek" / "notice.log")
    notice = notice[notice.note != "CaptureLoss::Too_Little_Traffic"]
    zeek = ATTACKER in set(notice.get("src", pd.Series(dtype=str)))

    t = load_split(cfg, f"test_{DAY}")
    epoch = (T0 - pd.Timestamp("1970-01-01")).total_seconds() + t["ts"] + UTC_OFFSET_S
    # per-day recalibration (evaluate.py `_adapted`): the unlabeled first 30 min are the benign reference, then excluded
    ref = t["ts"] < t["ts"].min() + cfg["scoring"].get("adapt_window_sec", 1800)
    atk = np.where((t["y"] == 1) & ~ref)[0]
    starts, ends = conn.ts.to_numpy(), (conn.ts + conn.dur).to_numpy()
    idx = np.searchsorted(starts, epoch[atk] + 2.0) - 1
    ok = (idx >= 0) & (epoch[atk] <= ends[np.clip(idx, 0, None)] + 5.0)
    matched, mconn = atk[ok], conn.iloc[idx[ok]]

    # proposed two-view, adapted threshold (identical to evaluate.py): min-p over both views, each referenced to the day start
    zf, zc = (np.load(CTX / "scores" / f"{n}.npz") for n in ("ssl_mm_flow_knn", "ssl_only_temporal_context_knn"))
    parts = [zf[f"test_{DAY}"].astype(np.float64), zc[f"test_{DAY}"].astype(np.float64)]
    refs = [p[ref] for p in parts]
    pred = min_p(parts, refs) > np.quantile(min_p(refs, refs), 0.99)
    df = pd.DataFrame({"attack": t["label"][matched], "suricata": mconn.suricata.to_numpy(), "zeek": zeek,
                       "proposed": pred[matched]})
    for k in ("ae_concat_knnrole", "ae_concat", "pca_recon", "iforest", "rf_supervised"):
        s = np.load(CTX / "scores" / f"{k}.npz")[f"test_{DAY}"].astype(np.float64)
        # robust re-scaling in evaluate.py is monotonic, so thresholding the raw score at the reference quantile is equivalent
        thr = 0.5 if k == "rf_supervised" else np.quantile(s[ref], 0.99)
        df[k] = s[matched] > thr
    df["hybrid"] = df.suricata | df.proposed

    # false-alarm volume on the same day: benign flows flagged by the proposed model vs Suricata alerts off the attacker
    ben = (t["y"] == 0) & ~ref
    hours_csv = (t["ts"].max() - t["ts"].min()) / 3600 - 0.5
    hours_pcap = (al.ts.max() - al.ts.min()) / 3600
    fa = pd.DataFrame([
        dict(detector="Suricata ET (alerts from non-attacker sources)", count=int((al.src != ATTACKER).sum()),
             hours=round(hours_pcap, 1)),
        dict(detector="Zeek notices (non-attacker)", count=len(notice), hours=round(hours_pcap, 1)),
        dict(detector="Proposed two-view SSL (benign flows flagged, recalibrated thr.)", count=int((pred & ben).sum()),
             hours=round(hours_csv, 1)),
    ])
    fa["per_hour"] = (fa["count"] / fa.hours).round(1)
    fa.to_csv(OUT / "table_false_alarms_thu22.csv", index=False)
    print(f"matched {ok.sum()}/{len(atk)} attack flows")
    return df, fa


def per_attack_table(sig):
    ra = pd.read_csv(CTX / "recall_per_attack_adapted.csv").set_index("attack")
    rows = {METHODS[k][0]: ra[k] for k in METHODS}
    tab = pd.DataFrame(rows).T
    thu = sig.groupby("attack")[["suricata", "zeek", "hybrid"]].mean()
    for col, name in (("suricata", "Suricata ET signatures"), ("zeek", "Zeek notices"),
                      ("hybrid", "Hybrid: Suricata OR proposed")):
        tab.loc[name] = thu[col].reindex(tab.columns)
    tab.loc["n attack flows"] = ra["n_flows"]
    tab = tab.round(4)
    tab.to_csv(OUT / "table_recall_per_attack.csv")
    # sanity: recomputed proposed recall on Thu-22 must equal evaluate.py's
    chk = sig.groupby("attack").proposed.mean()
    assert np.allclose(chk.values, ra.loc[chk.index, "ssl_mm_twoview_knn"].values, atol=1e-3), chk
    return tab


# ---------------------------------------------------------------- figures
def fig_overall(t):
    sub = t[(t.protocol.str.startswith("2-day + context")) & (t.threshold == "per-day recalibrated")]
    fams = [METHODS[k][1] for k in METHODS]
    fig, axs = plt.subplots(1, 2, figsize=(11, 3.6), sharey=True)
    hbar(axs[0], sub.method, sub.roc_auc, fams, "ROC-AUC")
    hbar(axs[1], sub.method, sub.pr_auc, fams, "PR-AUC")
    axs[0].axvline(0.5, color=INK2, lw=1, ls=":")
    axs[0].text(0.51, 5.45, "chance", fontsize=8, color=INK2, ha="left")
    fig.legend(handles=legend_handles(["proposed", "ml", "sup"]), loc="lower center", ncol=3, frameon=False,
               bbox_to_anchor=(0.55, -0.08))
    fig.suptitle("Ranking quality on unseen attacks, CSE-CIC-IDS2018 (4 test days, 3.4M flows)",
                 x=0.02, y=1.04, ha="left", fontsize=12, color=INK)
    fig.savefig(OUT / "fig1_auc_overall.png")
    plt.close(fig)


def fig_operating_point(t):
    sub = t[(t.protocol.str.startswith("2-day + context")) & (t.threshold == "per-day recalibrated")]
    fams = [METHODS[k][1] for k in METHODS]
    fig, axs = plt.subplots(1, 4, figsize=(15, 3.6), sharey=True)
    for ax, (col, title) in zip(axs, [("recall", "Recall"), ("precision", "Precision"), ("f1", "F1"), ("mcc", "MCC")]):
        hbar(ax, sub.method, sub[col].clip(lower=0), fams, title, fmt="{:.2f}")
    fig.legend(handles=legend_handles(["proposed", "ml", "sup"]), loc="lower center", ncol=3, frameon=False,
               bbox_to_anchor=(0.55, -0.08))
    fig.suptitle("Detection at the operating point (1% target FPR, per-day recalibrated threshold)",
                 x=0.02, y=1.04, ha="left", fontsize=12, color=INK)
    fig.savefig(OUT / "fig2_operating_point.png")
    plt.close(fig)


def fig_per_attack(tab):
    order = ["Suricata ET signatures", "Zeek notices", "Hybrid: Suricata OR proposed"] + [METHODS[k][0] for k in METHODS]
    cols = ["DDOS attack-HOIC", "DDOS attack-LOIC-UDP", "Infilteration", "Bot", "Brute Force -Web",
            "Brute Force -XSS", "SQL Injection"]
    heatmap(tab.loc[order, cols].astype(float), tab.loc["n attack flows", cols].astype(int),
            "Recall per attack type (1% target FPR, per-day recalibrated threshold)", "fig3_recall_per_attack.png")


def heatmap(m, n, title, fname, sep=3):
    order, cols = list(m.index), list(m.columns)
    fig, ax = plt.subplots(figsize=(1.55 * len(cols) + 3, 0.55 * len(order) + 1))
    cmap = matplotlib.colors.LinearSegmentedColormap.from_list("seq", ["#f2f6fc", "#2a78d6", "#0d366b"])
    ax.imshow(np.ma.masked_invalid(m.values), cmap=cmap, vmin=0, vmax=1, aspect="auto")
    for i in range(m.shape[0]):
        for j in range(m.shape[1]):
            v = m.values[i, j]
            if np.isnan(v):
                ax.add_patch(plt.Rectangle((j - .5, i - .5), 1, 1, facecolor="#f4f3f0", hatch="///",
                                           edgecolor="#d6d5d0", lw=0))
                ax.text(j, i, "no pcap", ha="center", va="center", fontsize=8, color=INK2)
            else:
                ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=9,
                        color="white" if v > 0.55 else INK)
    short = lambda c: c.replace("DDOS attack-", "DDoS ").replace("Web Attack - ", "").replace("DoS Slowhttptest", "DoS Slowhttp")
    ax.set_xticks(range(len(cols)), [f"{short(c)}\n(n={k:,})" for c, k in zip(cols, n)], fontsize=8.5)
    ax.set_yticks(range(len(order)), order)
    ax.axhline(sep - 0.5, color="white", lw=4)
    ax.set_xticks(np.arange(-.5, len(cols)), minor=True)
    ax.set_yticks(np.arange(-.5, len(order)), minor=True)
    ax.grid(which="minor", color="white", lw=2)
    ax.tick_params(which="both", length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title(title, loc="left", fontsize=12, color=INK)
    fig.savefig(OUT / fname)
    plt.close(fig)


def fig_signature(sig):
    det = [("suricata", "Suricata ET signatures", "sig"), ("zeek", "Zeek notices", "sig"),
           ("proposed", "Proposed two-view SSL", "proposed"), ("hybrid", "Hybrid: Suricata OR proposed", "proposed"),
           ("ae_concat_knnrole", "Autoencoder + role-kNN", "ml"), ("pca_recon", "PCA reconstruction", "ml"),
           ("iforest", "Isolation Forest", "ml"), ("rf_supervised", "Random Forest (supervised)", "sup")]
    g = sig.groupby("attack")
    atts = ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"]
    fig, axs = plt.subplots(1, 3, figsize=(14, 3.9), sharey=True)
    for ax, a in zip(axs, atts):
        vals = [g.get_group(a)[c].mean() for c, _, _ in det]
        hbar(ax, [d[1] for d in det], vals, [d[2] for d in det], f"{a}  (n={len(g.get_group(a))})", fmt="{:.2f}")
        ax.patches[3].set_hatch("////")
        ax.patches[3].set_edgecolor("white")
    fig.legend(handles=legend_handles(["proposed", "ml", "sup", "sig"]), loc="lower center", ncol=4, frameon=False,
               bbox_to_anchor=(0.55, -0.08))
    fig.suptitle("Signature IDS vs anomaly detection on the Thu-22 web-attack capture (share of attack flows detected)",
                 x=0.02, y=1.04, ha="left", fontsize=12, color=INK)
    fig.savefig(OUT / "fig4_signature_vs_ml_thu22.png")
    plt.close(fig)


def fig_tradeoff():
    tr = pd.read_csv(CTX / "fpr_recall_tradeoff_adapted.csv")
    lines = [("ssl_mm_twoview_knn", "#2a78d6"), ("ae_concat_knnrole", "#eb6834"), ("ae_concat", "#1baf7a"),
             ("pca_recon", "#eda100"), ("iforest", "#e87ba4")]
    fig, ax = plt.subplots(figsize=(8, 4.4))
    for k, c in lines:
        d = tr[tr.method == k].sort_values("fpr_target")
        ax.plot(d.fpr_target * 100, d.recall, color=c, lw=2, marker="o", ms=5, label=METHODS[k][0],
                markeredgecolor="white", markeredgewidth=1.5)
        if k == "ssl_mm_twoview_knn":
            ax.text(d.fpr_target.iloc[-1] * 100 * 1.08, d.recall.iloc[-1], "Proposed", va="center", fontsize=9, color=INK)
    ax.set_xscale("log")
    ax.set_xticks([0.1, 0.5, 1, 2, 5], ["0.1%", "0.5%", "1%", "2%", "5%"])
    ax.set_xlim(0.08, 9)
    ax.set_ylim(0, 1)
    ax.set_xlabel("Target false-positive rate (per-day recalibrated)")
    ax.set_ylabel("Recall (all attack flows)")
    ax.yaxis.grid(True, color=GRID, lw=0.8)
    ax.legend(frameon=False, fontsize=8.5, loc="upper left")
    ax.set_title("Recall vs alert budget", loc="left", fontsize=12, color=INK)
    fig.savefig(OUT / "fig5_fpr_recall_tradeoff.png")
    plt.close(fig)


# ---------------------------------------------------------------- Suricata2017: real multi-source telemetry, Suricata decision per flow
S17_METHODS = {
    "suricata_signature": ("Suricata ET signatures", "sig"),
    "hybrid_sig_or_ssl_mm_role_knn": ("Hybrid: Suricata OR proposed", "proposed"),
    "ssl_mm_role_knn": ("Proposed: SSL-MM role-kNN", "proposed"),
    "ae_concat_knnrole": ("Autoencoder + same role-kNN scorer", "ml"),
    "ae_concat": ("Autoencoder (recon. error)", "ml"),
    "pca_recon": ("PCA reconstruction", "ml"),
    "iforest": ("Isolation Forest", "ml"),
    "rf_supervised": ("Random Forest (supervised)", "sup"),
}


def suricata2017():
    d = ROOT / "results_suricata2017"
    rows = []
    for thr, suf in (("fixed (validation)", ""), ("per-day recalibrated", "_adapted")):
        m = pd.read_csv(d / f"metrics_overall{suf}.csv").set_index("method")
        for k, (name, _) in S17_METHODS.items():
            r = m.loc[k]
            rows.append(dict(threshold=thr, method=name, roc_auc=r.roc_auc, pr_auc=r.pr_auc, precision=r.precision,
                             recall=r.recall, f1=r.f1, fpr=r.fpr, mcc=r.mcc, incident_recall=r.incident_recall,
                             false_alerts_per_hour=r.false_alerts_per_hour))
    t = pd.DataFrame(rows).round(4)
    t.to_csv(OUT / "table_suricata2017_overall.csv", index=False)

    ra = pd.read_csv(d / "recall_per_attack.csv").set_index("attack")
    tab = pd.DataFrame({name: ra[k] for k, (name, _) in S17_METHODS.items()}).T
    cols = ["DDoS", "DoS Hulk", "DoS GoldenEye", "DoS Slowloris", "DoS Slowhttptest", "Portscan", "Botnet",
            "Infiltration", "Heartbleed", "Web Attack - SQL Injection"]
    tab = tab[cols]
    heatmap(tab, ra.loc[cols, "n_flows"].astype(int),
            "CIC-IDS2017 via Suricata telemetry: recall per attack type (fixed validation threshold, 1% target FPR)",
            "fig6_suricata2017_recall_per_attack.png", sep=1)
    tab.loc["n attack flows"] = ra.loc[cols, "n_flows"]
    tab.round(4).to_csv(OUT / "table_suricata2017_recall_per_attack.csv")

    # headline scorecard: proposed vs Suricata vs hybrid
    sub = t[t.threshold == "fixed (validation)"].set_index("method")
    keys = ["Suricata ET signatures", "Proposed: SSL-MM role-kNN", "Hybrid: Suricata OR proposed",
            "Autoencoder + same role-kNN scorer", "Isolation Forest", "Random Forest (supervised)"]
    fams = ["sig", "proposed", "proposed", "ml", "ml", "sup"]
    fig, axs = plt.subplots(1, 4, figsize=(15, 3.4), sharey=True)
    for ax, (col, title) in zip(axs, [("recall", "Recall (attack flows)"), ("mcc", "MCC"),
                                      ("incident_recall", "Incident recall"), ("roc_auc", "ROC-AUC")]):
        hbar(ax, keys, sub.loc[keys, col].clip(lower=0), fams, title, fmt="{:.2f}")
        ax.patches[2].set_hatch("////")
        ax.patches[2].set_edgecolor("white")
    fig.legend(handles=legend_handles(["proposed", "ml", "sup", "sig"]), loc="lower center", ncol=4, frameon=False,
               bbox_to_anchor=(0.55, -0.1))
    fig.suptitle("CIC-IDS2017 via Suricata telemetry (1.15M test flows, 10 attack types): proposed SSL vs Suricata signatures",
                 x=0.02, y=1.04, ha="left", fontsize=12, color=INK)
    fig.savefig(OUT / "fig7_suricata2017_scorecard.png")
    plt.close(fig)
    return t, tab


def md(df, index=True):
    df = df.reset_index() if index else df
    rows = [[str(c) for c in df.columns]] + [[f"{v:.4g}" if isinstance(v, float) else str(v) for v in r] for r in df.to_numpy()]
    return "\n".join("| " + " | ".join(r) + " |" for r in rows[:1] + [["---"] * len(rows[0])] + rows[1:])


def main():
    t = overall_table()
    sig, fa = signature_flags()
    tab = per_attack_table(sig)
    fig_overall(t)
    fig_operating_point(t)
    fig_per_attack(tab)
    fig_signature(sig)
    fig_tradeoff()
    t17, tab17 = suricata2017()
    with open(OUT / "tables.md", "w", encoding="utf-8") as fh:
        for thr in ("fixed (validation)", "per-day recalibrated"):
            s = t17[t17.threshold == thr].drop(columns=["threshold"])
            fh.write(f"### CIC-IDS2017 via Suricata telemetry — {thr} threshold\n\n{md(s, False)}\n\n")
        fh.write(f"### CIC-IDS2017 via Suricata telemetry — recall per attack type (fixed threshold)\n\n{md(tab17)}\n\n")
        for thr in ("per-day recalibrated", "fixed (validation)"):
            for proto in t.protocol.unique():
                s = t[(t.protocol == proto) & (t.threshold == thr)].drop(columns=["protocol", "threshold"])
                fh.write(f"### {proto} — {thr} threshold\n\n{md(s, False)}\n\n")
        fh.write(f"### Recall per attack type (per-day recalibrated threshold)\n\n{md(tab)}\n\n")
        fh.write(f"### False-alarm volume, Thu-22\n\n{md(fa, False)}\n")
    print((OUT / "tables.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
