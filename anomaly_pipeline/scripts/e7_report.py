"""E7 / E7a report (results_comparison/PREREGISTRATION.md): CIC-IDS2017 (rebuilt from the official pcaps) as the primary dataset,
proposed SSL vs Suricata ET signatures vs ML baselines, hypotheses H1-H7 checked as pre-registered, and the same methods on
CSE-CIC-IDS2018 (3-day clean, held-out) and UNSW-NB15. Reads only saved outputs; nothing is retrained.
    python scripts/e7_report.py [--p1 config_cic2017_3day.yaml] [--p2 config_cic2017_3day_sup.yaml] [--tag 3day]
Writes results_comparison/E7_<tag>_tables.md, table_E7_<tag>_*.csv, figE7_<tag>_*.png.
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from compare_proposed_vs_baselines import FAMILY, INK, OUT, heatmap, hbar, legend_handles, md, plt  # noqa: E402
from ids_pipeline.utils import load_config  # noqa: E402

PROP = "ssl_mm_role_knn"
SIG, HYB = "suricata_signature", f"hybrid_sig_or_{PROP}"
METHODS = {   # key: (display name, family)
    SIG: ("Suricata ET signatures (rule-based)", "sig"),
    PROP: ("Proposed: multi-modal role-aware SSL (latent kNN)", "proposed"),
    HYB: ("Hybrid: Suricata OR proposed", "proposed"),
    "ae_concat_knnrole": ("Autoencoder + same role-kNN scorer", "ml"),
    "ae_concat": ("Autoencoder (reconstruction error)", "ml"),
    "iforest": ("Isolation Forest", "ml"),
    "pca_recon": ("PCA reconstruction", "ml"),
    "rf_supervised": ("Random Forest (supervised)", "sup"),
}
ABL = {"ssl_mm_global_knn": "SSL without roles (global kNN)", "ssl_no_contrastive_knn": "SSL without contrastive term"}
COLS = ["roc_auc", "pr_auc", "precision", "recall", "f1", "fpr", "mcc", "incident_recall", "false_alerts_per_hour"]


def res_dir(cfg):
    return Path(load_config(ROOT / cfg)["paths"]["results_dir"])


def seed_table(d, sfx=""):
    """seed mean +- std (multiseed_overall) for the learned methods; the signature and hybrid rows come from the seed-42 run
    (the signature is deterministic; the hybrid follows the seed-42 proposed model)."""
    m42 = pd.read_csv(d / f"metrics_overall{sfx}.csv").set_index("method")
    ms = d / f"multiseed_overall{sfx}.csv"
    ms = pd.read_csv(ms).set_index("method") if ms.exists() else None
    rows = {}
    for k in m42.index:
        if ms is not None and k in ms.index:
            r = {c: ms.loc[k, f"{c}_mean"] for c in COLS if f"{c}_mean" in ms}
            r.update({f"{c}_std": ms.loc[k, f"{c}_std"] for c in ("roc_auc", "recall", "mcc") if f"{c}_std" in ms})
            r["n_seeds"] = int(ms.loc[k, "n_seeds"])
        else:
            r = {c: m42.loc[k, c] for c in COLS if c in m42}
            r["n_seeds"] = 1
        rows[k] = r
    return pd.DataFrame(rows).T


def named(t, keys):
    keys = [k for k in keys if k in t.index]
    out = t.loc[keys].copy()
    out.index = [METHODS.get(k, (ABL.get(k, k),))[0] for k in keys]
    return out


def ci(ce, m, met="roc_auc"):
    """paired difference proposed - m with 95% block-bootstrap CI (clean_eval: d = ref - method)."""
    r = ce.loc[m]
    return r[f"d_{met}"], r[f"d_{met}_lo"], r[f"d_{met}_hi"]


def hypotheses(p1, ce1, p2):
    H = []

    def add(h, claim, ok, evidence):
        H.append(dict(H=h, claim=claim, outcome="supported" if ok else "NOT supported", evidence=evidence))

    auc = p1.loc[PROP, "roc_auc"]
    parts, ok = [f"ROC-AUC {auc:.3f}"], auc >= 0.90
    for b in ("ae_concat", "iforest", "pca_recon"):
        d, lo, hi = ci(ce1, b)
        parts.append(f"vs {b} {d:+.3f} [{lo:+.3f}, {hi:+.3f}]")
        ok &= lo > 0
    add("H1", "SSL detects unseen attacks (AUC >= 0.90, beats AE / iForest / PCA)", ok, "; ".join(parts))

    rp, rs, fp = p1.loc[PROP, "recall"], p1.loc[SIG, "recall"], p1.loc[PROP, "fpr"]
    add("H2", "proposed recall > Suricata recall at realised FPR <= 2%", rp > rs and fp <= 0.02,
        f"recall {rp:.3f} vs Suricata {rs:.3f}; proposed FPR {fp:.4f} (Suricata FPR {p1.loc[SIG, 'fpr']:.4f})")

    ih, ip, isg = (p1.loc[k, "incident_recall"] for k in (HYB, PROP, SIG))
    add("H3", "hybrid incident recall >= both alone", ih >= max(ip, isg), f"hybrid {ih:.2f}, proposed {ip:.2f}, Suricata {isg:.2f}")

    singles = [m for m in ce1.index if m.startswith("ssl_only_")]
    parts = [f"{m.replace('ssl_only_', '').replace('_knn', '')} {ci(ce1, m)[0]:+.3f} [{ci(ce1, m)[1]:+.3f}, {ci(ce1, m)[2]:+.3f}]"
             for m in singles]
    add("H4", "multi-modal beats every single telemetry source", all(ci(ce1, m)[1] > 0 for m in singles), "; ".join(parts))

    d, lo, hi = ci(ce1, "ssl_mm_global_knn")
    add("H5", "role-aware beats global", lo > 0, f"{d:+.3f} [{lo:+.3f}, {hi:+.3f}]")

    if p2 is not None and "rf_supervised" in p2.index:
        rr, rpp = p2.loc["rf_supervised", "recall"], p2.loc[PROP, "recall"]
        add("H6", "(P2) supervised RF recall on unseen attacks < proposed", rr < rpp, f"RF {rr:.3f} vs proposed {rpp:.3f}")

    d, lo, hi = ci(ce1, "ae_concat_knnrole")
    add("H7", "gain is not only the kNN scorer (vs AE + same scorer)", lo > 0, f"{d:+.3f} [{lo:+.3f}, {hi:+.3f}]")
    return pd.DataFrame(H)


def monday_signature_fpr():
    """Suricata ET alerts on Monday: pure benign traffic, so every alerted flow is a false positive."""
    f = ROOT.parent / "external" / "cic2017" / "Monday" / "flows.parquet"
    if not f.exists():
        return None
    m = pd.read_parquet(f, columns=["alerted", "start_utc"])
    hours = (m.start_utc.max() - m.start_utc.min()).total_seconds() / 3600
    return dict(flows=len(m), alerted_flows=int(m.alerted.sum()), alerted_share=m.alerted.mean(),
                alerted_flows_per_hour=m.alerted.sum() / hours)


def cross_dataset(p1):
    """same methods on the three datasets; CIC-2018 and UNSW use their existing seed-42 runs (fixed threshold)."""
    sets = {"CIC-IDS2017 (primary, Suricata telemetry)": p1}
    for name, d in (("CSE-CIC-IDS2018 3-day clean (held-out)", ROOT / "results_multiday_context_clean"),
                    ("UNSW-NB15", ROOT / "results_unsw")):
        sets[name] = pd.read_csv(d / "metrics_overall.csv").set_index("method")
    keys = [PROP, "ssl_mm_twoview_knn", "ae_concat_knnrole", "ae_concat", "iforest", "pca_recon", "rf_supervised", SIG]
    names = {**{k: v[0] for k, v in METHODS.items()}, "ssl_mm_twoview_knn": "Proposed two-view SSL (+ temporal context)"}
    rows = []
    for ds, t in sets.items():
        for k in keys:
            if k in t.index:
                rows.append(dict(dataset=ds, method=names[k], **{c: t.loc[k, c] for c in ("roc_auc", "pr_auc", "recall", "fpr", "mcc")}))
    return pd.DataFrame(rows)


def fig_scorecard(t, tag, title):
    keys = [k for k in (SIG, PROP, HYB, "ae_concat_knnrole", "ae_concat", "iforest", "pca_recon", "rf_supervised") if k in t.index]
    fams = [METHODS[k][1] for k in keys]
    names = [METHODS[k][0].replace("Proposed: multi-modal role-aware SSL (latent kNN)", "Proposed SSL") for k in keys]
    fig, axs = plt.subplots(1, 4, figsize=(15, 0.45 * len(keys) + 1.4), sharey=True)
    for ax, (col, ttl) in zip(axs, [("recall", "Recall (attack flows)"), ("mcc", "MCC"),
                                    ("incident_recall", "Incident recall"), ("roc_auc", "ROC-AUC")]):
        hbar(ax, names, t.loc[keys, col].astype(float).clip(lower=0).to_numpy(), fams, ttl, fmt="{:.2f}")
        if HYB in keys:
            ax.patches[keys.index(HYB)].set_hatch("////")
            ax.patches[keys.index(HYB)].set_edgecolor("white")
    fig.legend(handles=legend_handles(sorted(set(fams), key=list(FAMILY).index)), loc="lower center", ncol=4, frameon=False,
               bbox_to_anchor=(0.55, -0.12))
    fig.suptitle(title, x=0.02, y=1.03, ha="left", fontsize=12, color=INK)
    fig.savefig(OUT / f"figE7_{tag}_scorecard.png")
    plt.close(fig)


def fig_cross(cd, tag):
    keys = ["Proposed: multi-modal role-aware SSL (latent kNN)", "Autoencoder + same role-kNN scorer", "Isolation Forest",
            "PCA reconstruction", "Random Forest (supervised)"]
    fams = ["proposed", "ml", "ml", "ml", "sup"]
    dsets = list(dict.fromkeys(cd.dataset))
    fig, axs = plt.subplots(1, len(dsets), figsize=(5 * len(dsets), 3.2), sharey=True)
    for ax, ds in zip(axs, dsets):
        s = cd[cd.dataset == ds].set_index("method")
        v = [s.loc[k, "roc_auc"] if k in s.index else np.nan for k in keys]
        hbar(ax, [k.replace("Proposed: multi-modal role-aware SSL (latent kNN)", "Proposed SSL") for k in keys],
             np.nan_to_num(v), fams, ds, fmt="{:.3f}")
        for i, x in enumerate(v):
            if np.isnan(x):
                ax.texts[i].set_text("")       # hbar's value label for this row ("0.000")
                ax.text(0.01, len(keys) - 1 - i, "n/a (no labelled attacks in training)", va="center", fontsize=8, color="#52514e")
    fig.legend(handles=legend_handles(["proposed", "ml", "sup"]), loc="lower center", ncol=3, frameon=False, bbox_to_anchor=(0.5, -0.1))
    fig.suptitle("ROC-AUC on three datasets (fixed benign-validation threshold; unseen attacks except UNSW RF)", x=0.02, y=1.04,
                 ha="left", fontsize=12, color=INK)
    fig.savefig(OUT / f"figE7_{tag}_cross_dataset_auc.png")
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--p1", default="config_cic2017_3day.yaml")
    ap.add_argument("--p2", default="config_cic2017_3day_sup.yaml")
    ap.add_argument("--tag", default="3day")
    a = ap.parse_args()
    d1, d2 = res_dir(a.p1), res_dir(a.p2)
    p1, p1a = seed_table(d1), seed_table(d1, "_adapted")
    p2 = seed_table(d2) if (d2 / "metrics_overall.csv").exists() else None
    ce1 = pd.read_csv(next(d1.glob("clean_eval_fixed*_e7.csv"))).set_index("method")
    hyp = hypotheses(p1, ce1, p2)
    cd = cross_dataset(p1)
    ra = pd.read_csv(d1 / "recall_per_attack.csv").set_index("attack")
    keys = [k for k in METHODS if k in ra.columns]
    # per attack: seed mean for the learned methods (multiseed), seed-42 run for the deterministic signature and the hybrid
    msa = d1 / "multiseed_recall_per_attack.csv"
    msa = pd.read_csv(msa).pivot(index="attack", columns="method", values="mean") if msa.exists() else pd.DataFrame()
    pa = pd.DataFrame({METHODS[k][0]: (msa[k] if k in msa.columns else ra[k]) for k in keys}).T
    # threshold metrics per seed: shows whether the operating point is stable across seeds
    seeds = {42: d1, **{s: d1.parent / f"{d1.name}_seed{s}" for s in (1, 2)}}
    per_seed = pd.concat({s: pd.read_csv(d / "metrics_overall.csv").set_index("method")[["roc_auc", "recall", "fpr", "mcc"]]
                          for s, d in seeds.items() if (d / "metrics_overall.csv").exists()}, names=["seed"])
    per_seed = per_seed.reset_index().pivot(index="method", columns="seed")
    per_seed = per_seed.loc[[k for k in (PROP, "ssl_no_contrastive_knn", "ae_concat_knnrole", "iforest", "pca_recon", SIG)
                             if k in per_seed.index]]
    mon = monday_signature_fpr()

    pre = f"table_E7_{a.tag}"
    named(p1, list(METHODS) + list(ABL)).round(4).to_csv(OUT / f"{pre}_P1_fixed.csv")
    named(p1a, list(METHODS) + list(ABL)).round(4).to_csv(OUT / f"{pre}_P1_adapted.csv")
    hyp.to_csv(OUT / f"{pre}_hypotheses.csv", index=False)
    cd.round(4).to_csv(OUT / f"{pre}_cross_dataset.csv", index=False)
    pa.round(4).to_csv(OUT / f"{pre}_recall_per_attack.csv")
    fig_scorecard(p1, a.tag, "CIC-IDS2017 (train Monday, test unseen attacks): proposed SSL vs Suricata vs ML baselines")
    heatmap(pa, ra.loc[pa.columns, "n_flows"].astype(int), "CIC-IDS2017: recall per attack type (fixed threshold, 1% target FPR)",
            f"figE7_{a.tag}_recall_per_attack.png", sep=3)
    fig_cross(cd, a.tag)

    cols = ["roc_auc", "pr_auc", "precision", "recall", "f1", "fpr", "mcc", "incident_recall", "false_alerts_per_hour"]
    with open(OUT / f"E7_{a.tag}_tables.md", "w", encoding="utf-8") as fh:
        fh.write(f"## E7 ({a.tag}): CIC-IDS2017 as primary dataset\n\nP1 = `{a.p1}`, P2 = `{a.p2}`. Learned methods: mean over seeds "
                 "(n_seeds column); signature and hybrid: seed-42 run.\n\n")
        fh.write(f"### Pre-registered hypotheses\n\n{md(hyp, False)}\n\n")
        std = [c for c in ("roc_auc_std", "recall_std", "mcc_std") if c in p1.columns]
        fh.write(f"### P1 overall, fixed threshold\n\n{md(named(p1, list(METHODS) + list(ABL))[cols + std + ['n_seeds']].astype(float))}\n\n")
        fh.write(f"### P1 overall, per-day recalibrated\n\n{md(named(p1a, list(METHODS) + list(ABL))[cols].astype(float))}\n\n")
        if p2 is not None:
            fh.write(f"### P2 overall (train Mon+Tue, test later days), fixed threshold\n\n{md(named(p2, list(METHODS))[cols].astype(float))}\n\n")
        fh.write(f"### P1 recall per attack type (fixed; learned methods: mean of 3 seeds)\n\n{md(pa.astype(float))}\n\n")
        per_seed.columns = [f"{m}_s{s}" for m, s in per_seed.columns]
        fh.write(f"### P1 threshold metrics per seed (fixed)\n\n{md(per_seed.astype(float))}\n\n")
        fh.write(f"### P1 paired differences, proposed minus method (3 seeds, 95% block-bootstrap CI)\n\n"
                 f"{md(ce1[[c for c in ce1.columns if c.startswith('d_roc_auc') or c.startswith('d_recall_at')]].dropna(how='all'))}\n\n")
        fh.write(f"### Cross-dataset comparison (fixed threshold)\n\n{md(cd, False)}\n\n")
        if mon:
            fh.write("### Suricata ET on Monday (benign only): signature false positives\n\n"
                     + "\n".join(f"- {k}: {v:.4g}" if isinstance(v, float) else f"- {k}: {v}" for k, v in mon.items()) + "\n")
    print((OUT / f"E7_{a.tag}_tables.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
