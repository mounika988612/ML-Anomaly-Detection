"""Analyst-facing alert volume: flagged flows aggregated into alerts, the same way for every detector.

One alert = one (entity, fixed 5-min bin) with at least one flagged flow; entity = service role for the ML detectors (the
CSVs have no IPs) and for Suricata on Suricata2017 (same flow table), (signature, source IP) for Suricata's eve.json on the
Thu-22 pcap. An alert is true if it contains an attack flow (Thu-22 pcap: if its source is the attacker), otherwise false.
The bin width is `scoring.incident_gap_sec` (300 s), the existing incident gap; nothing here is tuned.
Thresholds are those of evaluate.py: fixed = 99th pct of benign validation scores; adapted = 99th pct of the unlabeled
first 30 min of each day (then excluded). Writes results_comparison/table_alert_volume.csv and fig8_alert_volume.png.
    python scripts/alert_aggregation.py
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
sys.path.insert(0, str(ROOT / "scripts"))
from compare_proposed_vs_baselines import FAMILY, INK, OUT, hbar, legend_handles   # noqa: E402
from ids_pipeline.data import load_split                                           # noqa: E402
from ids_pipeline.evaluate import min_p                                             # noqa: E402
from ids_pipeline.utils import load_config                                          # noqa: E402

ATTACKER = "18.218.115.60"
NAMES = {"ssl_mm_twoview_knn": ("Proposed: two-view SSL", "proposed"),
         "ssl_mm_role_knn": ("Proposed: SSL-MM role-kNN", "proposed"),
         "ae_concat_knnrole": ("Autoencoder + role-kNN", "ml"), "ae_concat": ("Autoencoder", "ml"),
         "pca_recon": ("PCA reconstruction", "ml"), "iforest": ("Isolation Forest", "ml"),
         "rf_supervised": ("Random Forest (supervised)", "sup"), "suricata_signature": ("Suricata ET signatures", "sig")}


def alerts(ts, key, y, pred, bin_s):
    """(true alerts, false alerts) after grouping flagged flows into (key, time-bin) alerts."""
    df = pd.DataFrame({"k": key[pred], "b": (ts[pred] // bin_s).astype(np.int64), "y": y[pred]})
    g = df.groupby(["k", "b"]).y.max()
    return int(g.sum()), int((g == 0).sum())


def row(dataset, scope, name, ts, key, y, pred, hours, bin_s, n_inc=None):
    tp, fp = alerts(ts, key, y, pred, bin_s)
    return dict(dataset=dataset, scope=scope, method=NAMES[name][0], family=NAMES[name][1],
                flagged_benign_flows_per_h=round(float((pred & (y == 0)).sum()) / hours, 1),
                false_alerts_per_h=round(fp / hours, 2), true_alerts=tp, alert_precision=round(tp / max(tp + fp, 1), 3),
                attack_flow_recall=round(float(pred[y == 1].mean()), 4))


def cic_context(bin_s):
    cfg = load_config(ROOT / "config_context.yaml")
    res, days = cfg["paths"]["results_dir"], cfg["data"]["test_days"]
    win = cfg["scoring"]["adapt_window_sec"]
    methods = ["ssl_mm_twoview_knn", "ae_concat_knnrole", "ae_concat", "pca_recon", "iforest", "rf_supervised"]
    z = {m: np.load(res / "scores" / f"{m}.npz") for m in methods[1:] + ["ssl_mm_flow_knn", "ssl_only_temporal_context_knn"]}
    per = {m: [] for m in methods}
    cols = {k: [] for k in ("ts", "role", "y", "day")}
    for d in days:
        t = load_split(cfg, f"test_{d}")
        ref = t["ts"] < t["ts"].min() + win
        keep = ~ref
        parts = [z[p][f"test_{d}"].astype(np.float64) for p in ("ssl_mm_flow_knn", "ssl_only_temporal_context_knn")]
        refs = [p[ref] for p in parts]
        per["ssl_mm_twoview_knn"].append((min_p(parts, refs) > np.quantile(min_p(refs, refs), 0.99))[keep])
        for m in methods[1:]:
            s = z[m][f"test_{d}"].astype(np.float64)
            per[m].append((s > (0.5 if m == "rf_supervised" else np.quantile(s[ref], 0.99)))[keep])
        for k, v in (("ts", t["ts"]), ("role", t["role"]), ("y", t["y"])):
            cols[k].append(v[keep])
        cols["day"].append(np.full(keep.sum(), d))
    c = {k: np.concatenate(v) for k, v in cols.items()}
    key = np.char.add(c["day"].astype(str), c["role"].astype(str))
    hours_all = sum((c["ts"][c["day"] == d].max() - c["ts"][c["day"] == d].min()) / 3600 for d in days)
    thu = c["day"] == "Thursday-22-02-2018"
    hours_thu = (c["ts"][thu].max() - c["ts"][thu].min()) / 3600
    rows = []
    for m in methods:
        p = np.concatenate(per[m])
        rows.append(row("CSE-CIC-IDS2018 (2-day + context)", "all 4 test days", m, c["ts"], key, c["y"], p, hours_all, bin_s))
        rows.append(row("CSE-CIC-IDS2018 (2-day + context)", "Thu-22 only", m, c["ts"][thu], key[thu], c["y"][thu],
                        p[thu], hours_thu, bin_s))
    return rows


def suricata_thu22(bin_s):
    al = []
    for line in open(ROOT.parent / "external/pcap/thu22/suri/eve.json", encoding="utf-8"):
        e = json.loads(line)
        if e["event_type"] == "alert" and e["alert"]["signature"].startswith("ET "):
            al.append((pd.Timestamp(e["timestamp"]).timestamp(), e["src_ip"], e["alert"]["signature"]))
    al = pd.DataFrame(al, columns=["ts", "src", "sig"])
    hours = (al.ts.max() - al.ts.min()) / 3600
    y = (al.src == ATTACKER).to_numpy().astype(int)
    key = (al.sig + "|" + al.src).to_numpy()
    tp, fp = alerts(al.ts.to_numpy(), key, y, np.ones(len(al), bool), bin_s)
    return dict(dataset="CSE-CIC-IDS2018 (2-day + context)", scope="Thu-22 only", method=NAMES["suricata_signature"][0],
                family="sig", flagged_benign_flows_per_h=np.nan, false_alerts_per_h=round(fp / hours, 2), true_alerts=tp,
                alert_precision=round(tp / max(tp + fp, 1), 3), attack_flow_recall=np.nan)


def suricata2017(bin_s):
    cfg = load_config(ROOT / "config_suricata2017.yaml")
    res, days = cfg["paths"]["results_dir"], cfg["data"]["test_days"]
    methods = ["ssl_mm_role_knn", "ae_concat_knnrole", "ae_concat", "pca_recon", "iforest", "rf_supervised", "suricata_signature"]
    tests = {d: load_split(cfg, f"test_{d}") for d in days}
    ts = np.concatenate([tests[d]["ts"] for d in days])
    y = np.concatenate([tests[d]["y"] for d in days])
    key = np.concatenate([np.char.add(d, tests[d]["role"].astype(str)) for d in days])
    hours = sum((tests[d]["ts"].max() - tests[d]["ts"].min()) / 3600 for d in days)
    rows = []
    for m in methods:
        z = np.load(res / "scores" / f"{m}.npz")
        thr = 0.5 if m in ("rf_supervised", "suricata_signature") else float(np.quantile(z["val"], 0.99))
        p = np.concatenate([z[f"test_{d}"] > thr for d in days])
        rows.append(row("CIC-IDS2017 via Suricata telemetry", "all 3 test days", m, ts, key, y, p, hours, bin_s))
    return rows


def main():
    bin_s = load_config(ROOT / "config_context.yaml")["scoring"]["incident_gap_sec"]
    rows = cic_context(bin_s) + [suricata_thu22(bin_s)] + suricata2017(bin_s)
    t = pd.DataFrame(rows)
    t.to_csv(OUT / "table_alert_volume.csv", index=False)
    print(t.drop(columns="family").to_string(index=False))

    panels = [("CSE-CIC-IDS2018, Thu-22 (web attacks)", t[t.scope == "Thu-22 only"]),
              ("CIC-IDS2017 via Suricata telemetry, 3 test days", t[t.dataset.str.startswith("CIC-IDS2017")])]
    fig, axs = plt.subplots(1, 2, figsize=(13, 3.8))
    for ax, (title, s) in zip(axs, panels):
        s = s.sort_values("family", key=lambda f: f.map({"sig": 0, "proposed": 1, "ml": 2, "sup": 3}), kind="stable")
        hbar(ax, s.method, s.false_alerts_per_h, s.family, title, xmax=max(s.false_alerts_per_h.max(), 1), fmt="{:.1f}")
    fig.legend(handles=legend_handles(["proposed", "ml", "sup", "sig"]), loc="lower center", ncol=4, frameon=False,
               bbox_to_anchor=(0.5, -0.1))
    fig.suptitle(f"False alerts per hour after grouping into ({bin_s // 60}-min bin, entity) alerts",
                 x=0.02, y=1.04, ha="left", fontsize=12, color=INK)
    fig.tight_layout()
    fig.savefig(OUT / "fig8_alert_volume.png")


if __name__ == "__main__":
    main()
