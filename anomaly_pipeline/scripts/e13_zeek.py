"""E13 (results_comparison/PREREGISTRATION.md): Zeek on the CIC-IDS2017 P1 test days as a second operational baseline.

    python scripts/e13_zeek.py

Zeek logs: ../external/cic2017/<Day>/zeek/ (zeek/zeek:9.0.0, see PREREGISTRATION.md E13). Zeek alert = notice.log entry except Zeek health
notices. A test flow (one Suricata flow = one row of the processed P1 split) is Zeek-detected if (a) a notice's uid is the Zeek connection
matched to it (same 5-tuple in either direction, start within 2 s) or (b) a notice without uid has a `src` that is one of the flow's
endpoints and the flow starts within 30 minutes of the notice. Output: results_comparison/E13/.
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_pipeline.data import load_split                     # noqa: E402
from ids_pipeline.signature_compare import read_zeek          # noqa: E402
from ids_pipeline.utils import load_config                    # noqa: E402

OUT = ROOT / "results_comparison" / "E13"
ZEEK_ROOT = ROOT.parent / "external" / "cic2017"
HEALTH = ("CaptureLoss::", "PacketFilter::")
MATCH_S, WINDOW_S = 2.0, 1800.0
PROTO = {"tcp": 6, "udp": 17, "icmp": 1}
SSL_DIRS = {42: "results_e11_cic2017_monday", 1: "results_e11_cic2017_monday_seed1", 2: "results_e11_cic2017_monday_seed2"}


def test_flows(cfg, day, t):
    """Suricata flows of `day` in the order of the processed split (adapter: stable sort by start time), with endpoints and epoch start."""
    raw = pd.read_parquet(cfg["data"]["suricata_parquet"], columns=["Flow ID", "src_ip", "dst_ip", "class", "start", "start_utc", "Day"],
                          filters=[("Day", "==", day)]).reset_index(drop=True)
    hms = raw["start"].str.split(":", expand=True).astype(float)
    raw = raw.iloc[np.argsort((hms[0] * 3600 + hms[1] * 60 + hms[2]).to_numpy(), kind="stable")].reset_index(drop=True)
    lab = raw["class"].str.strip().replace({"BENIGN": "Benign"}).to_numpy()
    assert len(raw) == len(t["y"]) and (lab == t["label"]).all(), f"{day}: Suricata flows do not align with the processed split"
    p = raw["Flow ID"].str.rsplit("-", n=4, expand=True)            # srcip-sport-dstip-dport-proto
    return pd.DataFrame(dict(a=p[0], ap=pd.to_numeric(p[1], errors="coerce").fillna(-1).astype(int), b=p[2],
                             bp=pd.to_numeric(p[3], errors="coerce").fillna(-1).astype(int),
                             proto=pd.to_numeric(p[4], errors="coerce").fillna(-1).astype(int),
                             src=raw.src_ip.to_numpy(), dst=raw.dst_ip.to_numpy(),
                             t=raw.start_utc.astype("int64").to_numpy() / 1e6))       # microseconds -> seconds


def zeek_verdict(day, flows):
    zd = ZEEK_ROOT / day / "zeek"
    notice = read_zeek(zd / "notice.log") if (zd / "notice.log").exists() else pd.DataFrame(columns=["ts", "uid", "note", "src"])
    notice = notice[~notice.note.str.startswith(HEALTH)].copy()
    notice["ts"] = notice.ts.astype(float)
    hit = np.zeros(len(flows), bool)
    via = np.full(len(flows), "", dtype=object)

    # (a) per-connection notices: uid -> Zeek connection -> Suricata flow with the same 5-tuple (either direction), start within 2 s
    with_uid = notice[notice.uid.notna() & (notice.uid != "-")]
    if len(with_uid):
        conn = read_zeek(zd / "conn.log")
        conn = conn[conn.uid.isin(set(with_uid.uid))]
        c = pd.DataFrame(dict(uid=conn.uid, t=conn.ts.astype(float), a=conn["id.orig_h"], ap=conn["id.orig_p"].astype(int),
                              b=conn["id.resp_h"], bp=conn["id.resp_p"].astype(int), proto=conn.proto.map(PROTO).fillna(-1).astype(int)))
        c = c.merge(with_uid.groupby("uid").note.first().rename("note"), left_on="uid", right_index=True)
        rev = c.rename(columns={"a": "b", "b": "a", "ap": "bp", "bp": "ap"})
        f = flows.reset_index().rename(columns={"index": "row"})
        for side in (c, rev):
            m = f.merge(side, on=["a", "ap", "b", "bp", "proto"], suffixes=("", "_z"))
            m = m[np.abs(m.t - m.t_z) <= MATCH_S]
            hit[m.row.to_numpy()] = True
            via[m.row.to_numpy()] = m.note.to_numpy()

    # (b) source-level notices: either endpoint is the notice's src and the flow starts within 30 min of the notice
    src_only = notice[(notice.uid.isna() | (notice.uid == "-")) & notice.src.notna() & (notice.src != "-")]
    for src, g in src_only.groupby("src"):
        nts = np.sort(g.ts.to_numpy())
        notes = g.sort_values("ts").note.to_numpy()
        m = np.flatnonzero((flows.src.to_numpy() == src) | (flows.dst.to_numpy() == src))
        if not len(m):
            continue
        tt = flows.t.to_numpy()[m]
        j = np.clip(np.searchsorted(nts, tt), 1, len(nts)) - 1
        near = np.minimum(np.abs(tt - nts[j]), np.abs(tt - nts[np.clip(j + 1, 0, len(nts) - 1)]))
        ok = near <= WINDOW_S
        hit[m[ok]] = True
        via[m[ok]] = np.where(via[m[ok]] == "", notes[j[ok]], via[m[ok]])
    return hit, via, notice


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--days", nargs="+", help="subset of the test days (debugging); default all")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()
    cfg = load_config(ROOT / "config_cic2017_monday.yaml")
    days = args.days or cfg["data"]["test_days"]
    out = args.out
    zeek, via, sig, y, label, notices, hours = [], [], [], [], [], [], 0.0
    for day in days:
        t = load_split(cfg, f"test_{day}")
        flows = test_flows(cfg, day, t)
        h, v, n = zeek_verdict(day, flows)
        zeek.append(h)
        via.append(v)
        sig.append(t["sig"].astype(bool))
        y.append(t["y"])
        label.append(t["label"])
        notices.append(n.assign(day=day))
        hours += (flows.t.max() - flows.t.min()) / 3600
        print(f"{day}: {len(n)} notices, {h.sum()} flows Zeek-detected ({h[t['y'] == 1].sum()} attack)", flush=True)
    zeek, via, sig, y, label = map(np.concatenate, (zeek, via, sig, y, label))
    notices = pd.concat(notices, ignore_index=True)

    ssl = {}
    for seed, d in SSL_DIRS.items():
        z = np.load(ROOT / d / "scores" / "ssl_mm_role_knn.npz")
        assert np.array_equal(np.concatenate([z[f"y_{dd}"] for dd in days]), y)
        ssl[seed] = np.concatenate([z[f"test_{dd}"] for dd in days]) > np.quantile(z["val"], 0.99)

    det = {"zeek": zeek, "suricata": sig, "zeek_or_suricata": zeek | sig}
    for seed in SSL_DIRS:
        det[f"ssl_tuned_s{seed}"] = ssl[seed]
        det[f"zeek_or_ssl_tuned_s{seed}"] = zeek | ssl[seed]
    ben = y == 0
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, d in det.items():
        r = dict(detector=name, recall=float(d[y == 1].mean()), fpr=float(d[ben].mean()), alerted_benign_per_hour=float(d[ben].sum() / hours))
        for lab in sorted(set(label) - {"Benign"}):
            r[lab] = float(d[label == lab].mean())
        rows.append(r)
    res = pd.DataFrame(rows)
    for base in ("ssl_tuned", "zeek_or_ssl_tuned"):
        sub = res[res.detector.str.match(f"{base}_s\\d")]
        res = pd.concat([res, sub.drop(columns="detector").mean().to_frame().T.assign(detector=f"{base} (seed mean)")], ignore_index=True)
    res.round(4).to_csv(out / "zeek_vs_others.csv", index=False)
    notices.groupby(["day", "note"]).size().rename("notices").reset_index().to_csv(out / "zeek_notices.csv", index=False)
    by_note = pd.DataFrame(dict(note=via, attack=y == 1))[zeek]
    by_note.groupby("note").attack.agg(flows="size", attack_share="mean").reset_index().round(4).to_csv(out / "zeek_detections_by_note.csv", index=False)
    pd.set_option("display.width", 250)
    show = ["detector", "recall", "fpr", "alerted_benign_per_hour"]
    print(res[show].round(4).to_string(index=False))
    print(res.set_index("detector").drop(columns=show[1:]).T[["zeek", "suricata", "zeek_or_suricata", "ssl_tuned (seed mean)",
                                                               "zeek_or_ssl_tuned (seed mean)"]].round(3).to_string())
    print(notices.groupby("note").size().sort_values(ascending=False).to_string())
    print(by_note.groupby("note").attack.agg(["size", "mean"]).round(3).to_string())


if __name__ == "__main__":
    main()
