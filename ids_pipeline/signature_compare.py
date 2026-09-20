"""Suricata / Zeek (run on the raw CSE-CIC-IDS2018 pcap in Docker) vs the ML detectors.

For one victim capture the attack flows of the labelled CSV are aligned in time with the attacker's
connections seen by Zeek (conn.log) and Suricata (eve.json). Suricata's verdict counts only Emerging
Threats signatures ("ET ..."); SURICATA engine events (e.g. checksum decode events) are capture
artefacts and ignored. Zeek's verdict = any non-CaptureLoss notice involving the attacker.
"""
import json

import numpy as np
import pandas as pd

from .data import T0, load_split
from .utils import get_logger

log = get_logger()
UTC_OFFSET_S = 4 * 3600          # CSV timestamps are local time (UTC-4); verified against the pcap


def read_zeek(path):
    cols, rows = None, []
    for line in open(path, encoding="utf-8"):
        if line.startswith("#fields"):
            cols = line.rstrip("\n").split("\t")[1:]
        elif not line.startswith("#"):
            rows.append(line.rstrip("\n").split("\t"))
    return pd.DataFrame(rows, columns=cols)


def run_compare(cfg, capture_dir, day, attacker):
    res = cfg["paths"]["results_dir"]
    conn = read_zeek(capture_dir / "zeek" / "conn.log")
    conn["ts"] = conn.ts.astype(float)
    conn["dur"] = pd.to_numeric(conn.duration, errors="coerce").fillna(0)
    conn = conn[conn["id.orig_h"] == attacker].sort_values("ts").reset_index(drop=True)
    conn["orig_p"] = conn["id.orig_p"].astype(int)

    alerts = []
    for line in open(capture_dir / "suri" / "eve.json", encoding="utf-8"):
        e = json.loads(line)
        if e["event_type"] == "alert" and e["alert"]["signature"].startswith("ET "):
            alerts.append(dict(ts=pd.Timestamp(e["timestamp"]).timestamp(), src=e["src_ip"], sport=e.get("src_port", -1),
                               dst=e["dest_ip"], sig=e["alert"]["signature"], cat=e["alert"]["category"]))
    al = pd.DataFrame(alerts)
    hit_ports = set(al[al.src == attacker].sport)
    conn["suricata"] = conn.orig_p.isin(hit_ports)

    notice = read_zeek(capture_dir / "zeek" / "notice.log")
    notice = notice[notice.note != "CaptureLoss::Too_Little_Traffic"]
    zeek_flagged = attacker in set(notice.get("src", pd.Series(dtype=str)))
    conn["zeek"] = zeek_flagged

    # --- align labelled CSV attack flows with the attacker's connections
    t = load_split(cfg, f"test_{day}")
    epoch = (T0 - pd.Timestamp("1970-01-01")).total_seconds() + t["ts"] + UTC_OFFSET_S
    atk = np.where(t["y"] == 1)[0]
    starts, ends = conn.ts.to_numpy(), (conn.ts + conn.dur).to_numpy()
    idx = np.searchsorted(starts, epoch[atk] + 2.0) - 1          # last connection that began <= flow start + 2 s
    ok = (idx >= 0) & (epoch[atk] <= ends[np.clip(idx, 0, None)] + 5.0)
    matched = atk[ok]
    mconn = conn.iloc[idx[ok]]
    log.info("%d/%d attack flows matched to %d attacker connections (Zeek saw %d)", ok.sum(), len(atk),
             mconn.index.nunique(), len(conn))

    df = pd.DataFrame({"attack": t["label"][matched], "suricata_ET": mconn.suricata.to_numpy(),
                       "zeek_notice": mconn.zeek.to_numpy()})
    scores = {}
    for f in sorted((res / "scores").glob("*.npz")):
        if f.stem == "suricata_signature" or f"test_{day}" not in np.load(f).files:
            continue
        z = np.load(f)
        s = z[f"test_{day}"][matched]
        df[f.stem] = s > float(z["thr"])
        scores[f.stem] = float(z["thr"])
    main = [m for m in ("ssl_mm_role_knn", "ssl_mm_global_knn", "ae_concat_knn", "ssl_mm_role", "ssl_mm_global", "ae_concat") if m in df]
    for m in main:
        df[f"hybrid_suricata_or_{m}"] = df.suricata_ET | df[m]
    out = df.groupby("attack").mean().round(4)
    out.insert(0, "n_flows", df.groupby("attack").size())
    out.to_csv(res / f"signature_comparison_{day}.csv")
    log.info("\n%s", out.T.to_string())

    bg = al[al.src != attacker]
    summ = bg.groupby(["cat"]).size().sort_values(ascending=False)
    hours = (al.ts.max() - al.ts.min()) / 3600
    with open(res / f"signature_background_alerts_{day}.txt", "w", encoding="utf-8") as fh:
        fh.write(f"Suricata ET alerts from sources other than the attacker on this capture: {len(bg)} "
                 f"({len(bg) / hours:.1f}/h over {hours:.1f} h); attacker alerts: {int((al.src == attacker).sum())}\n\n")
        fh.write(summ.to_string() + "\n\n" + bg.sig.value_counts().head(15).to_string() + "\n")
        fh.write(f"\nZeek notices (excluding CaptureLoss): {len(notice)}; attacker flagged by Zeek: {zeek_flagged}\n")
        fh.write(notice[["note", "msg"]].to_string() if len(notice) else "")
    return out
