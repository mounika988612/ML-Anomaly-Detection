"""Rebuild of the Suricata2017 dataset, step 2: Suricata eve.json of the official CIC-IDS2017 pcaps (step 1:
scripts/cic2017_suricata.sh) -> one labelled row per Suricata flow, in the schema of the Hugging Face parquet it replaces
(`Flow ID, event_types, log, alerted, class, truth, start, age, Day, event_type_alert, label`), so
ids_pipeline/adapters/suricata2017.py and analyst_report.py read it unchanged.

Labels come only from CIC's published attack schedule (docs/cic2017_attack_schedule.csv: attacker IP, victim IP, start/end
in the testbed's local time, UTC-3), never from Suricata alerts. A flow is an attack if it is between a scheduled
attacker/victim pair and starts inside that attack's window (+- --pad seconds). A flow between an attacker-only pair
(`outside_window = drop`) that starts outside every window is not guessed: it is dropped and counted in the audit.

    python scripts/build_suricata2017.py --root ../external/cic2017 [--days Monday ...] [--hf-parquet ...] [--cic-csv-dir ...]
per day (cached): <root>/<Day>/flows.parquet; all days present: <root>/suricata2017_rebuilt.parquet, manifest.json, LABEL_AUDIT.md
"""
import argparse
import hashlib
import ipaddress
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

try:
    from orjson import loads
except ImportError:
    from json import loads

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_pipeline.adapters.suricata2017 import DAYS  # noqa: E402

DATES = dict(zip(DAYS, ["2017-07-03", "2017-07-04", "2017-07-05", "2017-07-06", "2017-07-07"]))
UTC_MINUS_LOCAL = pd.Timedelta(hours=3)    # testbed clock ADT = UTC-3 (Heartbleed 15:12 local = 18:12 UTC in the pcap)
EVENTS = ("flow", "dns", "http", "fileinfo", "tls", "ssh", "ftp", "anomaly")      # event types kept in `log` (as in the HF parquet)
FLOW_DROP = ("alerted", "start", "end")    # flow-event fields kept out of `log`: detector decision and absolute time
PROTO = {"TCP": 6, "UDP": 17, "ICMP": 1, "IPV6-ICMP": 58, "SCTP": 132}
STATS = ("decoder.pkts", "decoder.invalid", "flow.total", "flow.memcap", "flow.emerg_mode_entered", "tcp.ssn_memcap_drop",
         "tcp.segment_memcap_drop", "tcp.reassembly_gap", "tcp.midstream_pickups", "detect.alert", "detect.alert_queue_overflow")
ENGINE_SIDS = range(2200000, 2300000)      # Suricata's own decoder/stream/app-layer event rules (e.g. "invalid checksum"), not ET Open
COLS = ["Flow ID", "event_types", "log", "alerted", "event_type_alert", "n_engine_alerts", "start_iso", "age", "src_ip", "dst_ip"]


# --------------------------------------------------------------------------- eve.json -> one row per flow
def _flat(x, key, out):
    if isinstance(x, dict):
        for k, v in x.items():
            _flat(v, f"{key}_{k}", out)
    elif isinstance(x, list):
        for i, v in enumerate(x):
            _flat(v, f"{key}_{i}", out)
    else:
        out[key] = x
    return out


def _dns(d):
    """eve DNS v3 (Suricata 8: request/response with queries[]) -> the v2 per-query layout the adapter parses."""
    if d.get("version", 2) < 3:
        return d
    q = (d.get("queries") or [{}])[0]
    out = {"type": "query" if d.get("type") == "request" else "answer", "id": d.get("id"),
           "rrname": q.get("rrname", ""), "rrtype": q.get("rrtype", "")}
    if out["type"] == "answer":
        out.update(rcode=d.get("rcode", ""), answers=d.get("answers", []))
    return out


def event_text(e):
    """`event_type: flow, proto: TCP, flow_pkts_toserver: 8, ...`: nested keys joined by '_', list items by index.
    ', ' and ' ; ' are the field and event separators, so they are removed from values."""
    t = e["event_type"]
    kv = {"event_type": t}
    if t == "flow":
        kv["proto"] = e.get("proto", "")
        _flat({k: v for k, v in e["flow"].items() if k not in FLOW_DROP}, "flow", kv)
        if "tcp" in e:
            _flat(e["tcp"], "tcp", kv)
    else:
        _flat(_dns(e["dns"]) if t == "dns" else e.get(t, {}), t, kv)
    return ", ".join(f"{k}: {str(v).replace(' ; ', ' ;').replace(', ', ',')}" for k, v in kv.items())


def read_eve(path):
    """Group app-layer and alert events by flow_id; a flow's row is emitted at its flow event, which Suricata logs
    when the flow ends (timeout or end of pcap), i.e. after all its other events.
    `alerted` (the signature baseline) = at least one ET Open rule fired; engine-event alerts are only counted."""
    pending, alerts, engine, rows, n_ev, stats = defaultdict(list), defaultdict(list), Counter(), [], Counter(), {}
    with open(path, "rb") as fh:
        for line in fh:
            e = loads(line)
            t = e.get("event_type")
            n_ev[t] += 1
            if t == "stats":
                stats = e["stats"]
                continue
            fid = e.get("flow_id")
            if fid is None or (t not in EVENTS and t != "alert"):
                continue
            if t == "alert":
                a = e["alert"]
                if a.get("signature_id") in ENGINE_SIDS:
                    engine[fid] += 1
                    continue
                alerts[fid].append({"alert": {k: a.get(k) for k in ("signature_id", "signature", "category", "severity")}})
            elif t != "flow":
                pending[fid].append((t, event_text(e)))
            else:
                evs = [("flow", event_text(e))] + pending.pop(fid, [])
                al = alerts.pop(fid, [])
                f, proto = e["flow"], e.get("proto", "")
                fid_s = f"{e['src_ip']}-{e.get('src_port', 0)}-{e['dest_ip']}-{e.get('dest_port', 0)}-{PROTO.get(proto.upper(), proto)}"
                rows.append((fid_s,
                             str([k for k, _ in evs]), " ; ".join(s for _, s in evs), bool(al),
                             str(al), engine.pop(fid, 0), f["start"], int(f.get("age", 0)), e["src_ip"], e["dest_ip"]))
    stat = {}
    for k in STATS:
        a, b = k.split(".")
        stat[k] = stats.get(a, {}).get(b)
    return pd.DataFrame(rows, columns=COLS), dict(events=dict(n_ev), orphan_flows=len(pending), orphan_alert_flows=len(alerts),
                                                  suricata_stats=stat)


# --------------------------------------------------------------------------- labels from the published schedule
def load_schedule(path):
    s = pd.read_csv(path, dtype=str, keep_default_na=False)
    bad = set(s.direction) - {"any", "fwd"} | set(s.outside_window) - {"drop", "benign"} | set(s.day) - set(DAYS)
    if bad:
        raise ValueError(f"{path}: unknown values {bad}")
    return s


def _members(ips, spec):
    nets = [ipaddress.ip_network(x.strip()) for x in spec.split(";")]
    out = set()
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if any(a.version == n.version and a in n for n in nets):
            out.add(ip)
    return out


def window(day, r, pad):
    """[start, end + 1 min) in UTC: the documented times are local wall-clock minutes, end minute inclusive."""
    t0 = pd.Timestamp(f"{DATES[day]} {r.start}", tz="UTC") + UTC_MINUS_LOCAL
    t1 = pd.Timestamp(f"{DATES[day]} {r.end}", tz="UTC") + UTC_MINUS_LOCAL + pd.Timedelta(minutes=1)
    return t0, t1, t0 - pd.Timedelta(seconds=pad), t1 + pd.Timedelta(seconds=pad)


def label_flows(src, dst, ts, day, sched, pad):
    """ts: UTC DatetimeIndex. -> class per flow, index of the schedule row that labelled it (-1 = none), in pad zone, to drop.
    First matching row wins; windows of the same pair do not overlap at the default pad."""
    s = sched[sched.day == day]
    src, dst = pd.Series(src), pd.Series(dst)
    ips = set(src.unique()) | set(dst.unique())
    cls, rule = np.full(len(src), "BENIGN", object), np.full(len(src), -1)
    pad_zone, drop_pair = np.zeros(len(src), bool), np.zeros(len(src), bool)
    for i, r in s.iterrows():
        a, v = _members(ips, r.attacker), _members(ips, r.victim)
        pair = (src.isin(a) & dst.isin(v)).to_numpy()
        if r.direction == "any":
            pair = pair | (src.isin(v) & dst.isin(a)).to_numpy()
        t0, t1, p0, p1 = window(day, r, pad)
        hit = pair & (ts >= p0) & (ts < p1) & (rule < 0)
        cls[hit], rule[hit] = r.label, i
        pad_zone = pad_zone | hit & ~((ts >= t0) & (ts < t1))
        if r.outside_window == "drop":
            drop_pair = drop_pair | pair
    return cls, rule, pad_zone, drop_pair & (rule < 0)


# --------------------------------------------------------------------------- per day
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _txt(p):
    return p.read_text().strip() if p.exists() else None


def build_day(root, day, sched, pad):
    suri = root / day / "suri"
    df, info = read_eve(suri / "eve.json")
    ts = pd.DatetimeIndex(pd.to_datetime(df.start_iso, utc=True, format="ISO8601"))
    cls, rule, pad_zone, drop = label_flows(df.src_ip, df.dst_ip, ts, day, sched, pad)
    df = df.assign(start_utc=ts, **{"class": cls}, rule=rule, pad_zone=pad_zone, Day=day)
    info.update(flows_total=len(df), dropped_unscheduled_attacker_flows=int(drop.sum()),
                version=_txt(suri / "version.txt"), image=_txt(suri / "image.txt"),
                pcap_sha256=_txt(suri / "pcap.sha256"), rules_sha256=_txt(suri / "rules.sha256"))
    unsched = df[drop].assign(local=lambda d: d.start_utc - UTC_MINUS_LOCAL)
    df = df[~drop]
    df = df.assign(truth=df["class"] != "BENIGN", label=np.where(df["class"] != "BENIGN", "attack", "normal"),
                   start=df.start_utc.dt.strftime("%H:%M:%S"))
    df = df.sort_values(["start_utc", "Flow ID"], kind="stable").reset_index(drop=True).drop(columns="start_iso")
    df.to_parquet(root / day / "flows.parquet", index=False)
    unsched.drop(columns=["log"]).to_parquet(root / day / "unscheduled_attacker_flows.parquet", index=False)
    (root / day / "day_manifest.json").write_text(json.dumps(info, indent=1, default=str))
    return info


# --------------------------------------------------------------------------- audit
def _zeek_counts(root, day, sched, pad):
    p = root / day / "zeek" / "conn.log"
    if not p.exists():
        return None
    from ids_pipeline.signature_compare import read_zeek
    z = read_zeek(p)
    ts = pd.DatetimeIndex(pd.to_datetime(z.ts.astype(float), unit="s", utc=True))
    cls, _, _, drop = label_flows(z["id.orig_h"], z["id.resp_h"], ts, day, sched, pad)
    return pd.Series(cls[~drop]).value_counts()


def _cic_csv(d):
    """CIC's own labelled flows (TrafficLabelling CSVs). Their timestamps carry no AM/PM: hours < 8 are afternoon."""
    out = []
    for p in sorted(Path(d).glob("*.csv")):
        c = pd.read_csv(p, encoding="latin1", skipinitialspace=True, low_memory=False,
                        usecols=lambda k: k.strip() in ("Source IP", "Destination IP", "Timestamp", "Label"))
        c.columns = [k.strip() for k in c.columns]
        c = c.dropna(subset=["Label"])
        t = pd.to_datetime(c.Timestamp, dayfirst=True, format="mixed", errors="coerce")
        c["local"] = t + pd.to_timedelta((t.dt.hour < 8) * 12, unit="h")
        c["Day"] = c.local.dt.day_name()
        out.append(c)
    return pd.concat(out, ignore_index=True)


def _md(df):
    if not len(df):
        return "(none)"
    cells = [[str(c) for c in df.columns]] + [["" if pd.isna(v) else str(v) for v in r] for r in df.itertuples(index=False)]
    return "\n".join("| " + " | ".join(r) + " |" for r in cells[:1] + [["---"] * len(df.columns)] + cells[1:])


def audit(root, days, sched, pad, all_df, manifest, hf, cic_dir):
    L = ["# Suricata2017 (rebuilt): label audit",
         "", f"Generated by `scripts/build_suricata2017.py` on {manifest['built_utc']}. Labels: `docs/cic2017_attack_schedule.csv` "
         f"(sha256 `{manifest['schedule_sha256'][:16]}`), pad {pad} s. Times below are testbed local time (UTC-3).", "",
         "## 1. Provenance per day", ""]
    prov = pd.DataFrame([dict(day=d, flows=m["flows_total"], dropped_unscheduled=m["dropped_unscheduled_attacker_flows"],
                              pcap_sha256=(m["pcap_sha256"] or "")[:16], rules_sha256=(m["rules_sha256"] or "")[:16],
                              **{k: m["suricata_stats"].get(k) for k in ("decoder.pkts", "flow.memcap", "tcp.segment_memcap_drop",
                                                                         "tcp.reassembly_gap", "detect.alert_queue_overflow")})
                         for d, m in manifest["days"].items()])
    L += [_md(prov), "", f"Suricata: `{next(iter(manifest['days'].values()))['version']}`; image `{manifest['image']}`; "
          f"ET Open rules fetched {manifest['rules_fetched_utc']}. Non-zero memcap/overflow counters mean Suricata lost state; "
          "they should be 0.", ""]

    L += ["## 2. Flows per class", ""]
    cnt = all_df.groupby(["Day", "class"]).size().rename("rebuilt").reset_index()
    if hf is not None:
        cnt = cnt.merge(hf[hf.Day.isin(days)].groupby(["Day", "class"]).size().rename("hf_parquet").reset_index(), how="outer")
    z = {d: _zeek_counts(root, d, sched, pad) for d in days}
    if any(v is not None for v in z.values()):
        zz = pd.concat([v.rename("zeek_conn").rename_axis("class").reset_index().assign(Day=d) for d, v in z.items() if v is not None])
        cnt = cnt.merge(zz, how="outer")
    num = cnt.columns.drop(["Day", "class"])
    cnt[num] = cnt[num].fillna(0).astype(int)
    L += [_md(cnt.sort_values(["Day", "class"], key=lambda s: s.map(DAYS.index) if s.name == "Day" else s)), "",
          "Suricata and Zeek flows are both counted by the same schedule rule; the HF column is the unverified dataset this replaces "
          "(its classes were not produced by this rule).", ""]

    L += ["## 3. Per schedule row", ""]
    rows = []
    for i, r in sched[sched.day.isin(days)].iterrows():
        f = all_df[all_df.rule == i]
        loc = f.start_utc - UTC_MINUS_LOCAL
        ports = f["Flow ID"].str.split("-").str[3].value_counts().head(4)
        rows.append(dict(day=r.day, label=r.label, window=f"{r.start}-{r.end}", flows=len(f), in_pad=int(f.pad_zone.sum()),
                         first=loc.min().strftime("%H:%M:%S") if len(f) else "", last=loc.max().strftime("%H:%M:%S") if len(f) else "",
                         alerted=f"{f.alerted.mean():.1%}" if len(f) else "", top_ports=", ".join(f"{p}:{n}" for p, n in ports.items())))
    L += [_md(pd.DataFrame(rows)), "", "`first`/`last` hugging the window edges and many `in_pad` flows would mean the documented "
          "window is too narrow; flows far inside it with no traffic at the edges support it.", ""]

    L += ["## 4. Who talks to each victim during its window", "",
          "Top (source, destination) pairs among all flows touching the victim inside the window. The scheduled attacker should dominate; "
          "a large unscheduled pair would mean the attacker address at the capture point is not the one in the schedule.", ""]
    for _, r in sched[sched.day.isin(days)].iterrows():
        v = _members(set(all_df.src_ip) | set(all_df.dst_ip), r.victim)
        t0, t1, _, _ = window(r.day, r, 0)
        touch = all_df.src_ip.isin(v) | all_df.dst_ip.isin(v)
        w = all_df[(all_df.Day == r.day) & touch & (all_df.start_utc >= t0) & (all_df.start_utc < t1)]
        top = w.groupby(["src_ip", "dst_ip"]).size().sort_values(ascending=False).head(5)
        L += [f"- **{r.day} {r.label} {r.start}-{r.end}**: " + "; ".join(f"{a} -> {b}: {n}" for (a, b), n in top.items())]
    L += [""]

    L += ["## 5. Dropped: attacker-pair flows outside every window", ""]
    for d in days:
        u = pd.read_parquet(root / d / "unscheduled_attacker_flows.parquet")
        if len(u):
            h = u.local.dt.floor("10min").dt.strftime("%H:%M").value_counts().sort_index()
            L += [f"- **{d}**: {len(u)} flows; per 10 min: " + ", ".join(f"{t} {n}" for t, n in h.items())]
        else:
            L += [f"- **{d}**: none"]
    L += ["", "Many flows here next to a window means the window is too narrow; a few scattered flows are connections the "
          "schedule does not explain, which is why they are excluded instead of labelled.", ""]

    L += ["## 6. Suricata alerts vs labels (alerts were not used for labelling)", ""]
    al = all_df.assign(any_alert=all_df.alerted).groupby("class").agg(flows=("alerted", "size"), alerted=("any_alert", "mean"))
    al["alerted"] = al.alerted.map("{:.2%}".format)
    L += [_md(al.reset_index()), ""]
    if hf is not None:
        L += [f"HF parquet for comparison: {hf[hf['class'] == 'BENIGN'].alerted.mean():.2%} of BENIGN flows alerted.", ""]

    if cic_dir:
        c = _cic_csv(cic_dir)
        g = c.groupby(["Day", "Label"])
        t = pd.DataFrame(dict(flows=g.size(), first=g.local.min().dt.strftime("%H:%M"), last=g.local.max().dt.strftime("%H:%M"),
                              top_pair=g.apply(lambda x: (x["Source IP"] + " -> " + x["Destination IP"]).value_counts().index[0])))
        L += ["## 7. CIC's own labelled CSVs (independent check of pairs and windows)", "", _md(t.reset_index()), ""]
    (root / "LABEL_AUDIT.md").write_text("\n".join(L), encoding="utf-8")


# --------------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, default=ROOT.parent / "external" / "cic2017")
    ap.add_argument("--days", nargs="+", default=DAYS, choices=DAYS)
    ap.add_argument("--schedule", type=Path, default=ROOT / "docs" / "cic2017_attack_schedule.csv")
    ap.add_argument("--pad", type=int, default=60, help="seconds added to both ends of every window")
    ap.add_argument("--force", action="store_true", help="rebuild days whose flows.parquet exists")
    ap.add_argument("--hf-parquet", type=Path, default=ROOT.parent / "external" / "suricata2017" / "suricata2017_all.parquet")
    ap.add_argument("--cic-csv-dir", type=Path, help="CIC TrafficLabelling CSVs, optional cross-check")
    ap.add_argument("--out", type=Path, help="write the parquet of the built days here even if days are missing (interim runs)")
    a = ap.parse_args(argv)
    sched = load_schedule(a.schedule)
    for d in a.days:
        if (a.root / d / "suri" / "eve.json").exists() and (a.force or not (a.root / d / "flows.parquet").exists()):
            print(f"{d}: parsing eve.json", flush=True)
            build_day(a.root, d, sched, a.pad)
    days = [d for d in DAYS if (a.root / d / "flows.parquet").exists()]
    missing = [d for d in DAYS if d not in days]
    if missing:
        print(f"built: {days}; missing: {missing} (run scripts/cic2017_suricata.sh for them)")
        if not days:
            return
    all_df = pd.concat([pd.read_parquet(a.root / d / "flows.parquet") for d in days], ignore_index=True)
    manifest = dict(built_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), schedule_sha256=sha256(a.schedule),
                    pad_sec=a.pad, days={d: json.loads((a.root / d / "day_manifest.json").read_text()) for d in days},
                    image=None,
                    rules_fetched_utc=_txt(a.root / "rules" / "fetched_utc.txt"),
                    classes=all_df["class"].value_counts().to_dict())
    manifest["image"] = manifest["days"][days[0]]["image"]
    if len({m["rules_sha256"].split()[0] for m in manifest["days"].values() if m["rules_sha256"]}) > 1:
        print("WARNING: days were processed with different rule files")
    if not missing:
        all_df.to_parquet(a.root / "suricata2017_rebuilt.parquet", index=False)
    if a.out:
        all_df.to_parquet(a.out, index=False)
    (a.root / "manifest.json").write_text(json.dumps(manifest, indent=1, default=str))
    hf = pd.read_parquet(a.hf_parquet, columns=["class", "Day", "alerted"]) if a.hf_parquet and a.hf_parquet.exists() else None
    audit(a.root, days, sched, a.pad, all_df, manifest, hf, a.cic_csv_dir)
    print(all_df.groupby(["Day", "class"]).size().to_string())
    print(f"-> {a.root / 'LABEL_AUDIT.md'}" + ("" if missing else f", {a.root / 'suricata2017_rebuilt.parquet'}"))


if __name__ == "__main__":
    main()
