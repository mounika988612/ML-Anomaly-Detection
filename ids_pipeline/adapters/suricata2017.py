"""CIC-IDS2017 as seen by Suricata (HF: yasirchemmakh/Cicids2017_Suricata_Logs).

Each row is one flow with the Suricata events attached to it (flow / dns / http / tls / ssh / ftp /
fileinfo / anomaly), Suricata's own decision (`alerted`, Emerging Threats rules) and the CIC ground
truth. Alert content is never used as a feature; `alerted` is kept only as the signature-detector
baseline (`sig`). Modalities = Suricata event types, i.e. genuine multi-source telemetry.
"""
import re
from concurrent.futures import ProcessPoolExecutor

import numpy as np
import pandas as pd

from ..features import assign_roles

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
_FLAGS = ("fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr")
MODALITIES = {
    "flow": ["pkts_ts", "pkts_tc", "bytes_ts", "bytes_tc", "age", "bytes_per_pkt_ts", "bytes_per_pkt_tc",
             "dir_ratio", "proto_tcp", "proto_udp", "proto_icmp", "state_new", "state_established",
             "state_closed", "reason_timeout", "reason_forced", "reason_shutdown"],
    "tcp": [f"{d}_{b}" for d in ("ts", "tc") for b in _FLAGS] + ["has_tcp", "tcp_closed", "tcp_established"],
    "dns": ["n_dns", "n_dns_query", "n_dns_answer", "dns_name_len", "dns_A", "dns_AAAA", "dns_PTR",
            "dns_other_type", "dns_nxdomain", "dns_servfail", "dns_n_answers", "dns_ttl_min"],
    "http": ["n_http", "http_get", "http_post", "http_other_method", "http_2xx", "http_3xx", "http_4xx",
             "http_5xx", "http_url_len", "http_host_len", "http_ua_len", "http_has_referer", "http_length",
             "n_fileinfo", "fileinfo_size"],
    "session": ["has_tls", "tls_v10", "tls_v11", "tls_v12", "tls_sni_len", "tls_resumed", "tls_self_signed",
                "tls_valid_days", "has_ssh", "ssh_sw_len", "n_ftp", "ftp_err", "n_anomaly"],
}
_KV = re.compile(r"(?:^|, )([a-z][a-z_0-9]*): ")


def _f(d, k, default=0.0):
    try:
        return float(d[k])
    except (KeyError, ValueError):
        return default


def _bits(flags, prefix, out):
    try:
        v = int(flags, 16)
    except (TypeError, ValueError):
        v = 0
    for i, b in enumerate(_FLAGS):
        out[f"{prefix}_{b}"] = float((v >> i) & 1)


def parse_log(log):
    o = dict.fromkeys(sum(MODALITIES.values(), []), 0.0)
    q = a = 0
    ttl = []
    for ev in log.split(" ; "):
        parts = _KV.split(ev)
        d = dict(zip(parts[1::2], parts[2::2]))
        t = d.get("event_type")
        if t == "flow":
            pt, pc = _f(d, "flow_pkts_toserver"), _f(d, "flow_pkts_toclient")
            bt, bc = _f(d, "flow_bytes_toserver"), _f(d, "flow_bytes_toclient")
            o.update(pkts_ts=pt, pkts_tc=pc, bytes_ts=bt, bytes_tc=bc, age=_f(d, "flow_age"),
                     bytes_per_pkt_ts=bt / max(pt, 1), bytes_per_pkt_tc=bc / max(pc, 1),
                     dir_ratio=(bc + 1) / (bt + 1))
            pr = d.get("proto", "")
            o["proto_tcp"], o["proto_udp"], o["proto_icmp"] = float(pr == "TCP"), float(pr == "UDP"), float(pr.startswith("ICMP"))
            st, rs = d.get("flow_state", ""), d.get("flow_reason", "")
            o["state_new"], o["state_established"], o["state_closed"] = float(st == "new"), float(st == "established"), float(st == "closed")
            o["reason_timeout"], o["reason_forced"], o["reason_shutdown"] = float(rs == "timeout"), float(rs == "forced"), float(rs == "shutdown")
            if "tcp_tcp_flags" in d:
                o["has_tcp"] = 1.0
                _bits(d.get("tcp_tcp_flags_ts"), "ts", o)
                _bits(d.get("tcp_tcp_flags_tc"), "tc", o)
                o["tcp_closed"], o["tcp_established"] = float(d.get("tcp_state") == "closed"), float(d.get("tcp_state") == "established")
        elif t == "dns":
            o["n_dns"] += 1
            o["dns_name_len"] = max(o["dns_name_len"], len(d.get("dns_rrname", "")))
            ty = d.get("dns_rrtype", "")
            if d.get("dns_type") == "query":
                q += 1
                o["dns_A"] += ty == "A"
                o["dns_AAAA"] += ty == "AAAA"
                o["dns_PTR"] += ty == "PTR"
                o["dns_other_type"] += ty not in ("A", "AAAA", "PTR")
            else:
                a += 1
                rc = d.get("dns_rcode", "")
                o["dns_nxdomain"] += rc == "NXDOMAIN"
                o["dns_servfail"] += rc == "SERVFAIL"
                o["dns_n_answers"] += sum(k.startswith("dns_answers_") and k.endswith("_rrname") for k in d)
                ttl += [float(v) for k, v in d.items() if k.startswith("dns_answers_") and k.endswith("_ttl") and v.isdigit()]
        elif t == "http":
            o["n_http"] += 1
            m = d.get("http_http_method")
            o["http_get"] += m == "GET"
            o["http_post"] += m == "POST"
            o["http_other_method"] += m not in (None, "GET", "POST")
            s = d.get("http_status", "")
            for c in "2345":
                o[f"http_{c}xx"] += s.startswith(c)
            o["http_url_len"] = max(o["http_url_len"], len(d.get("http_url", "")))
            o["http_host_len"] = max(o["http_host_len"], len(d.get("http_hostname", "")))
            o["http_ua_len"] = max(o["http_ua_len"], len(d.get("http_http_user_agent", "")))
            o["http_has_referer"] = max(o["http_has_referer"], float("http_http_refer" in d))
            o["http_length"] = max(o["http_length"], _f(d, "http_length"))
        elif t == "fileinfo":
            o["n_fileinfo"] += 1
            o["fileinfo_size"] = max(o["fileinfo_size"], _f(d, "fileinfo_size"))
        elif t == "tls":
            o["has_tls"] = 1.0
            v = d.get("tls_version", "")
            o["tls_v10"], o["tls_v11"], o["tls_v12"] = float(v.endswith("1.0")), float(v.endswith("1.1")), float(v.endswith("1.2"))
            o["tls_sni_len"] = len(d.get("tls_sni", ""))
            o["tls_resumed"] = float(d.get("tls_session_resumed") == "True")
            o["tls_self_signed"] = float(d.get("tls_subject") is not None and d.get("tls_subject") == d.get("tls_issuerdn"))
            try:
                o["tls_valid_days"] = (pd.Timestamp(d["tls_notafter"]) - pd.Timestamp(d["tls_notbefore"])).days
            except Exception:
                pass
        elif t == "ssh":
            o["has_ssh"] = 1.0
            o["ssh_sw_len"] = len(d.get("ssh_client_software_version", ""))
        elif t == "ftp":
            o["n_ftp"] += 1
            o["ftp_err"] += d.get("ftp_completion_code_0", "").startswith(("4", "5"))
        elif t == "anomaly":
            o["n_anomaly"] += 1
    o["n_dns_query"], o["n_dns_answer"] = q, a
    o["dns_ttl_min"] = min(ttl) if ttl else 0.0
    return o


def _parse_chunk(logs):
    return pd.DataFrame([parse_log(s) for s in logs]).astype("float32")


def load_day(cfg, day):
    cache = cfg["paths"]["work_dir"] / "interim" / f"{day}.parquet"
    if cache.exists():
        return pd.read_parquet(cache)
    raw = pd.read_parquet(cfg["data"]["suricata_parquet"], columns=["Flow ID", "log", "alerted", "class", "start", "Day"])
    raw = raw[raw.Day == day].reset_index(drop=True)
    chunks = np.array_split(np.arange(len(raw)), 64)
    with ProcessPoolExecutor() as ex:
        feats = pd.concat(list(ex.map(_parse_chunk, [raw["log"].iloc[c].tolist() for c in chunks])), ignore_index=True)
    parts = raw["Flow ID"].str.split("-", expand=True)          # srcip-sport-dstip-dport-proto
    sp = pd.to_numeric(parts[1], errors="coerce").fillna(0)
    dp = pd.to_numeric(parts[3], errors="coerce").fillna(0)
    hms = raw["start"].str.split(":", expand=True).astype(float)
    df = feats.assign(
        ts=DAYS.index(day) * 86400 + hms[0] * 3600 + hms[1] * 60 + hms[2],
        Label=raw["class"].str.strip().replace({"BENIGN": "Benign"}),
        role=assign_roles(np.minimum(sp, dp).to_numpy()),
        sig=raw["alerted"].astype("int8"))
    df["attack"] = (df.Label != "Benign").astype("int8")
    df = df.sort_values("ts").reset_index(drop=True)
    cache.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(cache)
    return df
