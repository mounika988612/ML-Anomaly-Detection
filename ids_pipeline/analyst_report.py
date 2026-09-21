"""Analyst-facing alert reports: plain-language explanation + signature (Suricata/Zeek) context.

For every explained alert of the anomaly model this builds a short report that answers what a SOC analyst
asks first:
  1. Do the signature IDS and the anomaly model agree?   (verdict + priority)
  2. Why is this flow odd?      top SHAP features in words, against what is normal for the same service role,
                                marked "stable" only if they are in the top-k of two independent SHAP runs
  3. What might it be?          rule-based behaviour hypothesis (worded as "consistent with", never a diagnosis)
  4. Where do I look next?      network context (IPs, ports, URIs) and concrete next steps
The ground-truth label is printed last and only for evaluation; it is never used to write the report.

Signature context providers:
  Suricata2017Context : Suricata alert (ET signature/category/severity) and HTTP/DNS/TLS fields stored per flow
                        in the dataset (real 5-tuple available).
  PcapContext         : Suricata eve.json + Zeek conn/http/notice logs run on a CSE-CIC-IDS2018 victim capture;
                        the CSV has no IPs, so a flow is matched to an attacker connection by start time + dst port.
"""
import ast
import json
import re

import numpy as np
import pandas as pd

from .features import _raw_frame, assign_roles
from .utils import get_logger

log = get_logger()

# name -> (plain label, unit kind). kinds: count bytes us rate flag ratio secs num
GLOSSARY = {
    "Flow Duration": ("flow duration", "us"), "Tot Fwd Pkts": ("packets sent by the client", "count"),
    "Tot Bwd Pkts": ("packets sent by the server", "count"), "TotLen Fwd Pkts": ("bytes sent by the client", "bytes"),
    "TotLen Bwd Pkts": ("bytes sent by the server", "bytes"), "Flow Byts/s": ("data rate", "rate"),
    "Flow Pkts/s": ("packet rate", "rate"), "Fwd Pkts/s": ("client packet rate", "rate"),
    "Bwd Pkts/s": ("server packet rate", "rate"), "Flow IAT Mean": ("mean gap between packets", "us"),
    "Flow IAT Std": ("variation of gaps between packets", "us"), "Flow IAT Max": ("longest gap between packets", "us"),
    "Flow IAT Min": ("shortest gap between packets", "us"), "Fwd IAT Tot": ("total time between client packets", "us"),
    "Fwd IAT Mean": ("mean gap between client packets", "us"), "Fwd IAT Max": ("longest gap between client packets", "us"),
    "Fwd IAT Min": ("shortest gap between client packets", "us"), "Fwd IAT Std": ("variation of client packet gaps", "us"),
    "Bwd IAT Tot": ("total time between server packets", "us"), "Bwd IAT Mean": ("mean gap between server packets", "us"),
    "Bwd IAT Max": ("longest gap between server packets", "us"), "Bwd IAT Min": ("shortest gap between server packets", "us"),
    "Bwd IAT Std": ("variation of server packet gaps", "us"), "Idle Mean": ("mean idle time", "us"),
    "Idle Max": ("longest idle period", "us"), "Idle Min": ("shortest idle period", "us"), "Idle Std": ("variation of idle time", "us"),
    "Active Mean": ("mean active time", "us"), "Active Max": ("longest active period", "us"),
    "Active Min": ("shortest active period", "us"), "Active Std": ("variation of active time", "us"),
    "Fwd Pkt Len Max": ("largest client packet", "bytes"), "Fwd Pkt Len Min": ("smallest client packet", "bytes"),
    "Fwd Pkt Len Mean": ("average client packet size", "bytes"), "Fwd Pkt Len Std": ("variation of client packet size", "bytes"),
    "Bwd Pkt Len Max": ("largest server packet", "bytes"), "Bwd Pkt Len Min": ("smallest server packet", "bytes"),
    "Bwd Pkt Len Mean": ("average server packet size", "bytes"), "Bwd Pkt Len Std": ("variation of server packet size", "bytes"),
    "Pkt Len Mean": ("average packet size", "bytes"), "Pkt Len Max": ("largest packet", "bytes"),
    "Pkt Len Min": ("smallest packet", "bytes"), "Pkt Len Std": ("variation of packet size", "bytes"),
    "Pkt Len Var": ("variance of packet size", "num"), "Pkt Size Avg": ("average packet size", "bytes"),
    "Fwd Seg Size Avg": ("average client segment size", "bytes"), "Bwd Seg Size Avg": ("average server segment size", "bytes"),
    "Fwd Seg Size Min": ("smallest client segment", "bytes"), "Down/Up Ratio": ("download/upload ratio", "ratio"),
    "SYN Flag Cnt": ("packets with SYN flag (connection attempts)", "count"), "FIN Flag Cnt": ("packets with FIN flag (clean closes)", "count"),
    "RST Flag Cnt": ("packets with RST flag (aborted connections)", "count"), "PSH Flag Cnt": ("packets with PSH flag (push data)", "count"),
    "ACK Flag Cnt": ("packets with ACK flag", "count"), "URG Flag Cnt": ("packets with URG flag", "count"),
    "ECE Flag Cnt": ("packets with ECE flag", "count"), "CWE Flag Count": ("packets with CWR flag", "count"),
    "Fwd PSH Flags": ("client PSH flags", "count"), "Fwd Header Len": ("client header bytes", "bytes"),
    "Bwd Header Len": ("server header bytes", "bytes"), "Init Fwd Win Byts": ("client TCP window at start", "bytes"),
    "Init Bwd Win Byts": ("server TCP window at start", "bytes"), "Fwd Act Data Pkts": ("client packets carrying data", "count"),
    "Subflow Fwd Pkts": ("client packets per subflow", "count"), "Subflow Fwd Byts": ("client bytes per subflow", "bytes"),
    "Subflow Bwd Pkts": ("server packets per subflow", "count"), "Subflow Bwd Byts": ("server bytes per subflow", "bytes"),
    "Fwd Byts/b Avg": ("client bytes per bulk transfer", "bytes"), "Fwd Pkts/b Avg": ("client packets per bulk transfer", "count"),
    "Bwd Byts/b Avg": ("server bytes per bulk transfer", "bytes"), "Bwd Pkts/b Avg": ("server packets per bulk transfer", "count"),
    "proto_tcp": ("uses TCP", "flag"), "proto_udp": ("uses UDP", "flag"), "proto_other": ("uses a non-TCP/UDP protocol", "flag"),
    # Suricata2017 features
    "pkts_ts": ("packets sent by the client", "count"), "pkts_tc": ("packets sent by the server", "count"),
    "bytes_ts": ("bytes sent by the client", "bytes"), "bytes_tc": ("bytes sent by the server", "bytes"),
    "age": ("flow lifetime", "secs"), "dir_ratio": ("server/client byte ratio", "ratio"),
    "bytes_per_pkt_ts": ("average client packet size", "bytes"), "bytes_per_pkt_tc": ("average server packet size", "bytes"),
    "n_dns": ("DNS messages in the flow", "count"), "dns_nxdomain": ("DNS 'name does not exist' answers", "count"),
    "dns_name_len": ("longest DNS name", "num"), "n_http": ("HTTP requests in the flow", "count"),
    "http_url_len": ("longest HTTP URL", "num"), "http_4xx": ("HTTP client-error responses (4xx)", "count"),
    "http_5xx": ("HTTP server-error responses (5xx)", "count"), "http_post": ("HTTP POST requests", "count"),
    "http_ua_len": ("HTTP user-agent length", "num"), "has_tls": ("TLS session present", "flag"),
    "tls_self_signed": ("self-signed TLS certificate", "flag"), "tls_valid_days": ("TLS certificate validity (days)", "num"),
    "tls_v10": ("old TLS 1.0", "flag"), "has_ssh": ("SSH session present", "flag"), "n_anomaly": ("Suricata protocol-anomaly events", "count"),
    "ts_syn": ("SYN sent by client", "flag"), "ts_rst": ("RST sent by client", "flag"), "tc_rst": ("RST sent by server", "flag"),
    "tc_syn": ("SYN sent by server", "flag"), "state_new": ("flow never completed (state new)", "flag"),
    "reason_timeout": ("flow ended by timeout", "flag"),
    "http_get": ("HTTP GET requests", "count"), "http_2xx": ("HTTP success responses (2xx)", "count"),
    "http_3xx": ("HTTP redirects (3xx)", "count"), "http_other_method": ("HTTP requests with unusual methods", "count"),
    "http_host_len": ("length of the HTTP host name", "num"), "http_has_referer": ("HTTP request has a referer", "flag"),
    "http_length": ("HTTP response size", "bytes"), "n_fileinfo": ("files transferred in the flow", "count"),
    "fileinfo_size": ("size of transferred file", "bytes"), "tls_sni_len": ("length of the TLS server name", "num"),
    "tls_resumed": ("TLS session resumed", "flag"), "tls_v11": ("old TLS 1.1", "flag"), "tls_v12": ("TLS 1.2", "flag"),
    "dns_A": ("DNS A lookups", "count"), "dns_AAAA": ("DNS AAAA lookups", "count"), "dns_PTR": ("DNS reverse lookups", "count"),
    "dns_servfail": ("DNS server failures", "count"), "dns_n_answers": ("DNS answers", "count"), "dns_ttl_min": ("smallest DNS TTL", "num"),
    "n_dns_query": ("DNS queries", "count"), "n_dns_answer": ("DNS answers", "count"), "has_tcp": ("TCP flow", "flag"),
    "tcp_closed": ("TCP connection closed normally", "flag"), "tcp_established": ("TCP connection established", "flag"),
    "state_established": ("flow still established", "flag"), "state_closed": ("flow closed", "flag"),
    "reason_forced": ("flow ended by forced timeout", "flag"), "reason_shutdown": ("flow ended by shutdown", "flag"),
    "ts_fin": ("FIN sent by client", "flag"), "tc_fin": ("FIN sent by server", "flag"), "ts_psh": ("PSH sent by client", "flag"),
    "tc_psh": ("PSH sent by server", "flag"), "ts_ack": ("ACK sent by client", "flag"), "tc_ack": ("ACK sent by server", "flag"),
    "ssh_sw_len": ("SSH software string length", "num"), "n_ftp": ("FTP commands", "count"), "ftp_err": ("FTP errors", "count"),
    # UNSW-NB15 features
    "dur": ("flow duration", "secs"), "spkts": ("packets sent by the client", "count"), "dpkts": ("packets sent by the server", "count"),
    "sbytes": ("bytes sent by the client", "bytes"), "dbytes": ("bytes sent by the server", "bytes"), "rate": ("packet rate", "rate"),
    "sttl": ("client IP TTL", "num"), "dttl": ("server IP TTL", "num"), "sload": ("client data rate (bit/s)", "rate"),
    "dload": ("server data rate (bit/s)", "rate"), "ct_srv_src": ("connections from this client to this service (last 100)", "count"),
    "ct_dst_ltm": ("connections to this destination (last 100)", "count"), "ct_src_ltm": ("connections from this client (last 100)", "count"),
}

HIGH_VOLUME = {"Tot Fwd Pkts", "Flow Pkts/s", "Fwd Pkts/s", "Subflow Fwd Pkts", "pkts_ts", "spkts", "rate", "Fwd Act Data Pkts"}
SCAN = {"SYN Flag Cnt", "RST Flag Cnt", "ts_syn", "tc_rst", "ts_rst", "state_new"}
NO_REPLY = {"Tot Bwd Pkts", "TotLen Bwd Pkts", "pkts_tc", "bytes_tc", "dpkts", "dbytes", "Bwd Pkts/s"}
UPLOAD = {"TotLen Fwd Pkts", "Subflow Fwd Byts", "bytes_ts", "sbytes", "Fwd Byts/b Avg"}
DOWNLOAD = {"TotLen Bwd Pkts", "Subflow Bwd Byts", "bytes_tc", "dbytes", "Bwd Byts/b Avg"}
SLOW = {"Flow IAT Max", "Fwd IAT Max", "Bwd IAT Max", "Idle Max", "Idle Mean", "Flow IAT Mean", "Fwd IAT Tot", "Bwd IAT Tot"}
WEB = {"http_url_len", "http_4xx", "http_5xx", "n_http", "http_post"}
DNS = {"dns_nxdomain", "dns_name_len", "n_dns"}
TLS = {"tls_self_signed", "tls_valid_days", "tls_v10"}


def _label(name):
    return GLOSSARY.get(name, (name, "num"))


def _fmt(kind, v):
    if kind == "us":
        s = v / 1e6
        return f"{s * 1000:.0f} ms" if s < 1 else f"{s:.1f} s"
    if kind == "secs":
        return f"{v * 1000:.0f} ms" if v < 1 else f"{v:.1f} s"
    if kind == "bytes":
        for u, d in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
            if abs(v) >= d:
                return f"{v / d:.1f} {u}"
        return f"{v:.0f} B"
    if kind == "rate":
        return f"{v:,.0f} /s"
    if kind == "flag":
        return "yes" if v >= 0.5 else "no"
    if kind in ("count",):
        return f"{v:,.0f}"
    return f"{v:,.2f}" if abs(v) < 100 else f"{v:,.0f}"


def _vs(v, med, lo, hi):
    if v > hi:
        r = v / med if med > 0 else np.inf
        return "far above normal" if r > 10 or not np.isfinite(r) else "above normal"
    if v < lo:
        return "well below normal" if med > 0 and v < med * 0.1 else "below normal"
    return "normal alone, unusual in combination"


class Baseline:
    """Benign training flows per service role: median / 5th / 95th percentile of every raw feature."""

    def __init__(self, raw, roles, names, min_rows=500):
        self.names = names
        self.g = self._q(raw)
        self.by_role = {r: self._q(raw[roles == r]) for r in np.unique(roles) if (roles == r).sum() >= min_rows}

    @staticmethod
    def _q(a):
        return np.percentile(a, [50, 5, 95], axis=0)

    def get(self, role):
        return self.by_role.get(role, self.g)


def raw_features(cfg, df, names):
    ds = cfg["data"].get("dataset", "cicids2018")
    r = _raw_frame(df)[names] if ds == "cicids2018" else df[names]
    return r.to_numpy(np.float64)


def raw_roles(cfg, df):
    return df["role"].to_numpy() if "role" in df else assign_roles(df["Dst Port"].to_numpy())


# --------------------------------------------------------------------------- signature context providers
class Suricata2017Context:
    """Signature/protocol context stored with every flow of the Suricata-annotated CIC-IDS2017 dataset."""
    name = "Suricata (Emerging Threats rules), context stored per flow in the dataset"

    def __init__(self, cfg):
        self.cfg = cfg
        self.cache = {}

    def _day(self, day):
        if day not in self.cache:
            raw = pd.read_parquet(self.cfg["data"]["suricata_parquet"],
                                  columns=["Flow ID", "log", "alerted", "start", "Day", "event_type_alert"])
            w = raw[raw.Day == day].reset_index(drop=True)
            hms = w.start.str.split(":", expand=True).astype(float)
            from .adapters.suricata2017 import DAYS
            ts = DAYS.index(day) * 86400 + hms[0] * 3600 + hms[1] * 60 + hms[2]
            perm = pd.DataFrame({"ts": ts, "row": np.arange(len(w))}).sort_values("ts").row.to_numpy()   # same sort as the adapter
            self.cache[day] = (w, perm)
        return self.cache[day]

    def lookup(self, day, i, dst_port=None, ts=None):
        w, perm = self._day(day)
        r = w.iloc[perm[i]]
        parts = r["Flow ID"].split("-")
        ctx = dict(src=parts[0], sport=parts[1], dst=parts[2], dport=parts[3], proto={"6": "TCP", "17": "UDP", "1": "ICMP"}.get(parts[4] if len(parts) > 4 else "", ""),
                   signatures=[], notices=[], http=[], dns=[], sni=None)
        if r.alerted:
            try:
                for a in ast.literal_eval(r.event_type_alert):
                    al = a["alert"]
                    ctx["signatures"].append(dict(name=al["signature"], category=al.get("category", ""),
                                                  severity=int(al.get("severity", 3))))
            except Exception:
                pass
        for pat, key in ((r"http_hostname: ([^,]+).*?http_url: ([^,]+)", "http"), (r"dns_rrname: ([^,]+)", "dns")):
            for m in re.findall(pat, r.log)[:3]:
                ctx[key].append("/".join(m) if isinstance(m, tuple) else m)
        m = re.search(r"tls_sni: ([^,]+)", r.log)
        ctx["sni"] = m.group(1) if m else None
        return ctx


class PcapContext:
    """Suricata eve.json + Zeek logs from a victim capture (see signature_compare.py)."""
    name = "Suricata (Emerging Threats rules) + Zeek on the raw pcap of the victim host"

    def __init__(self, capture_dir, day, attacker):
        from pathlib import Path

        from .signature_compare import read_zeek
        d = Path(capture_dir)
        self.day, self.attacker = day, attacker
        conn = read_zeek(d / "zeek" / "conn.log")
        conn["ts"] = conn.ts.astype(float)
        conn["dur"] = pd.to_numeric(conn.duration, errors="coerce").fillna(0)
        self.conn = conn[conn["id.orig_h"] == attacker].sort_values("ts").reset_index(drop=True)
        self.conn["orig_p"] = self.conn["id.orig_p"].astype(int)
        self.conn["resp_p"] = self.conn["id.resp_p"].astype(int)
        sig = {}
        for line in open(d / "suri" / "eve.json", encoding="utf-8"):
            e = json.loads(line)
            if e["event_type"] == "alert" and e["alert"]["signature"].startswith("ET ") and e["src_ip"] == attacker:
                sig.setdefault(e.get("src_port"), {})[e["alert"]["signature"]] = (e["alert"]["category"], e["alert"]["severity"])
        self.sig = sig
        notice = read_zeek(d / "zeek" / "notice.log")
        notice = notice[notice.note != "CaptureLoss::Too_Little_Traffic"]
        self.notices = [f"{r.note}: {r.msg}" for r in notice.itertuples() if attacker in str(getattr(r, "src", ""))]
        try:
            http = read_zeek(d / "zeek" / "http.log")
            self.http = http.groupby("uid").agg(uri=("uri", lambda s: list(s)[:3]), status=("status_code", lambda s: list(s)[:3])).to_dict("index")
        except Exception:
            self.http = {}

    def lookup(self, day, i, dst_port=None, ts=None):
        from .data import T0
        from .signature_compare import UTC_OFFSET_S
        ctx = dict(src=None, sport=None, dst=None, dport=None, proto="", signatures=[], notices=[], http=[], dns=[], sni=None,
                   matched=False)
        if day != self.day or ts is None:
            return ctx
        epoch = (T0 - pd.Timestamp("1970-01-01")).total_seconds() + ts + UTC_OFFSET_S
        starts = self.conn.ts.to_numpy()
        j = int(np.searchsorted(starts, epoch + 2.0)) - 1
        if j < 0:
            return ctx
        c = self.conn.iloc[j]
        if epoch > c.ts + c.dur + 5.0 or (dst_port is not None and int(c.resp_p) != int(dst_port)):
            return ctx
        ctx.update(matched=True, src=self.attacker, sport=int(c.orig_p), dst=c["id.resp_h"], dport=int(c.resp_p),
                   proto=c.proto.upper(), notices=self.notices)
        for n, (cat, sev) in self.sig.get(int(c.orig_p), {}).items():
            ctx["signatures"].append(dict(name=n, category=cat, severity=int(sev)))
        h = self.http.get(c.uid)
        if h:
            ctx["http"] = [f"{u} → {s}" for u, s in zip(h["uri"], h["status"])]
        return ctx


# --------------------------------------------------------------------------- interpretation
def _evidence(names, x_raw, phi, phi2, base, k_show, k_robust):
    top = list(np.argsort(-np.abs(phi))[:k_show])
    robust = set(np.argsort(-np.abs(phi))[:k_robust]) & set(np.argsort(-np.abs(phi2))[:k_robust])
    med, p05, p95 = base
    rows = []
    for j in top:
        if phi[j] <= 0:                     # only features that push the score UP explain the alert
            continue
        lab, kind = _label(names[j])
        rows.append(dict(feature=names[j], label=lab, kind=kind, value=x_raw[j], typical=med[j], upper=p95[j], lower=p05[j],
                         shap=float(phi[j]), stable=j in robust, verdict=_vs(x_raw[j], med[j], p05[j], p95[j])))
    return rows


def _hypotheses(ev):
    def hit(group, direction="high"):
        out = []
        for e in ev:
            if e["feature"] in group and e["stable"]:      # only evidence that survives a second explanation run
                if direction == "high" and e["value"] > e["upper"]:
                    out.append(e)
                if direction == "low" and e["value"] < e["typical"] * 0.5:
                    out.append(e)
        return out

    h = []
    if hit(HIGH_VOLUME):
        h.append(("High packet volume or rate from the client",
                  "consistent with a flood / DoS attempt or an automated request loop",
                  ["Check how many similar flows this source produced in the same minute",
                   "Compare with the service's normal request rate (rate limiting / WAF logs)"]))
    if hit(SCAN) and (hit(NO_REPLY, "low") or hit(SCAN)):
        h.append(("Many connection attempts with few or no replies",
                  "consistent with port scanning or probing of closed/filtered services",
                  ["List the distinct destination ports contacted by this source",
                   "Check firewall logs for blocked or reset connections from the same source"]))
    if hit(UPLOAD):
        h.append(("Unusually large data sent by the client",
                  "consistent with an upload, data exfiltration, or a payload-heavy exploit attempt",
                  ["Identify what was sent (destination, protocol, file transfer logs)",
                   "Check whether the client normally sends this much data to this service"]))
    if hit(DOWNLOAD):
        h.append(("Unusually large data returned by the server",
                  "consistent with a bulk download or data being pulled from the server",
                  ["Check which resource was fetched and by whom (proxy/web logs)"]))
    if hit(SLOW):
        h.append(("Very long pauses between packets",
                  "consistent with a slow attack (e.g. Slowloris), a stalled session, or a low-rate C2 keep-alive",
                  ["Check for many long-lived half-open connections from the same source",
                   "Look for regular periodic timing (beaconing) across this host's flows"]))
    if hit(WEB):
        h.append(("Unusual HTTP activity (long URLs, error responses, POSTs)",
                  "consistent with web probing, brute-forcing or injection attempts",
                  ["Read the request URIs and status codes in the web server / Zeek http.log",
                   "Look for repeated login or parameter-tampering requests"]))
    if hit(DNS):
        h.append(("Unusual DNS behaviour (many failed lookups or long names)",
                  "consistent with DNS tunnelling, DGA malware or reconnaissance",
                  ["Inspect the queried names in dns.log for random-looking or very long labels"]))
    if hit(TLS):
        h.append(("Unusual TLS certificate or protocol version",
                  "consistent with a self-signed / short-lived certificate typical of malware C2 or a misconfigured service",
                  ["Inspect the certificate subject/issuer and the SNI value"]))
    return h


SIG_MEANING = [   # (keyword in signature name or category, meaning, next step)
    ("TROJAN", "traffic matches a known malware / remote-access-trojan pattern (e.g. a check-in to a command-and-control server)",
     "Isolate the source host and check it for the malware named in the signature; block the destination"),
    ("CnC", "traffic to a known command-and-control server", "Isolate the source host; block the destination address"),
    ("MALWARE", "traffic matches known malware behaviour", "Isolate the source host and run an endpoint scan"),
    ("Network Trojan", "traffic matches known malware behaviour", "Isolate the source host and run an endpoint scan"),
    ("SCAN", "the source is scanning or probing services", "Check what else the source contacted; block it if external"),
    ("Network Scan", "the source is scanning or probing services", "Check what else the source contacted; block it if external"),
    ("SQL", "an SQL-injection attempt against a web application", "Review the web application logs for the request and check the database for tampering"),
    ("WEB_SERVER", "an attack pattern against a web server", "Review web server logs and patch/harden the targeted application"),
    ("Web Application Attack", "an attack pattern against a web application", "Review web server logs and patch/harden the targeted application"),
    ("Administrator Privilege", "an attempt to gain administrator rights", "Check the target for a successful login or new privileged account"),
    ("Information Leak", "an attempt to read information it should not see", "Check what data was returned to the source"),
    ("Privacy Violation", "a policy violation such as a tool or user-agent that is not normally allowed", "Confirm with the host owner whether the software is authorised"),
    ("POLICY", "a policy violation such as a tool or user-agent that is not normally allowed", "Confirm with the host owner whether the software is authorised"),
    ("DROP", "traffic involving an address on a known-bad reputation list", "Block the address if it is not required"),
    ("CINS", "traffic involving an address with a poor threat-intelligence reputation", "Check whether the address should be blocked"),
    ("Bad Traffic", "traffic that violates protocol norms", "Check for a misconfigured client or an evasion attempt"),
    ("Misc Attack", "a generic attack pattern", "Read the full signature description for details"),
]


def signature_meaning(sig):
    key = f"{sig['name']} {sig['category']}"
    for kw, meaning, step in SIG_MEANING:
        if kw.lower() in key.lower():
            return meaning, step
    return "a known suspicious pattern (see the rule description)", "Read the rule description for the signature ID"


def _priority(sev, ratio, has_sig):
    if has_sig and sev <= 2:
        return "HIGH"
    if has_sig or ratio >= 3:
        return "MEDIUM"
    return "LOW"


def _fmt_ev(e):
    return (f"| {e['label']} | {_fmt(e['kind'], e['value'])} | {_fmt(e['kind'], e['typical'])} "
            f"(up to {_fmt(e['kind'], e['upper'])}) | {e['verdict']} | {'yes' if e['stable'] else 'no'} |")


def build_report(cfg, method, fs, alerts, items, thr, provider, res, suffix):
    """items: one dict per explained alert (aligned with `alerts` rows): raw, role, score, phi, phi2, ts, dst_port."""
    names, ecfg = fs.names, cfg["explain"]
    k_show, k_robust = ecfg.get("report_top", 5), ecfg["top_k"]
    md = [f"# Analyst alert report ({method})\n",
          "How to read this: each alert shows (1) whether the signature IDS and the anomaly model agree, (2) the traffic "
          "properties that made it look abnormal compared with normal traffic of the same service role, (3) a hypothesis of "
          "what the behaviour resembles, and (4) what to check next. \"Stable evidence\" = the feature is in the top-"
          f"{k_robust} of two independent explanation runs; unstable evidence should be treated with caution. "
          "Hypotheses are patterns, not diagnoses.\n",
          f"Signature source: {provider.name if provider else 'none available for this dataset'}\n"]
    table = []
    for n, (a, it) in enumerate(zip(alerts.itertuples(), items), 1):
        ctx = provider.lookup(a.day, int(a.i), it["dst_port"], it["ts"]) if provider else dict(signatures=[], notices=[], http=[], dns=[], sni=None)
        ev = _evidence(names, it["raw"], it["phi"], it["phi2"], it["base"], k_show, k_robust)
        hyp = _hypotheses(ev)
        ratio = it["score"] / thr
        sigs = ctx["signatures"]
        sev = min([s["severity"] for s in sigs], default=3)
        prio = _priority(sev, ratio, bool(sigs))
        if sigs:
            verdict = "CONFIRMED - the signature IDS and the anomaly model both flag this flow"
            kind = "confirmed"
        else:
            verdict = ("ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern "
                       "(candidate novel activity or a false alarm)")
            kind = "anomaly_only"
        n_stable = sum(e["stable"] for e in ev)
        conf = "high" if ev and n_stable >= 3 else "medium" if n_stable >= 1 else "low"
        md.append(f"## Alert {n}: {prio} priority | {a.day} | service role: {it['role']} | anomaly score {ratio:.1f}x the alert threshold\n")
        md.append(f"**Verdict:** {verdict}\n")
        md.append("**Detectors**\n")
        if sigs:
            for s in sigs:
                m, _ = signature_meaning(s)
                md.append(f"- Suricata: `{s['name']}` - {s['category']} (severity {s['severity']}). Meaning: {m}.")
        else:
            md.append("- Suricata: no Emerging Threats rule fired for this flow")
        md += [f"- Zeek: {t}" for t in ctx["notices"]] or (["- Zeek: no notice raised"] if provider and not isinstance(provider, Suricata2017Context) else [])
        md.append(f"- Anomaly model: {ratio:.1f}x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)\n")
        md.append("**Why it looks abnormal** (compared with normal traffic for this service role)\n")
        if ev:
            md += ["| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |", "|---|---|---|---|---|"]
            md += [_fmt_ev(e) for e in ev]
            md.append("")
        else:
            md.append("No single property stands out; the alert comes from a combination of many small deviations.\n")
        if hyp:
            md.append("**What the traffic shape resembles** (hypothesis"
                      + (", secondary to the signature above, which is the more specific evidence)\n" if sigs else ")\n"))
            for t, why, _ in hyp:
                md.append(f"- {t}: {why}.")
            md.append("")
        if ctx.get("src") or ctx.get("http") or ctx.get("dns") or ctx.get("sni"):
            md.append("**Network context**\n")
            if ctx.get("src"):
                md.append(f"- {ctx['src']}:{ctx['sport']} -> {ctx['dst']}:{ctx['dport']} ({ctx['proto']})")
            md += [f"- HTTP request: {h}" for h in ctx["http"]] + [f"- DNS query: {d}" for d in ctx["dns"]]
            if ctx.get("sni"):
                md.append(f"- TLS server name: {ctx['sni']}")
            md.append("")
        steps = [s for h in hyp for s in h[2]]
        if sigs:
            steps = list(dict.fromkeys(signature_meaning(s)[1] for s in sigs)) + steps
            steps.append("Look up the signature in the Emerging Threats rule documentation to confirm what it targets")
        if not sigs:
            steps.append("No signature matched: search the source host for other unusual flows around the same time before escalating")
        md.append("**Suggested next steps**\n")
        md += [f"- {s}" for s in dict.fromkeys(steps)] or ["- Review the flow in the flow/packet capture"]
        md.append(f"\n**Explanation confidence:** {conf} ({n_stable} of {len(ev)} evidence properties stable across two runs)\n")
        md.append(f"<sub>Evaluation only (not used above): ground-truth label = {a.label}</sub>\n")
        table.append(dict(alert=n, day=a.day, priority=prio, verdict=kind, signature="; ".join(s["name"] for s in sigs),
                          score_ratio=round(ratio, 2), stable_evidence=n_stable, evidence=len(ev),
                          hypothesis="; ".join(h[0] for h in hyp), true_label=a.label))
    df = pd.DataFrame(table)
    (res / f"analyst_report{suffix}.md").write_text("\n".join(md), encoding="utf-8")
    df.to_csv(res / f"analyst_report_summary{suffix}.csv", index=False)
    if len(df):
        log.info("analyst report: %d alerts | %s | confirmed by signature: %d | with hypothesis: %d",
                 len(df), df.priority.value_counts().to_dict(), int((df.verdict == "confirmed").sum()), int((df.hypothesis != "").sum()))
    return df
