"""Rebuilt Suricata2017 dataset (scripts/build_suricata2017.py): eve.json -> adapter format, and schedule-based labels."""
import importlib.util
import json
from pathlib import Path

import pandas as pd
import pytest

from ids_pipeline.adapters.suricata2017 import parse_log

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("build_suricata2017", ROOT / "scripts" / "build_suricata2017.py")
b = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(b)
SCHED = b.load_schedule(ROOT / "docs" / "cic2017_attack_schedule.csv")

FLOW = {"timestamp": "2017-07-05T18:13:00+0000", "flow_id": 7, "event_type": "flow", "src_ip": "172.16.0.1", "src_port": 45022,
        "dest_ip": "192.168.10.51", "dest_port": 444, "proto": "TCP",
        "flow": {"pkts_toserver": 10, "pkts_toclient": 8, "bytes_toserver": 1000, "bytes_toclient": 5000,
                 "start": "2017-07-05T18:12:20.700136+0000", "end": "2017-07-05T18:13:00+0000", "age": 40,
                 "state": "closed", "reason": "timeout", "alerted": True},
        "tcp": {"tcp_flags": "1b", "tcp_flags_ts": "1b", "tcp_flags_tc": "1b", "state": "closed"}}
DNS_REQ = {"flow_id": 9, "event_type": "dns",
           "dns": {"version": 3, "type": "request", "id": 1, "queries": [{"rrname": "a.example.com", "rrtype": "A"}]}}
DNS_RSP = {"flow_id": 9, "event_type": "dns",
           "dns": {"version": 3, "type": "response", "id": 1, "rcode": "NXDOMAIN", "queries": [{"rrname": "a.example.com", "rrtype": "A"}],
                   "answers": [{"rrname": "a.example.com", "rrtype": "A", "ttl": 30, "rdata": "1.2.3.4"}]}}
HTTP = {"flow_id": 7, "event_type": "http", "http": {"hostname": "x", "url": "/a, b ; c", "http_method": "POST", "status": 404,
                                                    "http_user_agent": "Mozilla/5.0 (X11, Linux)"}}


def test_event_text_is_parsed_by_the_unchanged_adapter():
    o = parse_log(" ; ".join(b.event_text(e) for e in (FLOW, HTTP, DNS_REQ, DNS_RSP)))
    assert (o["pkts_ts"], o["bytes_tc"], o["age"], o["proto_tcp"], o["state_closed"], o["has_tcp"]) == (10, 5000, 40, 1, 1, 1)
    assert o["ts_fin"] == o["ts_syn"] == o["ts_ack"] == 1 and o["ts_rst"] == 0
    assert (o["n_http"], o["http_post"], o["http_4xx"], o["http_url_len"]) == (1, 1, 1, len("/a,b ;c"))
    assert (o["n_dns_query"], o["n_dns_answer"], o["dns_A"], o["dns_nxdomain"], o["dns_n_answers"], o["dns_ttl_min"]) == (1, 1, 1, 1, 1, 30)


def test_flow_log_carries_no_detector_decision_or_absolute_time():
    t = b.event_text(FLOW)
    assert "alerted" not in t and "flow_start" not in t and "flow_end" not in t


def test_read_eve_groups_by_flow_and_separates_engine_alerts(tmp_path):
    et = {"flow_id": 7, "event_type": "alert",
          "alert": {"signature_id": 2018377, "signature": "ET EXPLOIT HeartBleed", "category": "c", "severity": 1}}
    eng = {"flow_id": 7, "event_type": "alert", "alert": {"signature_id": 2200073, "signature": "SURICATA IPv4 invalid checksum"}}
    quiet = {**FLOW, "flow_id": 8, "src_ip": "192.168.10.5", "flow": {**FLOW["flow"], "alerted": True}}
    lines = [HTTP, et, eng, FLOW, eng | {"flow_id": 8}, quiet, DNS_REQ, {"event_type": "stats", "stats": {"flow": {"memcap": 0}}}]
    (tmp_path / "eve.json").write_text("\n".join(json.dumps(x) for x in lines))
    df, info = b.read_eve(tmp_path / "eve.json")
    assert df["Flow ID"].tolist() == ["172.16.0.1-45022-192.168.10.51-444-6", "192.168.10.5-45022-192.168.10.51-444-6"]
    assert df.event_types.tolist() == ["['flow', 'http']", "['flow']"]
    assert df.alerted.tolist() == [True, False]          # engine-only alerts do not count as a signature detection
    assert df.n_engine_alerts.tolist() == [1, 1]
    assert "HeartBleed" in df.event_type_alert[0] and "checksum" not in df.event_type_alert[0]
    assert info["orphan_flows"] == 1 and info["suricata_stats"]["flow.memcap"] == 0      # DNS flow 9 never ended


def _label(day, rows, pad=60):
    src, dst, local = zip(*rows)
    ts = pd.DatetimeIndex([pd.Timestamp(f"{b.DATES[day]} {t}", tz="UTC") + b.UTC_MINUS_LOCAL for t in local])
    return b.label_flows(list(src), list(dst), ts, day, SCHED, pad)


def test_labels_follow_pair_window_and_local_time():
    cls, rule, pad_zone, drop = _label("Wednesday", [
        ("172.16.0.1", "192.168.10.51", "15:20:00"),     # Heartbleed, attacker -> victim
        ("192.168.10.51", "172.16.0.1", "15:32:59"),     # reverse direction, last minute of the window is inclusive
        ("172.16.0.1", "192.168.10.51", "15:33:30"),     # pad zone
        ("172.16.0.1", "192.168.10.51", "16:30:00"),     # attacker pair, no window -> dropped, not guessed
        ("192.168.10.5", "192.168.10.51", "15:20:00"),   # other host during the attack -> benign
        ("172.16.0.1", "192.168.10.50", "10:50:00"),     # DoS Hulk
    ])
    assert cls.tolist() == ["Heartbleed", "Heartbleed", "Heartbleed", "BENIGN", "BENIGN", "DoS Hulk"]
    assert pad_zone.tolist() == [False, False, True, False, False, False]
    assert drop.tolist() == [False, False, False, True, False, False]
    assert (rule[:3] >= 0).all() and rule[3] == rule[4] == -1


def test_infected_host_is_benign_outside_its_scan_window():
    cls, _, _, drop = _label("Thursday", [
        ("192.168.10.8", "192.168.10.19", "15:10:00"),   # scan from the infected Vista host
        ("192.168.10.19", "192.168.10.8", "15:10:00"),   # 'fwd' row: the reverse direction is not the scan
        ("192.168.10.8", "192.168.10.3", "11:00:00"),    # its normal traffic outside the window
        ("192.168.10.8", "205.174.165.73", "14:20:00"),  # meterpreter session
    ])
    assert cls.tolist() == ["Infiltration - Portscan", "BENIGN", "BENIGN", "Infiltration"]
    assert not drop.any()


def test_monday_is_all_benign():
    cls, _, _, drop = _label("Monday", [("172.16.0.1", "192.168.10.50", "10:00:00")])
    assert cls.tolist() == ["BENIGN"] and not drop.any()


@pytest.mark.parametrize("pad", [60])
def test_schedule_windows_of_one_pair_do_not_overlap(pad):
    for (day, att, vic), g in SCHED.groupby(["day", "attacker", "victim"]):
        w = sorted(b.window(day, r, pad)[2:] for r in g.itertuples())
        assert all(w[i][1] <= w[i + 1][0] for i in range(len(w) - 1)), (day, att, vic)


def test_build_day_writes_the_columns_the_adapter_and_reports_read(tmp_path):
    (tmp_path / "Wednesday" / "suri").mkdir(parents=True)
    late = {**FLOW, "flow_id": 8, "flow": {**FLOW["flow"], "start": "2017-07-05T19:30:00+0000"}}       # 16:30 local: dropped
    early = {**FLOW, "flow_id": 6, "dest_ip": "192.168.10.9", "flow": {**FLOW["flow"], "start": "2017-07-05T12:00:01+0000"}}
    (tmp_path / "Wednesday" / "suri" / "eve.json").write_text("\n".join(json.dumps(x) for x in (HTTP, FLOW, late, early)))
    info = b.build_day(tmp_path, "Wednesday", SCHED, 60)
    df = pd.read_parquet(tmp_path / "Wednesday" / "flows.parquet")
    assert {"Flow ID", "log", "alerted", "class", "start", "Day", "event_type_alert"} <= set(df.columns)   # adapter + analyst_report
    assert df.start.tolist() == ["12:00:01", "18:12:20"] and df["class"].tolist() == ["BENIGN", "Heartbleed"]
    assert df.truth.tolist() == [False, True] and df.label.tolist() == ["normal", "attack"]
    assert info["dropped_unscheduled_attacker_flows"] == 1 and info["flows_total"] == 3
