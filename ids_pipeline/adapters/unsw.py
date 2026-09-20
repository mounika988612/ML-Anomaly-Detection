"""UNSW-NB15 official partition (training-set 175,341 flows / testing-set 82,332 flows).

The public mirror (HF Mireu-Lab/UNSW-NB15) has the two files swapped, so its `test.csv` is the official
training set. The partition carries no timestamps: the split is the official one, not time-separated.
"""
from pathlib import Path

import numpy as np
import pandas as pd

MODALITIES = {
    "volume": ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sload", "dload", "smean", "dmean"],
    "timing_tcp": ["sttl", "dttl", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin", "dwin",
                   "tcprtt", "synack", "ackdat"],
    "categorical": ["proto_tcp", "proto_udp", "proto_other", "state_FIN", "state_INT", "state_CON",
                    "state_REQ", "state_other", "svc_none", "svc_http", "svc_dns", "svc_ftp", "svc_smtp",
                    "svc_ssh", "svc_other"],
    "application": ["trans_depth", "response_body_len", "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd"],
    "context": ["ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
                "ct_dst_src_ltm", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports"],
}
_SVC_ROLE = {"http": 0, "ssh": 1, "ftp": 2, "ftp-data": 2, "dns": 3, "smtp": 4}   # ids of features.ROLE_NAMES


def load_day(cfg, day):
    f = {"train": "test.csv", "test": "train.csv"}[day]         # swapped on the mirror, see docstring
    d = pd.read_csv(Path(cfg["data"]["unsw_dir"]) / f)
    o = d[[c for c in sum(MODALITIES.values(), []) if c in d]].copy()
    o["proto_tcp"], o["proto_udp"] = (d.proto == "tcp").astype(float), (d.proto == "udp").astype(float)
    o["proto_other"] = 1.0 - o.proto_tcp - o.proto_udp
    for s in ("FIN", "INT", "CON", "REQ"):
        o[f"state_{s}"] = (d.state == s).astype(float)
    o["state_other"] = 1.0 - o[["state_FIN", "state_INT", "state_CON", "state_REQ"]].sum(axis=1)
    for k, s in (("none", "-"), ("http", "http"), ("dns", "dns"), ("ftp", "ftp"), ("smtp", "smtp"), ("ssh", "ssh")):
        o[f"svc_{k}"] = (d.service == s).astype(float)
    o["svc_other"] = 1.0 - o[[c for c in o if c.startswith("svc_")]].sum(axis=1)
    feat = [c for c in o.columns]
    o = o.astype({c: "float32" for c in feat})
    o["role"] = d.service.map(_SVC_ROLE).fillna(6).astype("int8")
    # no timestamps and the files are sorted by class, so file order would put every attack in the "later" slice:
    # use a seeded random order instead (the train/val cutoff then becomes a random split)
    o["ts"] = np.random.RandomState(cfg["data"]["seed"]).permutation(len(d)).astype(np.float64)
    o["Label"] = d.attack_cat.replace({"Normal": "Benign"})
    o["attack"] = d.label.astype("int8")
    return o.sort_values("ts").reset_index(drop=True)
