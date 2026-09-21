"""Input contract for flow records (CICFlowMeter / CSE-CIC-IDS2018 column layout).

Two entry points share the same rules:
  * training data  -> `require_columns` (fail fast with the list of missing columns)
  * serving data   -> `validate_flows`  (per-row rejection, the rest of the batch is still scored)
"""
import numpy as np
import pandas as pd

from .features import MODALITIES, ROLE_NAMES, raw_columns

_PROTO = {"proto_tcp", "proto_udp", "proto_other"}


class DataError(ValueError):
    """Input data does not match the expected layout."""


ROLE_COLUMN = "__role__"     # optional per-flow asset role (one of ROLE_NAMES); overrides the port-derived role

# CICFlowMeter releases name the same columns differently (CIC-IDS2017 / newer builds vs the CSE-CIC-IDS2018 CSVs).
COLUMN_ALIASES = {
    "Destination Port": "Dst Port", "Total Fwd Packets": "Tot Fwd Pkts", "Total Backward Packets": "Tot Bwd Pkts",
    "Total Length of Fwd Packets": "TotLen Fwd Pkts", "Total Length of Bwd Packets": "TotLen Bwd Pkts",
    "Flow Bytes/s": "Flow Byts/s", "Flow Packets/s": "Flow Pkts/s", "Fwd Packets/s": "Fwd Pkts/s", "Bwd Packets/s": "Bwd Pkts/s",
    "Fwd Packet Length Max": "Fwd Pkt Len Max", "Fwd Packet Length Min": "Fwd Pkt Len Min",
    "Fwd Packet Length Mean": "Fwd Pkt Len Mean", "Fwd Packet Length Std": "Fwd Pkt Len Std",
    "Bwd Packet Length Max": "Bwd Pkt Len Max", "Bwd Packet Length Min": "Bwd Pkt Len Min",
    "Bwd Packet Length Mean": "Bwd Pkt Len Mean", "Bwd Packet Length Std": "Bwd Pkt Len Std",
    "Min Packet Length": "Pkt Len Min", "Max Packet Length": "Pkt Len Max", "Packet Length Mean": "Pkt Len Mean",
    "Packet Length Std": "Pkt Len Std", "Packet Length Variance": "Pkt Len Var",
    "FIN Flag Count": "FIN Flag Cnt", "SYN Flag Count": "SYN Flag Cnt", "RST Flag Count": "RST Flag Cnt",
    "PSH Flag Count": "PSH Flag Cnt", "ACK Flag Count": "ACK Flag Cnt", "URG Flag Count": "URG Flag Cnt",
    "ECE Flag Count": "ECE Flag Cnt", "Average Packet Size": "Pkt Size Avg", "Avg Fwd Segment Size": "Fwd Seg Size Avg",
    "Avg Bwd Segment Size": "Bwd Seg Size Avg", "Fwd Header Length": "Fwd Header Len", "Bwd Header Length": "Bwd Header Len",
    "Fwd Avg Bytes/Bulk": "Fwd Byts/b Avg", "Fwd Avg Packets/Bulk": "Fwd Pkts/b Avg", "Fwd Avg Bulk Rate": "Fwd Blk Rate Avg",
    "Bwd Avg Bytes/Bulk": "Bwd Byts/b Avg", "Bwd Avg Packets/Bulk": "Bwd Pkts/b Avg", "Bwd Avg Bulk Rate": "Bwd Blk Rate Avg",
    "Subflow Fwd Packets": "Subflow Fwd Pkts", "Subflow Fwd Bytes": "Subflow Fwd Byts",
    "Subflow Bwd Packets": "Subflow Bwd Pkts", "Subflow Bwd Bytes": "Subflow Bwd Byts",
    "Init_Win_bytes_forward": "Init Fwd Win Byts", "Init_Win_bytes_backward": "Init Bwd Win Byts",
    "act_data_pkt_fwd": "Fwd Act Data Pkts", "min_seg_size_forward": "Fwd Seg Size Min",
}


def normalize_columns(df, column_map=None):
    """strip padded names, map known CICFlowMeter aliases and an optional caller mapping {their_name: our_name}
    onto the canonical names. A canonical column already present is never overwritten."""
    mapping = {**COLUMN_ALIASES, **(column_map or {})}
    cols, seen = [], set()
    canon = {str(c).strip() for c in df.columns}
    for c in df.columns:
        n = str(c).strip()
        target = mapping.get(n, n)
        if target != n and (target in canon or target in seen):
            target = n
        seen.add(target)
        cols.append(target)
    out = df.copy(deep=False)
    out.columns = cols
    return out


def training_columns():
    """every raw column the training pipeline reads from a CICFlowMeter CSV."""
    return sorted({c for cols in MODALITIES.values() for c in cols if c not in _PROTO} | {"Protocol", "Dst Port", "Timestamp", "Label"})


def require_columns(df, required, where="input"):
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise DataError(f"{where}: missing {len(missing)} required column(s): {', '.join(missing[:12])}"
                        + (" ..." if len(missing) > 12 else ""))


def validate_flows(df, feature_names, column_map=None):
    """Validate a batch of flow records for scoring.

    Returns (clean_df, rejected) where `rejected` maps the original row position to a reason.
    Raises DataError if a required column is absent from the whole batch (a schema problem, not a bad row).
    Rules: all required values numeric and finite, Flow Duration >= 0, Protocol >= 0, 0 <= Dst Port <= 65535.
    """
    df = normalize_columns(df, column_map)
    required = raw_columns(feature_names)
    require_columns(df, required, "flow batch")
    num = df[required].apply(pd.to_numeric, errors="coerce").astype("float64")
    reason = pd.Series("", index=df.index, dtype=object)

    def flag(mask, text):
        m = mask & (reason == "")
        reason[m] = text

    bad_num = ~np.isfinite(num.to_numpy())
    for j, c in enumerate(required):
        flag(pd.Series(bad_num[:, j], index=df.index), f"non-numeric, missing or infinite value in '{c}'")
    if "Flow Duration" in num:
        flag(num["Flow Duration"] < 0, "negative 'Flow Duration'")
    flag(num["Protocol"] < 0, "negative 'Protocol'")
    flag((num["Dst Port"] < 0) | (num["Dst Port"] > 65535), "'Dst Port' outside 0-65535")
    if ROLE_COLUMN in df:
        r = df[ROLE_COLUMN]
        flag(r.notna() & ~r.isin(ROLE_NAMES), f"unknown role (expected one of {', '.join(ROLE_NAMES)})")
    ok = (reason == "").to_numpy()
    rejected = {int(i): reason.iloc[i] for i in np.flatnonzero(~ok)}
    clean = df.loc[ok].copy()
    clean[required] = num.loc[ok, required].astype("float32").to_numpy()
    return clean, rejected
