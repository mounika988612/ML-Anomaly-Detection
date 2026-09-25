"""Multi-modal feature space and role assignment for CICFlowMeter flow records.

The CSE-CIC-IDS2018 CSVs only contain flow statistics (no DNS/TLS/HTTP logs), so the
"modalities" are complementary views of a flow. The same abstraction accepts Zeek/Suricata
sources later: add a new key to MODALITIES with the columns of e.g. dns.log or ssl.log.
"""
import numpy as np
import pandas as pd

MODALITIES = {
    "volume_timing": [
        "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
        "Flow Byts/s", "Flow Pkts/s", "Fwd Pkts/s", "Bwd Pkts/s",
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
        "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
        "Active Mean", "Active Std", "Active Max", "Active Min",
        "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    ],
    "packet_size": [
        "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Mean", "Fwd Pkt Len Std",
        "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std",
        "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var",
        "Pkt Size Avg", "Fwd Seg Size Avg", "Bwd Seg Size Avg", "Fwd Seg Size Min", "Down/Up Ratio",
    ],
    "protocol_flags": [
        "proto_tcp", "proto_udp", "proto_other",
        "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
        "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt",
        "URG Flag Cnt", "CWE Flag Count", "ECE Flag Cnt",
        "Fwd Header Len", "Bwd Header Len", "Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Act Data Pkts",
    ],
    "bulk_subflow": [
        "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg",
        "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg",
        "Subflow Fwd Pkts", "Subflow Fwd Byts", "Subflow Bwd Pkts", "Subflow Bwd Byts",
    ],
}

# Optional 5th modality (data.context_features): what the rest of the network does around a flow.
# Computed per day from timestamp, destination port and flow "shape" (protocol + packet/byte counts),
# because this release has no IPs. Targets attacks that look normal one flow at a time but not
# in aggregate: floods (HOIC), beaconing bots, scans (infiltration).
CONTEXT_MODALITY = {
    "temporal_context": [
        "ctx_flows_1s", "ctx_flows_60s",             # overall load
        "ctx_port_flows_1s", "ctx_port_flows_60s",   # load on this service
        "ctx_port_share_60s",                        # this service's share of the load
        "ctx_ports_1s", "ctx_ports_10s",             # distinct destination ports (scanning)
        "ctx_shape_1s", "ctx_shape_60s",             # near-identical flows (floods, bots)
        "ctx_shape_share_60s",                       # repetitiveness of this service's traffic
        "ctx_shape_gap", "ctx_port_gap",             # seconds since the previous identical flow / flow to this port
    ],
}
_SHAPE_COLS = ["Dst Port", "Protocol", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts"]
_MAX_GAP = 3600.0


def _window_count(key, sec, w):
    """flows with the same key in the trailing window [sec-w+1, sec] (timestamps have 1-s resolution)."""
    span = int(sec.max()) + w + 1
    code = key * span + sec
    u, inv, cnt = np.unique(code, return_inverse=True, return_counts=True)
    c = np.cumsum(cnt)
    lo = np.searchsorted(u, u - (w - 1), "left")      # key blocks are `span` apart, so windows never cross keys
    return (c - np.where(lo > 0, c[lo - 1], 0))[inv].astype(np.float32)


def _gap(key, sec):
    """seconds since the previous second in which a flow with the same key occurred (capped)."""
    span = int(sec.max()) + 1
    u, inv = np.unique(key * span + sec, return_inverse=True)
    k, s = u // span, u % span
    g = np.full(len(u), _MAX_GAP)
    same = k[1:] == k[:-1]
    g[1:][same] = np.minimum(s[1:] - s[:-1], _MAX_GAP)[same]
    return g[inv].astype(np.float32)


def add_context_features(df):
    """adds the CONTEXT_MODALITY columns, computed over all flows of `df` (one full capture day,
    attacks included, labels unused). Must run before any sampling, or the counts are diluted."""
    sec = np.floor(df["ts"].to_numpy(np.float64)).astype(np.int64)
    sec -= sec.min()
    port = pd.factorize(df["Dst Port"])[0].astype(np.int64)
    shape = df.groupby(_SHAPE_COLS, sort=False).ngroup().to_numpy(np.int64)
    one = np.zeros(len(df), np.int64)
    out = {
        "ctx_flows_1s": _window_count(one, sec, 1), "ctx_flows_60s": _window_count(one, sec, 60),
        "ctx_port_flows_1s": _window_count(port, sec, 1), "ctx_port_flows_60s": _window_count(port, sec, 60),
        "ctx_shape_1s": _window_count(shape, sec, 1), "ctx_shape_60s": _window_count(shape, sec, 60),
        "ctx_shape_gap": _gap(shape, sec), "ctx_port_gap": _gap(port, sec),
    }
    out["ctx_port_share_60s"] = out["ctx_port_flows_60s"] / out["ctx_flows_60s"]
    out["ctx_shape_share_60s"] = out["ctx_shape_60s"] / out["ctx_port_flows_60s"]
    for w in (1, 10):
        b = pd.Series(sec // w)
        out[f"ctx_ports_{w}s"] = pd.Series(port).groupby(b).transform("nunique").to_numpy(np.float32)
    return df.assign(**out)


# Service roles derived from the destination port. IPs are not present in this release of the
# dataset; on Terma telemetry replace with host role / network zone from asset metadata.
ROLE_NAMES = ["web", "remote_admin", "file_transfer", "name_directory", "mail",
              "database", "other_system", "registered", "ephemeral"]
_ROLE_PORTS = {
    0: [80, 443, 8080, 8443, 8000, 8888],
    1: [22, 23, 3389, 5900],
    2: [20, 21, 69, 137, 138, 139, 445, 2049],
    3: [53, 67, 68, 88, 123, 389, 636, 5353],
    4: [25, 110, 143, 465, 587, 993, 995],
    5: [1433, 1521, 3306, 5432, 6379, 27017],
}
N_ROLES = len(ROLE_NAMES)


def assign_roles(port):
    port = np.asarray(port)
    role = np.full(len(port), 6, dtype=np.int8)
    role[port >= 1024] = 7
    role[port >= 49152] = 8
    for r, ports in _ROLE_PORTS.items():
        role[np.isin(port, ports)] = r
    return role


def _signed_log1p(x):
    return np.sign(x) * np.log1p(np.abs(x))


_PROTO_COLS = ("proto_tcp", "proto_udp", "proto_other")


def _raw_frame(df, needed=None, modalities=MODALITIES):
    """model input columns from a CICFlowMeter frame; `needed` restricts it to the columns a fitted
    feature space actually uses (so serving does not demand columns that were constant in training)."""
    d = pd.DataFrame(index=df.index)
    proto = df["Protocol"]
    d["proto_tcp"] = (proto == 6).astype("float32")
    d["proto_udp"] = (proto == 17).astype("float32")
    d["proto_other"] = (~proto.isin([6, 17])).astype("float32")
    for cols in modalities.values():
        for c in cols:
            if c not in d and (needed is None or c in needed):
                d[c] = df[c].astype("float32")
    return d


def raw_columns(names):
    """CICFlowMeter columns required to build the given feature names (+ destination port for the role)."""
    cols = {"Dst Port"}
    for n in names:
        cols.add("Protocol" if n in _PROTO_COLS else n)
    return sorted(cols)


class FeatureSpace:
    """signed-log1p -> standardise (train-only stats) -> clip; features ordered by modality."""

    def __init__(self, clip=8.0, context=False):
        self.clip = clip
        self.context = context              # add the temporal_context modality (needs add_context_features)

    def _modalities(self):
        return {**MODALITIES, **CONTEXT_MODALITY} if getattr(self, "context", False) else MODALITIES

    def fit(self, df):
        raw = _raw_frame(df, modalities=self._modalities())
        x = _signed_log1p(raw.to_numpy(np.float64))
        std = x.std(0)
        keep = dict(zip(raw.columns, std > 1e-6))       # drop constant columns
        stats = dict(zip(raw.columns, zip(x.mean(0), std)))
        self.names, self.slices, mean, sd = [], {}, [], []
        for m, cols in self._modalities().items():
            start = len(self.names)
            for c in cols:
                if keep[c]:
                    self.names.append(c)
                    mean.append(stats[c][0])
                    sd.append(stats[c][1])
            if len(self.names) > start:
                self.slices[m] = (start, len(self.names))
        self.mean = np.array(mean, np.float32)
        self.std = np.array(sd, np.float32)
        self.modality_of = [m for m, (a, b) in self.slices.items() for _ in range(b - a)]
        return self

    def transform(self, df):
        x = _signed_log1p(_raw_frame(df, set(self.names), self._modalities())[self.names].to_numpy(np.float32))
        x = np.clip((x - self.mean) / self.std, -self.clip, self.clip).astype(np.float32)
        return x, assign_roles(df["Dst Port"].to_numpy())

    def required_columns(self):
        return raw_columns(self.names)

    def get_state(self):
        """plain-data state (JSON-serialisable) so a deployed model needs no pickle."""
        return dict(clip=float(self.clip), names=list(self.names), slices={m: list(v) for m, v in self.slices.items()},
                    mean=[float(v) for v in self.mean], std=[float(v) for v in self.std])

    @classmethod
    def from_state(cls, st):
        fs = cls(st["clip"], context="temporal_context" in st["slices"])
        fs.names = list(st["names"])
        fs.slices = {m: tuple(v) for m, v in st["slices"].items()}
        fs.mean, fs.std = np.array(st["mean"], np.float32), np.array(st["std"], np.float32)
        fs.modality_of = [m for m, (a, b) in fs.slices.items() for _ in range(b - a)]
        return fs

    def subset(self, modalities):
        """column indices and re-based slices for a subset of modalities (ablations)."""
        idx, sl, pos = [], {}, 0
        for m in modalities:
            a, b = self.slices[m]
            idx += list(range(a, b))
            sl[m] = (pos, pos + b - a)
            pos += b - a
        return np.array(idx), sl


class GenericSpace:
    """Feature space for adapter datasets: a DataFrame with numeric columns already grouped into
    modalities (`modalities`: name -> columns) and a `role` column. Same interface as FeatureSpace."""

    def __init__(self, modalities, clip=8.0):
        self.modalities, self.clip = modalities, clip

    def fit(self, df):
        self.names, self.slices, mean, sd = [], {}, [], []
        for m, cols in self.modalities.items():
            start = len(self.names)
            for c in cols:
                if c not in df:
                    continue
                x = _signed_log1p(df[c].to_numpy(np.float64))
                if x.std() > 1e-6:
                    self.names.append(c)
                    mean.append(x.mean())
                    sd.append(x.std())
            if len(self.names) > start:
                self.slices[m] = (start, len(self.names))
        self.mean, self.std = np.array(mean, np.float32), np.array(sd, np.float32)
        self.modality_of = [m for m, (a, b) in self.slices.items() for _ in range(b - a)]
        return self

    def transform(self, df):
        x = _signed_log1p(df[self.names].to_numpy(np.float32))
        x = np.clip((x - self.mean) / self.std, -self.clip, self.clip).astype(np.float32)
        return x, df["role"].to_numpy(np.int8)

    subset = FeatureSpace.subset
