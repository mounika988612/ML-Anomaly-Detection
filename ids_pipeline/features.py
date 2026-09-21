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


def _raw_frame(df, needed=None):
    """model input columns from a CICFlowMeter frame; `needed` restricts it to the columns a fitted
    feature space actually uses (so serving does not demand columns that were constant in training)."""
    d = pd.DataFrame(index=df.index)
    proto = df["Protocol"]
    d["proto_tcp"] = (proto == 6).astype("float32")
    d["proto_udp"] = (proto == 17).astype("float32")
    d["proto_other"] = (~proto.isin([6, 17])).astype("float32")
    for cols in MODALITIES.values():
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

    def __init__(self, clip=8.0):
        self.clip = clip

    def fit(self, df):
        raw = _raw_frame(df)
        x = _signed_log1p(raw.to_numpy(np.float64))
        std = x.std(0)
        keep = dict(zip(raw.columns, std > 1e-6))       # drop constant columns
        stats = dict(zip(raw.columns, zip(x.mean(0), std)))
        self.names, self.slices, mean, sd = [], {}, [], []
        for m, cols in MODALITIES.items():
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
        x = _signed_log1p(_raw_frame(df, set(self.names))[self.names].to_numpy(np.float32))
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
        fs = cls(st["clip"])
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
