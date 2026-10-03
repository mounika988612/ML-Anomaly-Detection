"""Label audit of CSE-CIC-IDS2018 (docs/LABEL_AUDIT.md). Uses the raw labels and timestamps only, never model scores.

    python scripts/label_audit.py

1. window check: benign flow rate inside each attack's [first, last] timestamp vs outside it, the share of those benign flows that
   are one repeated flow shape, and the share going to ephemeral ports (>= 49152, i.e. reverse-direction flows).
2. separability ceiling: share of attack flows whose per-flow feature vector (all CICFlowMeter features used by the model, no
   timestamp / label / context) is identical to a benign flow of the same day or of the training days. No flow-level detector
   can score those above their benign twins.
Writes results_comparison/label_audit_windows.csv and label_audit_identical_to_benign.csv.
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_pipeline.data import load_day            # noqa: E402
from ids_pipeline.features import MODALITIES      # noqa: E402
from ids_pipeline.utils import load_config        # noqa: E402

DAYS = ["Wednesday-14-02-2018", "Thursday-15-02-2018", "Wednesday-21-02-2018", "Thursday-22-02-2018", "Thursday-01-03-2018",
        "Friday-02-03-2018"]
TRAIN = DAYS[:2]
COLS = sorted(({c for v in MODALITIES.values() for c in v} - {"proto_other", "proto_tcp", "proto_udp"}) | {"Dst Port", "Protocol"})
OUT = ROOT / "results_comparison"


def windows(df, day):
    ts, lab = df.ts.to_numpy(), df.Label.to_numpy()
    ben = lab == "Benign"
    span = (ts.max() - ts.min()) / 60
    rows = []
    for a in sorted(set(lab) - {"Benign"}):
        t = ts[lab == a]
        inw = (ts >= t.min()) & (ts <= t.max())
        win = max((t.max() - t.min()) / 60, 1 / 60)
        sub = df[ben & inw]
        r_in, r_out = len(sub) / win, (ben & ~inw).sum() / max(span - win, 1)
        rows.append(dict(day=day, attack=a, attack_flows=int((lab == a).sum()), window_min=round(win, 1),
                         benign_in_window=len(sub), benign_per_min_in=round(r_in, 1), benign_per_min_out=round(r_out, 1),
                         rate_ratio=round(r_in / max(r_out, 1e-9), 1),
                         top_shape_share=round(sub.groupby(["Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts"]).size().max() / len(sub), 3)
                         if len(sub) else 0.0,
                         ephemeral_dport_share=round(float((sub["Dst Port"] >= 49152).mean()), 3) if len(sub) else 0.0))
    return rows


def keys(df):
    return pd.util.hash_pandas_object(df[COLS].round(4), index=False).to_numpy()


def main():
    cfg = load_config(ROOT / "config.yaml")
    win_rows, id_rows, train_keys = [], [], []
    for day in DAYS:
        df = load_day(cfg, day)
        win_rows += windows(df, day)
        k, lab = keys(df), df.Label.to_numpy()
        if day in TRAIN:
            train_keys.append(k[lab == "Benign"])
            continue
        tb = np.unique(np.concatenate(train_keys))
        bd = np.unique(k[lab == "Benign"])
        for a in sorted(set(lab) - {"Benign"}):
            ka = k[lab == a]
            id_rows.append(dict(day=day, attack=a, attack_flows=len(ka), identical_to_benign_same_day=round(float(np.isin(ka, bd).mean()), 4),
                                identical_to_benign_training=round(float(np.isin(ka, tb).mean()), 4)))
        del df
    pd.set_option("display.width", 250)
    w, i = pd.DataFrame(win_rows), pd.DataFrame(id_rows)
    w.to_csv(OUT / "label_audit_windows.csv", index=False)
    i.to_csv(OUT / "label_audit_identical_to_benign.csv", index=False)
    print(w.to_string(index=False), "\n\n", i.to_string(index=False))


if __name__ == "__main__":
    main()
