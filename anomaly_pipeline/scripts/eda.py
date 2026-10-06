"""Basic EDA report for CSE-CIC-IDS2018, CIC-IDS2017 (Suricata rebuild) and UNSW-NB15.

Each dataset writes dataset_summary.csv (one row per day / file), label_counts.csv, core_feature_summary.csv and
feature_quality.csv (every model feature: missing, infinite, negative, constant).
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "anomaly_pipeline"))

CORE_COLUMNS = [
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "Dst Port",
    "Protocol",
]
# closest equivalents of the CIC-2018 core columns in the other two datasets
CORE_2017 = ["age", "pkts_ts", "pkts_tc", "dst_port", "proto_num"]
CORE_UNSW = ["dur", "spkts", "dpkts", "sbytes", "dbytes"]


def analyse_file(path):
    df = pd.read_csv(path, low_memory=False)
    labels = df["Label"].astype("string").str.strip()
    repeated_headers = int(labels.eq("Label").sum())
    df = df.loc[~labels.eq("Label")].copy()
    labels = labels.loc[df.index]

    missing_cells = int(df.isna().sum().sum())
    rows_with_missing = int(df.isna().any(axis=1).sum())
    duplicate_rows = int(df.duplicated().sum())

    numeric = df[CORE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    invalid_core_values = int(numeric.isna().any(axis=1).sum())
    negative_duration = int((numeric["Flow Duration"] < 0).sum())
    invalid_ports = int(((numeric["Dst Port"] < 0) | (numeric["Dst Port"] > 65535)).sum())
    invalid_protocols = int((numeric["Protocol"] < 0).sum())

    timestamps = pd.to_datetime(
        df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce"
    )
    timestamps = timestamps.where(timestamps.dt.year == 2018)
    attack = labels.ne("Benign")
    summary = {
        "file": path.name,
        "rows_raw": len(pd.read_csv(path, usecols=["Label"], low_memory=False)),
        "rows_clean": len(df),
        "repeated_headers": repeated_headers,
        "benign_rows": int((~attack).sum()),
        "attack_rows": int(attack.sum()),
        "missing_cells": missing_cells,
        "rows_with_missing": rows_with_missing,
        "duplicate_rows": duplicate_rows,
        "invalid_core_rows": invalid_core_values,
        "negative_duration": negative_duration,
        "invalid_ports": invalid_ports,
        "invalid_protocols": invalid_protocols,
        "invalid_timestamps": int(timestamps.isna().sum()),
        "first_timestamp": timestamps.min(),
        "last_timestamp": timestamps.max(),
        "attack_types": "; ".join(sorted(labels[attack].dropna().unique())),
    }

    label_counts = labels.value_counts().rename_axis("label").reset_index(name="rows")
    label_counts.insert(0, "file", path.name)
    feature_summary = numeric.describe().T.reset_index(names="feature")
    feature_summary.insert(0, "file", path.name)
    model_features = df.drop(columns=["Label", "Timestamp"]).apply(pd.to_numeric, errors="coerce")
    return summary, label_counts, feature_summary, feature_quality(path.name, model_features)


def feature_quality(name, X):
    """Per-feature data-quality table for the numeric model features X."""
    v = X.to_numpy(dtype="float64")
    finite = np.isfinite(v)
    q = pd.DataFrame({
        "feature": X.columns,
        "missing": np.isnan(v).sum(axis=0),
        "infinite": np.isinf(v).sum(axis=0),
        "negative": (np.where(finite, v, 0) < 0).sum(axis=0),
        "zero_fraction": (v == 0).mean(axis=0).round(4),
        "n_unique": X.nunique().to_numpy(),
    })
    q["constant"] = q.n_unique <= 1
    q.insert(0, "file", name)
    return q


def conflicting_duplicates(X, labels):
    """Rows whose feature vector also occurs with a different label (irreducible label noise)."""
    key = pd.util.hash_pandas_object(X, index=False)
    n_labels = labels.groupby(key.to_numpy()).transform("nunique")
    return int((n_labels.to_numpy() > 1).sum())


def label_table(name, labels):
    t = labels.value_counts().rename_axis("label").reset_index(name="rows")
    t.insert(0, "file", name)
    return t


def describe(name, numeric):
    t = numeric.describe().T.reset_index(names="feature")
    t.insert(0, "file", name)
    return t


def analyse_cic2017(parquet, interim_dir):
    from ids_pipeline.adapters.suricata2017 import DAYS, MODALITIES

    feats = sum(MODALITIES.values(), [])
    raw_all = pd.read_parquet(parquet, columns=["Flow ID", "Day", "class", "alerted", "pad_zone", "start_utc"])
    summaries, labels, cores, quality = [], [], [], []
    for day in DAYS:
        print(f"Analysing CIC-IDS2017 {day} ...")
        raw = raw_all[raw_all.Day == day]
        df = pd.read_parquet(Path(interim_dir) / f"{day}.v2.parquet")
        if len(df) != len(raw):
            raise SystemExit(f"{day}: interim cache has {len(df)} rows, raw parquet {len(raw)}; rebuild the cache")
        lab = df["Label"].astype("string").str.strip()
        attack = lab.ne("Benign")
        X = df[feats + ["dst_port", "proto_num"]]
        ts = raw["start_utc"]
        summaries.append({
            "file": day,
            "rows_raw": len(raw),
            "rows_clean": len(df),
            "benign_rows": int((~attack).sum()),
            "attack_rows": int(attack.sum()),
            "attack_pct": round(100 * attack.mean(), 3),
            "missing_cells": int(raw.isna().sum().sum() + X.isna().sum().sum()),
            "duplicate_flow_ids": int(raw["Flow ID"].duplicated().sum()),
            "duplicate_feature_rows": int(X.duplicated().sum()),
            "conflicting_duplicates": conflicting_duplicates(X, lab),
            "invalid_core_rows": int((~np.isfinite(df[CORE_2017].to_numpy("float64")).all(axis=1)).sum()),
            "negative_duration": int((df["age"] < 0).sum()),
            "invalid_ports": int(((df["dst_port"] < 0) | (df["dst_port"] > 65535)).sum()),
            "invalid_protocols": int((df["proto_num"] < 0).sum()),
            "invalid_timestamps": int(ts.isna().sum()),
            "first_timestamp_utc": ts.min(),
            "last_timestamp_utc": ts.max(),
            "pad_zone_rows": int(raw["pad_zone"].sum()),
            "suricata_alerted_rows": int(raw["alerted"].sum()),
            "suricata_alerted_attack_rows": int((raw["alerted"].to_numpy() & attack.to_numpy()).sum()),
            "attack_types": "; ".join(sorted(lab[attack].unique())),
        })
        labels.append(label_table(day, lab))
        cores.append(describe(day, df[CORE_2017]))
        quality.append(feature_quality(day, X))
    return summaries, labels, cores, quality


def analyse_unsw(unsw_dir):
    from ids_pipeline.adapters.unsw import _find_file

    meta = ["id", "attack_cat", "label"]
    parts = {}
    summaries, labels, cores, quality = [], [], [], []
    for part in ("train", "test"):
        path = _find_file(unsw_dir, part)
        print(f"Analysing UNSW-NB15 {path.name} ...")
        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip().str.lstrip("﻿")
        cat = df["attack_cat"].astype("string").str.strip().replace({"Normal": "Benign"})
        attack = df["label"].astype(int).eq(1)
        X = df.drop(columns=meta)
        numeric = X.select_dtypes("number")
        parts[part] = X
        summaries.append({
            "file": path.name,
            "rows_raw": len(df),
            "benign_rows": int((~attack).sum()),
            "attack_rows": int(attack.sum()),
            "attack_pct": round(100 * attack.mean(), 3),
            "label_category_mismatch": int((attack != cat.ne("Benign")).sum()),
            "attack_cat_padded": int((df["attack_cat"].astype("string") != df["attack_cat"].astype("string").str.strip()).sum()),
            "missing_cells": int(df.isna().sum().sum()),
            "rows_with_missing": int(df.isna().any(axis=1).sum()),
            "duplicate_rows": int(X.assign(attack_cat=cat).duplicated().sum()),
            "duplicate_feature_rows": int(X.duplicated().sum()),
            "conflicting_duplicates": conflicting_duplicates(X, cat),
            "invalid_core_rows": int(df[CORE_UNSW].apply(pd.to_numeric, errors="coerce").isna().any(axis=1).sum()),
            "negative_duration": int((df["dur"] < 0).sum()),
            "negative_values": int((numeric < 0).to_numpy().sum()),
            "n_protocols": df["proto"].nunique(),
            "n_services": df["service"].nunique(),
            "n_states": df["state"].nunique(),
            "has_timestamps": False,
            "attack_types": "; ".join(sorted(cat[attack].unique())),
        })
        labels.append(label_table(path.name, cat))
        cores.append(describe(path.name, df[CORE_UNSW]))
        quality.append(feature_quality(path.name, numeric))
    # identical feature vectors in both official splits (train/test leakage)
    train_keys = set(pd.util.hash_pandas_object(parts["train"], index=False))
    test_keys = pd.util.hash_pandas_object(parts["test"], index=False)
    summaries[1]["test_rows_seen_in_train"] = int(test_keys.isin(train_keys).sum())
    return summaries, labels, cores, quality


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=["cic2018", "cic2017", "unsw"], default="cic2018")
    parser.add_argument("--data-dir", type=Path, help="CIC-2018 CSV folder or UNSW-NB15 folder")
    parser.add_argument("--suricata-parquet", type=Path, default=ROOT / "external" / "cic2017" / "suricata2017_rebuilt.parquet")
    parser.add_argument("--interim-dir", type=Path, default=ROOT / "anomaly_pipeline" / "work_cic2017_monday" / "interim",
                        help="parsed CIC-IDS2017 days (<Day>.v2.parquet) written by the pipeline")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    out_default = {"cic2018": ROOT / "dataset" / "EDA" / "CICIDS2018", "cic2017": ROOT / "dataset" / "EDA" / "CICIDS2017",
                   "unsw": ROOT / "dataset" / "EDA" / "UNSW_NB15"}
    args.output_dir = args.output_dir or out_default[args.dataset]
    quality = []
    if args.dataset == "cic2018":
        data_dir = args.data_dir or ROOT / "dataset" / "CICIDS2018"
        files = sorted(data_dir.glob("*.csv"))
        if not files:
            raise SystemExit(f"No CSV files found in {data_dir}")
        summaries, labels, features = [], [], []
        for path in files:
            print(f"Analysing {path.name} ...")
            summary, label_counts, feature_summary, file_quality = analyse_file(path)
            summaries.append(summary)
            labels.append(label_counts)
            features.append(feature_summary)
            quality.append(file_quality)
    elif args.dataset == "cic2017":
        summaries, labels, features, quality = analyse_cic2017(args.suricata_parquet, args.interim_dir)
    else:
        summaries, labels, features, quality = analyse_unsw(args.data_dir or ROOT / "dataset" / "UNSW_NB15")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(summaries).to_csv(args.output_dir / "dataset_summary.csv", index=False)
    pd.concat(labels, ignore_index=True).to_csv(args.output_dir / "label_counts.csv", index=False)
    pd.concat(features, ignore_index=True).to_csv(args.output_dir / "core_feature_summary.csv", index=False)
    if quality:
        pd.concat(quality, ignore_index=True).to_csv(args.output_dir / "feature_quality.csv", index=False)

    print(f"\nWrote EDA reports to {args.output_dir}")
    print(pd.DataFrame(summaries).drop(columns="attack_types").T.to_string(header=False))


if __name__ == "__main__":
    main()
