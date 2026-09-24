"""Basic EDA report for the CICIDS2018 CSV files."""
import argparse
from pathlib import Path

import pandas as pd

CORE_COLUMNS = [
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "Dst Port",
    "Protocol",
]


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
    return summary, label_counts, feature_summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default_data = Path(__file__).resolve().parents[2] / "dataset" / "CICIDS2018"
    default_output = Path(__file__).resolve().parents[2] / "eda"
    parser.add_argument("--data-dir", type=Path, default=default_data)
    parser.add_argument("--output-dir", type=Path, default=default_output)
    args = parser.parse_args()

    files = sorted(args.data_dir.glob("*.csv"))
    if not files:
        raise SystemExit(f"No CSV files found in {args.data_dir}")

    summaries, labels, features = [], [], []
    for path in files:
        print(f"Analysing {path.name} ...")
        summary, label_counts, feature_summary = analyse_file(path)
        summaries.append(summary)
        labels.append(label_counts)
        features.append(feature_summary)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(summaries).to_csv(args.output_dir / "dataset_summary.csv", index=False)
    pd.concat(labels, ignore_index=True).to_csv(args.output_dir / "label_counts.csv", index=False)
    pd.concat(features, ignore_index=True).to_csv(args.output_dir / "core_feature_summary.csv", index=False)

    print(f"\nWrote EDA reports to {args.output_dir}")
    print(pd.DataFrame(summaries).to_string(index=False))


if __name__ == "__main__":
    main()
