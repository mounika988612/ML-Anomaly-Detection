"""Loading, cleaning and chronological splitting of CSE-CIC-IDS2018."""
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

from .features import ROLE_NAMES, FeatureSpace, GenericSpace
from .schema import DataError, require_columns, training_columns
from .utils import get_logger, set_seed

log = get_logger()
T0 = pd.Timestamp("2018-01-01")


def _unwrap_12h(t):
    """CICFlowMeter writes a 12-hour clock without AM/PM (13:51 is stored as 01:51). Captures start
    around 08:00 and hours 06-07 never occur in any file, so hours 01-07 are afternoon."""
    return t + 43200 * (((t % 86400) // 3600) < 8)


def clean_day(csv_path):
    csv_path = Path(csv_path)
    if not csv_path.is_file():
        raise DataError(f"dataset file not found: {csv_path} (set IDS_DATA_DIR or paths.raw_dir)")
    try:
        df = pd.read_csv(csv_path, low_memory=False)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError) as e:
        raise DataError(f"{csv_path.name}: unreadable CSV: {e}") from e
    require_columns(df, training_columns(), csv_path.name)
    n_raw = len(df)
    df = df[df["Label"] != "Label"]                       # header rows repeated inside some files
    n_hdr = n_raw - len(df)
    num = [c for c in df.columns if c not in ("Timestamp", "Label")]
    df[num] = df[num].apply(pd.to_numeric, errors="coerce")
    ts = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    df = df.assign(ts=(ts - T0).dt.total_seconds().where(ts.dt.year == 2018)).drop(columns="Timestamp")  # corrupt 1970 dates -> NaN
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    df = df[(df["Flow Duration"] >= 0) & (df["Protocol"] >= 0)]
    df = df.drop_duplicates()
    df["ts"] = _unwrap_12h(df["ts"].to_numpy())
    df[num] = df[num].astype("float32")
    df["Label"] = df["Label"].str.strip()
    df["attack"] = (df["Label"] != "Benign").astype("int8")
    if df.empty:
        raise DataError(f"{csv_path.name}: no valid rows left after cleaning")
    stats = dict(rows_raw=n_raw, header_rows=n_hdr, rows_clean=len(df),
                 benign=int((df.attack == 0).sum()), attack=int(df.attack.sum()))
    return df.sort_values("ts").reset_index(drop=True), stats


def load_day(cfg, day):
    cache = cfg["paths"]["work_dir"] / "interim" / f"{day}.parquet"
    if cache.exists():
        return pd.read_parquet(cache)
    log.info("cleaning %s", day)
    df, stats = clean_day(cfg["paths"]["raw_dir"] / f"{day}.csv")
    log.info("  %s", stats)
    cache.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(cache)
    return df


def _pack(fs, df):
    x, role = fs.transform(df)
    out = dict(X=x, role=role, y=df["attack"].to_numpy(np.int8),
               label=df["Label"].to_numpy().astype("U40"), ts=df["ts"].to_numpy(np.float64))
    if "sig" in df:                                    # signature-IDS (Suricata) decision per flow
        out["sig"] = df["sig"].to_numpy(np.int8)
    return out


def _adapter(cfg):
    name = cfg["data"].get("dataset", "cicids2018")
    if name == "suricata2017":
        from .adapters import suricata2017 as a
    elif name == "unsw_nb15":
        from .adapters import unsw as a
    else:
        return load_day, lambda: FeatureSpace(cfg["data"]["clip"])
    return (lambda c, day: a.load_day(c, day)), lambda: GenericSpace(a.MODALITIES, cfg["data"]["clip"])


def prepare(cfg):
    d = cfg["data"]
    loader, make_fs = _adapter(cfg)
    set_seed(d["seed"])
    proc = cfg["paths"]["work_dir"] / "processed"
    proc.mkdir(parents=True, exist_ok=True)

    # validation = latest slice of benign traffic of EACH training day (representative of all days,
    # still strictly later than the training portion of that day)
    tb, vb, sp = [], [], []
    for day in d["train_days"]:
        df = loader(cfg, day)
        ben = df[df.attack == 0]
        cutoff = ben["ts"].iloc[int(len(ben) * (1 - d["val_fraction"]))]
        tb.append(ben[ben.ts < cutoff])
        vb.append(ben[ben.ts >= cutoff])
        sp.append(df[df.ts < cutoff])
    train_b, val_b, sup = pd.concat(tb), pd.concat(vb), pd.concat(sp)
    log.info("train benign %d | val benign %d | supervised pool %d (attacks %d)",
             len(train_b), len(val_b), len(sup), int(sup.attack.sum()))

    fs = make_fs().fit(train_b)
    log.info("features: %d in %s", len(fs.names), {m: b - a for m, (a, b) in fs.slices.items()})
    with open(proc / "feature_space.pkl", "wb") as f:
        pickle.dump(fs, f)

    rs = np.random.RandomState(d["seed"])

    def cap(df, n):
        return df if len(df) <= n else df.iloc[np.sort(rs.choice(len(df), n, replace=False))]

    np.savez(proc / "train.npz", **_pack(fs, cap(train_b, d["max_train_rows"])))
    np.savez(proc / "val.npz", **_pack(fs, val_b))
    np.savez(proc / "sup.npz", **_pack(fs, cap(sup, d["max_sup_rows"])))
    rows = []
    for day in d["test_days"]:
        df = loader(cfg, day)
        sub = cap(df, d["max_test_rows_per_day"])
        np.savez(proc / f"test_{day}.npz", **_pack(fs, sub))
        rows.append(dict(day=day, flows=len(df), sampled=len(sub), attacks=int(sub.attack.sum()),
                         attack_types=", ".join(sorted(set(sub.Label) - {"Benign"}))))
    summary = pd.DataFrame(rows)
    summary.to_csv(cfg["paths"]["results_dir"] / "test_set_summary.csv", index=False)
    log.info("\n%s", summary.to_string(index=False))
    role_counts = np.bincount(np.load(proc / "val.npz")["role"], minlength=len(ROLE_NAMES))
    log.info("val flows per role: %s", dict(zip(ROLE_NAMES, role_counts)))


def load_split(cfg, name):
    z = np.load(cfg["paths"]["work_dir"] / "processed" / f"{name}.npz")
    return {k: z[k] for k in z.files}


def load_feature_space(cfg):
    with open(cfg["paths"]["work_dir"] / "processed" / "feature_space.pkl", "rb") as f:
        return pickle.load(f)
