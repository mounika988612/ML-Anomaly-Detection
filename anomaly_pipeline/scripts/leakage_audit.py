"""X2 (results_comparison/PREREGISTRATION.md): leakage and data-integrity audit, POST HOC and descriptive.

    python scripts/leakage_audit.py                       # all three protocols
    python scripts/leakage_audit.py --protocols unsw

Each protocol's split is rebuilt in memory with the pipeline's own loader, label exclusions, train/validation cut and feature
space, so every check is on what the models see (for CIC-IDS2017 P1 the rebuild is checked against the cached processed/*.npz).
Nothing is written to the pipeline's work or results folders except through the loaders' own interim cache, which is redirected
to --cache-dir. Output: results_comparison/leakage_audit/L*.csv (write-up: docs/LEAKAGE_AUDIT.md).
"""
import argparse
import gc
import os
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
from sklearn.neighbors import NearestNeighbors

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PROTOCOLS = {
    "cic2017_p1": "config_cic2017_monday.yaml",
    "cic2018_3day_clean": "config_multiday_context_clean.yaml",
    "unsw": "config_unsw.yaml",
}
# exact names that would be identifiers or label / IDS-decision leaks if they were model inputs
IDENTIFIERS = {"Flow ID", "Src IP", "Dst IP", "Src Port", "Dst Port", "Timestamp", "ts", "id", "src_ip", "dst_ip",
               "src_port", "dst_port", "start", "start_utc", "stcpb", "dtcpb"}
LABEL_LIKE = {"Label", "label", "attack", "attack_cat", "class", "truth", "sig", "alerted", "rule", "n_engine_alerts",
              "event_type_alert", "pad_zone"}
NN_REF, NN_QUERY, NEAR = 200_000, 5_000, 0.1


def auc(y, s):
    a = roc_auc_score(y, s)
    return max(a, 1 - a)


def row_hash(X, role):
    return pd.util.hash_pandas_object(pd.DataFrame(X).assign(role=role), index=False).to_numpy()


class Protocol:
    """train / validation / test frames of one config, built exactly as data.prepare does (without writing anything)."""

    def __init__(self, name, cache_dir):
        from ids_pipeline.utils import load_config
        if name != "cic2017_p1":                    # P1 reads its existing interim cache; the others cache in cache_dir
            os.environ["IDS_WORK_DIR"] = str(Path(cache_dir) / name)
        os.environ["IDS_RESULTS_DIR"] = str(Path(cache_dir) / name / "results")
        self.cfg = load_config(ROOT / PROTOCOLS[name])
        os.environ.pop("IDS_WORK_DIR", None)
        os.environ.pop("IDS_RESULTS_DIR", None)
        self.name, self.d = name, self.cfg["data"]
        self.dataset = self.d.get("dataset", "cicids2018")

    def load(self, day):
        from ids_pipeline import data
        loader, _ = data._adapter(self.cfg)
        df = loader(self.cfg, day)
        if self.dataset == "suricata2017":
            df = self._attach_2017_ids(df, day)
        elif self.dataset == "unsw_nb15":
            df = self._attach_unsw_ids(df, day)
        return data.drop_label_errors(df, day, self.d.get("label_exclusions"))

    def _attach_2017_ids(self, df, day):
        raw = pd.read_parquet(self.d["suricata_parquet"], columns=["Flow ID", "src_ip", "dst_ip", "class", "start", "Day"],
                              filters=[("Day", "==", day)]).reset_index(drop=True)
        hms = raw["start"].str.split(":", expand=True).astype(float)
        order = np.argsort((hms[0] * 3600 + hms[1] * 60 + hms[2]).to_numpy(), kind="stable")   # adapter's stable ts sort
        raw = raw.iloc[order].reset_index(drop=True)
        lab = raw["class"].str.strip().replace({"BENIGN": "Benign"})
        if len(raw) != len(df) or not (lab.to_numpy() == df["Label"].to_numpy()).all():
            raise SystemExit(f"{day}: raw identifiers do not align with the interim cache")
        return df.assign(flow_id=raw["Flow ID"].to_numpy(), src_ip=raw["src_ip"].to_numpy(), dst_ip=raw["dst_ip"].to_numpy())

    def _attach_unsw_ids(self, df, day):
        from ids_pipeline.adapters.unsw import _find_file
        raw = pd.read_csv(_find_file(self.d["unsw_dir"], day), usecols=["id", "proto", "service", "state", "attack_cat"])
        order = np.argsort(np.random.RandomState(self.d["seed"]).permutation(len(raw)))       # adapter's seeded shuffle
        raw = raw.iloc[order].reset_index(drop=True)
        if not (raw["attack_cat"].replace({"Normal": "Benign"}).to_numpy() == df["Label"].to_numpy()).all():
            raise SystemExit(f"UNSW {day}: raw identifiers do not align with the adapter output")
        return df.assign(row_id=raw["id"].to_numpy(), proto=raw["proto"].to_numpy(), service=raw["service"].to_numpy(),
                         state=raw["state"].to_numpy())

    def build_train(self):
        """benign training rows, benign validation rows and the labelled pool (data.prepare); feature space fitted on train."""
        from ids_pipeline import data
        _, make_fs = data._adapter(self.cfg)
        tb, vb, sp, rows = [], [], [], []
        for day in self.d["train_days"]:
            df = self.load(day)
            ben = df[df.attack == 0]
            cutoff = ben["ts"].iloc[int(len(ben) * (1 - self.d["val_fraction"]))]
            t, v = ben[ben.ts < cutoff], ben[ben.ts >= cutoff]
            tb.append(t)
            vb.append(v)
            sp.append(df[df.ts < cutoff])
            for split, part in (("train_benign", t), ("val_benign", v), ("sup_pool", df[df.ts < cutoff])):
                rows.append(dict(protocol=self.name, split=split, day=day, rows=len(part), attacks=int(part.attack.sum()),
                                 ts_min=part.ts.min(), ts_max=part.ts.max()))
            del df
        self.train_b, self.val_b, self.sup = pd.concat(tb), pd.concat(vb), pd.concat(sp)
        self.fs = make_fs().fit(self.train_b)
        return rows


def split_rows(p):
    rows = p.build_train()
    for day in p.d["test_days"]:
        df = p.load(day)
        rows.append(dict(protocol=p.name, split="test", day=day, rows=len(df), attacks=int(df.attack.sum()),
                         ts_min=df.ts.min(), ts_max=df.ts.max()))
    t = pd.DataFrame(rows)
    train_max = t.loc[t.split != "test", "ts_max"].max()
    t["after_all_training"] = np.where(t.split == "test", t.ts_min > train_max, np.nan)
    return t


def check_preprocessing(p):
    """L2 (P1 only): refitted feature space and transformed test rows equal the shipped processed split."""
    from ids_pipeline.data import load_feature_space
    shipped = load_feature_space(p.cfg)
    out = dict(protocol=p.name, same_feature_names=list(shipped.names) == list(p.fs.names),
               max_abs_mean_diff=float(np.abs(shipped.mean - p.fs.mean).max()),
               max_abs_std_diff=float(np.abs(shipped.std - p.fs.std).max()))
    proc = p.cfg["paths"]["work_dir"] / "processed"
    for day in p.d["test_days"]:
        z = np.load(proc / f"test_{day}.npz")
        X, role = p.fs.transform(p.load(day))
        out[f"test_{day}_identical"] = bool(np.array_equal(z["X"], X) and np.array_equal(z["role"], role))
    return out


def audit(p, out_rows):
    fs = p.fs
    Xb, rb = fs.transform(pd.concat([p.train_b, p.val_b]))
    benign_keys = set(row_hash(Xb, rb))
    Xs, rs_ = fs.transform(p.sup)
    pool_keys = set(row_hash(Xs, rs_))
    rng = np.random.RandomState(0)
    ref = Xb[rng.choice(len(Xb), min(NN_REF, len(Xb)), replace=False)]
    nn = NearestNeighbors(n_neighbors=1, algorithm="brute", n_jobs=-1).fit(ref)
    del Xs, rs_
    gc.collect()

    feats = list(fs.names)
    out_rows["L5"].append(dict(protocol=p.name, n_features=len(feats),
                               identifier_features="; ".join(sorted(set(feats) & IDENTIFIERS)) or "none",
                               label_like_features="; ".join(sorted(set(feats) & LABEL_LIKE)) or "none",
                               port_named_features="; ".join(f for f in feats if "port" in f.lower()) or "none",
                               role_from="destination port (service role, by design)" if p.dataset != "unsw_nb15" else "service field"))

    tests = []
    for day in p.d["test_days"]:
        df = p.load(day)
        X, role = fs.transform(df)
        keys = row_hash(X, role)
        lab = df["Label"].to_numpy()
        # benign test rows of the same day, for "attack row identical to a benign row" (irreducible at flow level)
        benign_test_keys = set(keys[lab == "Benign"])
        dup = pd.DataFrame(dict(label=lab, in_benign_period=pd.Series(keys).isin(benign_keys).to_numpy(),
                                in_labelled_pool=pd.Series(keys).isin(pool_keys).to_numpy(),
                                identical_to_benign_test=pd.Series(keys).isin(benign_test_keys).to_numpy()))
        g = dup.groupby("label").agg(rows=("label", "size"), in_benign_period=("in_benign_period", "mean"),
                                     in_labelled_pool=("in_labelled_pool", "mean"),
                                     identical_to_benign_test=("identical_to_benign_test", "mean")).reset_index()
        g.loc[g.label == "Benign", "identical_to_benign_test"] = np.nan
        g.insert(0, "day", day)
        g.insert(0, "protocol", p.name)
        out_rows["L3"].append(g)

        for label in np.unique(lab):                                            # L4 near duplicates
            idx = np.flatnonzero(lab == label)
            idx = rng.choice(idx, min(NN_QUERY, len(idx)), replace=False)
            dist = nn.kneighbors(X[idx], return_distance=True)[0][:, 0]
            out_rows["L4"].append(dict(protocol=p.name, day=day, label=label, sampled=len(idx), exact=float((dist == 0).mean()),
                                       below_0_1=float((dist < NEAR).mean()), median_dist=float(np.median(dist))))

        keep = dict(X=X, role=role, y=df["attack"].to_numpy(), label=lab, ts=df["ts"].to_numpy())
        for c in ("flow_id", "src_ip", "dst_ip", "row_id", "proto", "service", "state", "Dst Port", "dst_port", "Protocol"):
            if c in df:
                keep[c] = df[c].to_numpy()
        if p.dataset == "cicids2018" and "ctx_ports_10s" in df:
            out_rows["L9"].append(context_future_check(p.name, day, df))
        tests.append(keep)
        del df
        gc.collect()

    T = {k: np.concatenate([t[k] for t in tests]) for k in tests[0]}
    del tests
    y = T["y"]

    # L6 identifier shortcuts (in-sample target encoding = optimistic upper bound of what the identifier alone reveals)
    keys = {"role": T["role"], "minute_of_day": np.floor(T["ts"] % 86400 / 60) if p.dataset != "unsw_nb15" else None}
    for c in ("flow_id", "src_ip", "dst_ip", "Dst Port", "dst_port", "Protocol", "proto", "service", "state"):
        if c in T:
            keys[c] = T[c]
    for k, v in keys.items():
        if v is None:
            continue
        rate = pd.Series(y).groupby(pd.Series(v)).transform("mean").to_numpy()
        out_rows["L6"].append(dict(protocol=p.name, identifier=k, used_as_feature=k in feats or (k == "role"),
                                   n_values=int(pd.Series(v).nunique()), target_encoding_auc=auc(y, rate)))
    if "row_id" in T:
        out_rows["L6"].append(dict(protocol=p.name, identifier="row id (raw value)", used_as_feature=False,
                                   n_values=int(len(np.unique(T["row_id"]))), target_encoding_auc=auc(y, T["row_id"])))

    # L7 session / flow overlap with the training days (P1 has Flow IDs)
    if "flow_id" in T:
        train_ids = set(pd.concat([p.load(d)["flow_id"] for d in p.d["train_days"]]))
        ov = pd.DataFrame(dict(label=T["label"], in_training_day=pd.Series(T["flow_id"]).isin(train_ids).to_numpy()))
        g = ov.groupby("label").agg(rows=("label", "size"), flow_id_seen_in_training=("in_training_day", "mean")).reset_index()
        g.insert(0, "protocol", p.name)
        out_rows["L7"].append(g)

    # L8 single-feature artefacts: pooled and per attack type (vs a benign sample)
    sample = rng.choice(len(y), min(300_000, len(y)), replace=False)
    ben = np.flatnonzero(y == 0)
    ben = rng.choice(ben, min(50_000, len(ben)), replace=False)
    for label in ["(all attacks)"] + sorted(set(T["label"]) - {"Benign"}):
        if label == "(all attacks)":
            idx, yy = sample, y[sample]
        else:
            att = np.flatnonzero(T["label"] == label)
            idx = np.concatenate([ben, att])
            yy = np.r_[np.zeros(len(ben)), np.ones(len(att))]
        if yy.min() == yy.max():
            continue
        a = np.array([auc(yy, T["X"][idx, j]) for j in range(len(feats))])
        order = np.argsort(-a)
        out_rows["L8"].append(dict(protocol=p.name, attack=label, attack_rows=int(yy.sum()), best_feature=feats[order[0]],
                                   best_auc=float(a[order[0]]), second_feature=feats[order[1]], second_auc=float(a[order[1]]),
                                   n_features_auc_ge_0_95=int((a >= 0.95).sum()),
                                   features_auc_ge_0_95="; ".join(feats[j] for j in order if a[j] >= 0.95)))


def context_future_check(name, day, df):
    """L9: ctx_ports_10s counts distinct ports in the fixed 10-s bucket of the flow, which includes up to 9 s of later flows.
    Compare it with the strictly trailing count over [t-9, t] (same 1-s resolution)."""
    sec = np.floor(df["ts"].to_numpy(np.float64)).astype(np.int64)
    sec -= sec.min()
    port = pd.factorize(df["Dst Port"])[0].astype(np.int64)
    pairs = np.unique(np.stack([port, sec], 1), axis=0)                 # sorted by port, then second
    start, end = pairs[:, 1], pairs[:, 1] + 9                            # second s is covered by an occurrence in [s-9, s]
    same = np.r_[False, pairs[1:, 0] == pairs[:-1, 0]]
    new = ~same | (start > np.r_[-10, end[:-1]] + 1)                     # merge overlapping cover intervals per port
    grp = np.cumsum(new) - 1
    ms, me = start[new], pd.Series(end).groupby(grp).max().to_numpy()
    diff = np.zeros(sec.max() + 12, np.int64)
    np.add.at(diff, ms, 1)
    np.add.at(diff, me + 1, -1)
    trailing = np.cumsum(diff)[sec].astype(np.float32)
    bucket = df["ctx_ports_10s"].to_numpy(np.float32)
    y = df["attack"].to_numpy()
    out = dict(protocol=name, day=day, rows=len(df), share_bucket_differs=float((bucket != trailing).mean()),
               spearman=float(pd.Series(bucket).corr(pd.Series(trailing), method="spearman")))
    if 0 < y.sum() < len(y):
        out.update(auc_bucket=auc(y, bucket), auc_trailing=auc(y, trailing))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--protocols", nargs="+", default=list(PROTOCOLS), choices=list(PROTOCOLS))
    ap.add_argument("--cache-dir", type=Path, default=Path(tempfile.gettempdir()) / "ids_leakage_cache")
    ap.add_argument("--out", type=Path, default=ROOT / "results_comparison" / "leakage_audit")
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    rows = {k: [] for k in ("L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9")}
    for name in a.protocols:
        print(f"=== {name}", flush=True)
        p = Protocol(name, a.cache_dir)
        rows["L1"].append(split_rows(p))
        if name == "cic2017_p1":
            rows["L2"].append(check_preprocessing(p))
        audit(p, rows)
        del p
        gc.collect()
    for k, v in rows.items():
        if not v:
            continue
        df = pd.concat(v, ignore_index=True) if isinstance(v[0], pd.DataFrame) else pd.DataFrame(v)
        suffix = "" if len(a.protocols) == len(PROTOCOLS) else "_" + "_".join(a.protocols)
        df.to_csv(a.out / f"{k}{suffix}.csv", index=False)
        print(f"\n--- {k}\n{df.to_string(index=False, max_colwidth=70)}", flush=True)


if __name__ == "__main__":
    main()
