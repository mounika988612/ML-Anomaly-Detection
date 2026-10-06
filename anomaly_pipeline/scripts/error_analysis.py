"""X4 (results_comparison/PREREGISTRATION.md): error and failure analysis on CIC-IDS2017 P1, POST HOC and descriptive.

    python scripts/error_analysis.py

Saved score files only, fixed threshold (evaluate.collect_scores, adapt=False). Methods: ssl_mm_role_knn, ae_concat_knnrole, iforest
(seeds 42 / 1 / 2), ssl_mm_ensemble (one file: already the mean over the three seeds) and suricata_signature. Flow metadata (packets,
protocol, destination port, time) from the interim cache, which holds the test rows in the order of the processed split (checked).
Output: results_comparison/error_analysis/.
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_pipeline.data import load_split                       # noqa: E402
from ids_pipeline.evaluate import collect_scores                # noqa: E402
from ids_pipeline.features import ROLE_NAMES                    # noqa: E402
from ids_pipeline.utils import interim_path, load_config        # noqa: E402

OUT = ROOT / "results_comparison" / "error_analysis"
DIRS = {42: "results_cic2017_monday", 1: "results_cic2017_monday_seed1", 2: "results_cic2017_monday_seed2"}
SEEDED = ["ssl_mm_role_knn", "ae_concat_knnrole", "iforest"]
SIZE_BINS, SIZE_NAMES = [0, 2, 5, 20, 100, np.inf], ["1-2", "3-5", "6-20", "21-100", ">100"]
PROTO = {6: "tcp", 17: "udp", 1: "icmp"}


def scores_of(cfg, results_dir):
    cfg = dict(cfg, paths=dict(cfg["paths"], results_dir=ROOT / results_dir))
    return collect_scores(cfg, False)


def benign_flags(cfg, X, role, y):
    """exact: model input (features + role) occurs among benign training-period rows; near (attack rows only): Euclidean
    distance < 0.1 to the nearest of 50,000 benign training rows (as X2 L3 / L4)."""
    tr, va = load_split(cfg, "train"), load_split(cfg, "val")
    Xb, rb = np.concatenate([tr["X"], va["X"]]), np.concatenate([tr["role"], va["role"]])
    h = lambda A, r: pd.util.hash_pandas_object(pd.DataFrame(A).assign(role=r), index=False)
    exact = h(X, role).isin(set(h(Xb, rb))).to_numpy()
    ref = torch.from_numpy(Xb[np.random.RandomState(0).choice(len(Xb), 50_000, replace=False)])
    near = exact.copy()
    att = np.flatnonzero(y == 1)
    for i in range(0, len(att), 8192):
        ix = att[i:i + 8192]
        near[ix] |= torch.cdist(torch.from_numpy(X[ix]), ref).min(1).values.numpy() < 0.1
    return exact, near


def main():
    cfg = load_config(ROOT / "config_cic2017_monday.yaml")
    days = cfg["data"]["test_days"]
    parts = [load_split(cfg, f"test_{d}") for d in days]
    X, role = np.concatenate([p["X"] for p in parts]), np.concatenate([p["role"] for p in parts])
    meta = pd.concat([pd.read_parquet(interim_path(cfg, d), columns=["pkts_ts", "pkts_tc", "proto_num", "dst_port", "ts", "Label",
                                                                  "reason_shutdown"])
                      for d in days], ignore_index=True)
    dec, val_p = {}, {}
    t = None
    for seed, d in DIRS.items():
        sc, tt = scores_of(cfg, d)
        t = tt if t is None else t
        assert np.array_equal(t["y"], tt["y"])
        for m in SEEDED + (["suricata_signature"] if seed == 42 else []):
            dec[(m, seed)] = sc[m]["s"] > sc[m]["thr"]
            z = np.load(ROOT / d / "scores" / f"{m}.npz")
            val_p[(m, seed)] = 1 - np.searchsorted(np.sort(z["val"]), sc[m]["s"], "right") / len(z["val"])   # upper-tail p vs benign val
    sc, tt = scores_of(cfg, "results_experts_cic2017_monday")
    assert np.array_equal(t["y"], tt["y"])
    dec[("ssl_mm_ensemble", 0)] = sc["ssl_mm_ensemble"]["s"] > sc["ssl_mm_ensemble"]["thr"]
    y, label = t["y"], t["label"]
    assert (meta["Label"].to_numpy() == label).all(), "interim rows are not in the order of the processed split"

    exact, near = benign_flags(cfg, X, role, y)
    pk = meta.pkts_ts + meta.pkts_tc
    fac = pd.DataFrame(dict(role=np.array(ROLE_NAMES)[role], protocol=meta.proto_num.map(PROTO).fillna("other").to_numpy(),
                            size_pkts=pd.cut(pk, SIZE_BINS, labels=SIZE_NAMES).astype(str).to_numpy(),
                            hour=(meta.ts % 86400 // 3600).astype(int).to_numpy(), day=t["day_of"],
                            dst_port=meta.dst_port.to_numpy(), identical_to_benign_train=exact, near_benign_train=near))
    OUT.mkdir(parents=True, exist_ok=True)

    # 1 per-attack recall and the share of misses that are (near-)identical to benign training flows
    rows = []
    for (m, s), p in dec.items():
        for lab in sorted(set(label) - {"Benign"}):
            a = label == lab
            fn = a & ~p
            rows.append(dict(method=m, seed=s, attack=lab, flows=int(a.sum()), recall=float(p[a].mean()), fn=int(fn.sum()),
                             fn_identical_to_benign=float(exact[fn].mean()) if fn.any() else np.nan,
                             fn_near_benign=float(near[fn].mean()) if fn.any() else np.nan,
                             near_benign_share_of_attack=float(near[a].mean())))
    per_attack = pd.DataFrame(rows)
    per_attack.round(4).to_csv(OUT / "per_attack.csv", index=False)

    # 2 false negatives by factor; 3 false positives by factor
    fn_rows, fp_rows = [], []
    for (m, s), p in dec.items():
        att, ben = y == 1, y == 0
        for f in ("role", "protocol", "size_pkts", "near_benign_train"):
            g = pd.DataFrame(dict(level=fac[f][att].to_numpy(), miss=~p[att], lab=label[att]))
            for lv, gg in g.groupby("level"):
                fn_rows.append(dict(method=m, seed=s, factor=f, level=lv, attack_flows=len(gg), miss_rate=gg.miss.mean(),
                                    attack_types=", ".join(gg.lab.value_counts().index[:3])))
        fp_all = int(p[ben].sum())
        for f in ("role", "protocol", "size_pkts", "hour", "day", "identical_to_benign_train", "dst_port"):
            g = pd.DataFrame(dict(level=fac[f][ben].to_numpy(), fp=p[ben]))
            agg = g.groupby("level").fp.agg(["size", "sum"]).reset_index()
            if f == "dst_port":
                agg = agg.sort_values("sum", ascending=False).head(15)
            for r in agg.itertuples():
                fp_rows.append(dict(method=m, seed=s, factor=f, level=r.level, benign_flows=r.size, fp=int(r.sum),
                                    fp_rate=r.sum / r.size, share_of_fp=r.sum / max(fp_all, 1)))
    pd.DataFrame(fn_rows).round(4).to_csv(OUT / "fn_by_factor.csv", index=False)
    pd.DataFrame(fp_rows).round(4).to_csv(OUT / "fp_by_factor.csv", index=False)

    # 4 complementarity (seed 42 + ensemble + Suricata)
    main_m = [(m, 42) for m in SEEDED] + [("ssl_mm_ensemble", 0), ("suricata_signature", 42)]
    stack = np.stack([dec[k] for k in main_m], 1)
    comp = []
    for lab in sorted(set(label) - {"Benign"}):
        a = label == lab
        st = stack[a]
        r = dict(attack=lab, flows=int(a.sum()), caught_by_any=float(st.any(1).mean()), caught_by_all=float(st.all(1).mean()),
                 missed_by_all=float((~st.any(1)).mean()), missed_by_all_near_benign=float(near[a][~st.any(1)].mean()) if (~st.any(1)).any() else np.nan)
        for j, (m, _) in enumerate(main_m):
            r[f"only_{m}"] = float((st[:, j] & (st.sum(1) == 1)).mean())
        comp.append(r)
    comp = pd.DataFrame(comp)
    comp.round(4).to_csv(OUT / "complementarity.csv", index=False)

    # 5 seed disagreement
    flips = []
    for m in SEEDED:
        D = np.stack([dec[(m, s)] for s in DIRS], 1)
        P = np.stack([val_p[(m, s)] for s in DIRS], 1)
        flip = D.any(1) & ~D.all(1)
        for lab in sorted(set(label)):
            a = label == lab
            flips.append(dict(method=m, label=lab, flows=int(a.sum()), flip_share=float(flip[a].mean()),
                              **{f"recall_or_fpr_seed{s}": float(D[a, i].mean()) for i, s in enumerate(DIRS)},
                              median_val_p_of_flips=float(np.median(P[a & flip])) if (a & flip).any() else np.nan))
    pd.DataFrame(flips).round(4).to_csv(OUT / "seed_flips.csv", index=False)

    # 6 near misses: false negatives just below the threshold (validation upper-tail p in (0.01, 0.05])
    near_miss = []
    for m in SEEDED:
        for s in DIRS:
            p, pv = dec[(m, s)], val_p[(m, s)]
            for lab in sorted(set(label) - {"Benign"}):
                fn = (label == lab) & ~p
                if fn.any():
                    near_miss.append(dict(method=m, seed=s, attack=lab, fn=int(fn.sum()), share_p_le_0_05=float((pv[fn] <= 0.05).mean()),
                                          share_p_gt_0_5=float((pv[fn] > 0.5).mean()), median_p=float(np.median(pv[fn]))))
    pd.DataFrame(near_miss).round(4).to_csv(OUT / "near_misses.csv", index=False)

    # 6b false positives on flows Suricata flushed when the capture ended (flow_reason = shutdown): a capture artefact
    sd = meta.reason_shutdown.to_numpy() == 1
    ben = y == 0
    rows = []
    for (m, s), p in dec.items():
        fp = p & ben
        rows.append(dict(method=m, seed=s, fp=int(fp.sum()), fp_shutdown_share=round(float(sd[fp].mean()), 3),
                         fpr_shutdown=round(float(p[ben & sd].mean()), 3), fpr_other=round(float(p[ben & ~sd].mean()), 4)))
    pd.DataFrame(rows).to_csv(OUT / "fp_shutdown_flows.csv", index=False)

    # 7 which features deviate in each outcome group (ssl_mm_role_knn, seed 42); X is standardised on benign training data
    from ids_pipeline.data import load_feature_space
    names = np.array(load_feature_space(cfg).names)
    p = dec[("ssl_mm_role_knn", 42)]
    groups = dict(TP=(y == 1) & p, FN=(y == 1) & ~p, FP=(y == 0) & p, TN=(y == 0) & ~p)
    rs = np.random.RandomState(0)
    med = {}
    for g, mask in groups.items():
        ix = np.flatnonzero(mask)
        ix = rs.choice(ix, min(20_000, len(ix)), replace=False)
        med[g] = np.median(np.abs(X[ix]), 0)
    dev = pd.DataFrame(med, index=names)
    dev["FP_minus_TN"], dev["FN_minus_TP"] = dev.FP - dev.TN, dev.FN - dev.TP
    dev.round(3).to_csv(OUT / "feature_deviation_ssl_mm_role_knn.csv")

    pd.set_option("display.width", 250)
    print(per_attack.pivot_table(index="attack", columns="method", values="recall", aggfunc="mean").round(3).to_string())
    print(comp[["attack", "flows", "caught_by_any", "missed_by_all", "missed_by_all_near_benign"]].round(3).to_string(index=False))
    print(pd.DataFrame(flips).query("method == 'ssl_mm_role_knn'").round(3).to_string(index=False))
    print(dev.sort_values("FP_minus_TN", ascending=False).head(10).round(2).to_string())


if __name__ == "__main__":
    main()
