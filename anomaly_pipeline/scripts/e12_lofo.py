"""E12 (results_comparison/PREREGISTRATION.md): leave-one-attack-family-out evaluation of the supervised RF on CIC-IDS2017.

    python scripts/e12_lofo.py

For each attack family F: `rf_unseen` is trained on Monday benign + the other families' attacks, `rf_seen` additionally on the earlier
half (per attack type, by start time) of F; both and the saved SSL scores (tuned E11 and default E7 `ssl_mm_role_knn`) are evaluated on
the same rows: every Tue-Fri benign flow + the later half of F. Seeds 42 / 1 / 2; 10-minute block bootstrap as scripts/clean_eval.py.
Output: results_comparison/E12/.
"""
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from clean_eval import Ranked                           # noqa: E402
from ids_pipeline.baselines import SupervisedRF         # noqa: E402
from ids_pipeline.data import load_split                # noqa: E402
from ids_pipeline.utils import get_logger, load_config  # noqa: E402

log = get_logger()
OUT = ROOT / "results_comparison" / "E12"
FAMILIES = {
    "DoS": ["DoS Hulk", "DoS GoldenEye", "DoS Slowloris", "DoS Slowhttptest"],
    "DDoS": ["DDoS"],
    "Brute force": ["FTP-Patator", "SSH-Patator"],
    "Web": ["Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - SQL Injection"],
    "Scan": ["Portscan", "Infiltration - Portscan"],
    "Botnet": ["Botnet"],
}
SEEDS = [42, 1, 2]
CAP, FPR, BOOT, BLOCK = 50_000, 0.01, 500, 600
CACHE = ROOT / "work_cic2017_monday" / "e12_cache"           # RF test scores (statistics can be redone without refitting)
SSL = {"ssl_tuned": "results_e11_cic2017_monday", "ssl_default": "results_cic2017_monday"}


def seed_dir(base, seed):
    return ROOT / (base if seed == 42 else f"{base}_seed{seed}") / "scores" / "ssl_mm_role_knn.npz"


def main():
    cfg = load_config(ROOT / "config_cic2017_monday.yaml")
    days = cfg["data"]["test_days"]
    tr, va = load_split(cfg, "train"), load_split(cfg, "val")
    parts = [load_split(cfg, f"test_{d}") for d in days]
    X = np.concatenate([p["X"] for p in parts])
    y = np.concatenate([p["y"] for p in parts])
    label = np.concatenate([p["label"] for p in parts])
    ts = np.concatenate([p["ts"] for p in parts])
    day_of = np.concatenate([[d] * len(p["y"]) for d, p in zip(days, parts)])
    del parts

    ssl = {}
    for name, base in SSL.items():
        for seed in SEEDS:
            z = np.load(seed_dir(base, seed))
            assert np.array_equal(np.concatenate([z[f"y_{d}"] for d in days]), y), f"{name} seed {seed}: row order differs"
            s = np.concatenate([z[f"test_{d}"] for d in days]).astype(np.float64)
            ssl[(name, seed)] = (s, float(np.quantile(z["val"], 1 - FPR)))

    # earlier / later half of every attack type, split at its median start time
    later = np.zeros(len(y), bool)
    for lab in set(label[y == 1]):
        m = label == lab
        later[m] = ts[m] >= np.median(ts[m])
    benign = y == 0

    rows, decisions = [], []
    for fam, types in FAMILIES.items():
        in_f = np.isin(label, types)
        test = np.flatnonzero(benign | (in_f & later))
        yt = y[test]
        blk = pd.factorize(pd.Series(day_of[test]) + ":" + (ts[test] // BLOCK).astype(np.int64).astype(str))[0]
        blk_day = pd.Series(day_of[test]).groupby(blk).first().to_numpy()
        ranked = {}
        for seed in SEEDS:
            rs = np.random.RandomState(seed)
            other = []
            for lab in sorted(set(label[(y == 1) & ~in_f])):
                ix = np.flatnonzero(label == lab)
                other.append(ix if len(ix) <= CAP else np.sort(rs.choice(ix, CAP, replace=False)))
            other = np.concatenate(other)
            seen_half = np.flatnonzero(in_f & ~later)
            for name, att in (("rf_unseen", other), ("rf_seen", np.concatenate([other, seen_half]))):
                t0 = time.time()
                cache = CACHE / f"{fam.replace(' ', '_')}_{name}_{seed}.npz"
                if cache.exists():
                    z = np.load(cache)
                    s, thr_cal = z["s"], float(z["thr_cal"])
                else:
                    Xf = np.concatenate([tr["X"], X[att]])
                    yf = np.r_[np.zeros(len(tr["X"]), np.int8), np.ones(len(att), np.int8)]
                    m = SupervisedRF(100, seed).fit(Xf, yf)
                    s = m.score(X[test])
                    thr_cal = float(np.quantile(m.score(va["X"]), 1 - FPR))
                    CACHE.mkdir(parents=True, exist_ok=True)
                    np.savez(cache, s=s.astype(np.float32), thr_cal=thr_cal)
                for thr_name, thr in (("0.5", 0.5), ("cal", thr_cal)):
                    ranked[(f"{name}@{thr_name}", seed)] = Ranked(s, yt, np.zeros(len(yt), int), 1, s > thr)
                rows.append(dict(family=fam, method=name, seed=seed, train_attacks=len(att), thr_cal=thr_cal,
                                 seconds=round(time.time() - t0, 1)))
                log.info("%s %s seed %d: %d training attacks, %.0fs", fam, name, seed, len(att), time.time() - t0)
            for name in SSL:
                s, thr = ssl[(name, seed)]
                ranked[(name, seed)] = Ranked(s[test], yt, np.zeros(len(yt), int), 1, s[test] > thr)

        rng = np.random.default_rng(0)
        point = {k: v.metrics(np.ones(len(yt))) for k, v in ranked.items()}
        boot = {k: [] for k in ranked}
        for _ in range(BOOT):
            cnt = np.zeros(blk.max() + 1)
            for d in np.unique(blk_day):
                ids = np.where(blk_day == d)[0]
                cnt += np.bincount(rng.choice(ids, len(ids)), minlength=len(cnt))
            w = cnt[blk]
            for k, v in ranked.items():
                boot[k].append(v.metrics(w))
        methods = sorted({k[0] for k in ranked})
        # a resample without any attack flow (the family sits in few 10-minute blocks) has undefined recall and AUC: Ranked returns
        # recall 0 and AUC NaN there, so recall / FPR are set to NaN in exactly the resamples whose AUC is undefined, then dropped
        def mean_boot(m, met):
            v = np.array([[b[met] if np.isfinite(b["roc_auc"]) else np.nan for b in boot[(m, s)]] for s in SEEDS])
            return v.mean(0)
        mean_pt = lambda m, met: float(np.mean([point[(m, s)][met] for s in SEEDS]))
        for m in methods:
            r = dict(family=fam, method=m, attack_flows_tested=int(yt.sum()), benign_flows=int((1 - yt).sum()))
            for met in ("roc_auc", "recall", "fpr"):
                r[met] = mean_pt(m, met)
                r[f"{met}_seed_std"] = float(np.std([point[(m, s)][met] for s in SEEDS], ddof=1))
                r[f"{met}_lo"], r[f"{met}_hi"] = np.nanpercentile(mean_boot(m, met), [2.5, 97.5])
            decisions.append(r)
        for tag, a, b, met in (("H8a", "rf_seen@cal", "rf_unseen@cal", "roc_auc"),
                               ("H8b", "ssl_tuned", "rf_unseen@cal", "recall"),
                               ("H8b_auc", "ssl_tuned", "rf_unseen@cal", "roc_auc"),
                               ("ssl_default_vs_unseen_recall", "ssl_default", "rf_unseen@cal", "recall")):
            diff = mean_boot(a, met) - mean_boot(b, met)
            lo, hi = np.nanpercentile(diff, [2.5, 97.5])
            decisions.append(dict(family=fam, method=f"{tag}: {a} - {b} ({met})", diff=mean_pt(a, met) - mean_pt(b, met),
                                  diff_lo=lo, diff_hi=hi, ci_above_0=bool(lo > 0),
                                  resamples_used=int(np.isfinite(diff).sum()), resamples=BOOT))
        log.info("family %s done", fam)

    OUT.mkdir(parents=True, exist_ok=True)
    res = pd.DataFrame(decisions)
    res.round(4).to_csv(OUT / "lofo_results.csv", index=False)
    pd.DataFrame(rows).round(4).to_csv(OUT / "lofo_training_runs.csv", index=False)
    met = res[res["diff"].isna()]
    pd.set_option("display.width", 250)
    print(met.pivot_table(index="family", columns="method", values="recall").round(3).to_string())
    print(met.pivot_table(index="family", columns="method", values="roc_auc").round(3).to_string())
    dec = res[res["diff"].notna()][["family", "method", "diff", "diff_lo", "diff_hi", "ci_above_0"]]
    print(dec.round(3).to_string(index=False))
    for tag in ("H8a", "H8b:"):
        k = int(dec[dec.method.str.startswith(tag)].ci_above_0.sum())
        print(f"{tag} CI > 0 in {k} of {len(FAMILIES)} families -> {'supported' if k >= 4 else 'not supported'}")


if __name__ == "__main__":
    main()
