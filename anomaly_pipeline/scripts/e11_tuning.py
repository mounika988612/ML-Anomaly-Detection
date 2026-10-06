"""E11 (results_comparison/PREREGISTRATION.md): fair hyperparameter tuning of the baselines.

    python scripts/e11_tuning.py select                        # P1, label-free search of every unsupervised method
    python scripts/e11_tuning.py select-rf --config config_unsw.yaml
    python scripts/e11_tuning.py final                         # P1, selected settings, seeds 42 1 2 -> results_e11_cic2017_monday*
    python scripts/e11_tuning.py final-rf --config config_unsw.yaml

Unsupervised selection = the criterion of scripts/hparam_search.py for every method: mean ROC-AUC of 4,000 benign validation flows
(seed 1) against the same two synthetic-anomaly sets (modality shuffle, feature extreme), model seed 0, no attack label. A candidate
replaces the default only if it beats it by more than 0.002. RF selection: PR-AUC on the latest 20% (by time) of the labelled
training-period pool (UNSW-NB15: stratified random 20%, seed 42). Selections are written to results_comparison/E11/; the final runs
write normal score files, so scripts/clean_eval.py evaluates them (--results-dir results_e11_<name>).
"""
import argparse
import copy
import json
import shutil
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import average_precision_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from hparam_search import auc, make_pseudo_anomalies          # noqa: E402
from ids_pipeline.data import load_feature_space, load_split  # noqa: E402
from ids_pipeline.models import MLPAutoencoder, MultiModalSSL, batched_components, batched_embed, train_model  # noqa: E402
from ids_pipeline.scoring import LatentKNN                    # noqa: E402
from ids_pipeline.train import _save_scores, _threshold, method_specs, train_neural  # noqa: E402
from ids_pipeline.utils import get_logger, load_config, set_seed  # noqa: E402

log = get_logger()
OUT = ROOT / "results_comparison" / "E11"
P1 = "config_cic2017_monday.yaml"
SEED, TIE = 0, 0.002
SEEDS = [42, 1, 2]
NEURAL_GRID = [(h, z) for h in (64, 128, 256) for z in (16, 32, 64)]
K_GRID = [1, 5, 10, 20]
IF_GRID = [(n, s, f) for n in (100, 200, 400) for s in (256, 1024, 4096) for f in (0.5, 1.0)]
PCA_GRID = [0.80, 0.90, 0.95, 0.99]
RF_GRID = [(n, d, l) for n in (100, 300) for d in (10, 20, None) for l in (1, 2, 5)]
DEFAULTS = dict(neural=(128, 32), k=5, iforest=(200, 256, 1.0), pca=0.95, rf=(100, 20, 2))


def pseudo(cfg, fs, va):
    """benign validation sample and its two synthetic-anomaly sets, built as in hparam_search.run_candidate."""
    rs = np.random.RandomState(1)
    pick = rs.choice(len(va["X"]), min(4000, len(va["X"])), replace=False)
    Xb, rb = va["X"][pick], va["role"][pick]
    return Xb, rb, make_pseudo_anomalies(rs, Xb, fs.slices, cfg["data"]["clip"])


def pseudo_aucs(score, Xb, rb, sets):
    b = score(Xb, rb)
    r = {name: auc(b, score(Xp, rb)) for name, Xp in sets.items()}
    r["mean"] = float(np.mean(list(r.values())))
    return r


def knn_scorer(cfg, model, tr, k, seed):
    s = cfg["scoring"]
    knn = LatentKNN(k, s.get("knn_ref", 10000), s.get("knn_ref_role", 5000), True, s["min_role_samples"], seed)
    knn.fit(batched_embed(model, tr["X"], tr["role"]), tr["role"])
    return lambda X, r: knn.distances(batched_embed(model, X, r), r)


def fit_iforest(X, params, seed, n_fit):
    n, s, f = params
    rs = np.random.RandomState(seed)
    sub = X[rs.choice(len(X), min(n_fit, len(X)), replace=False)]
    m = IsolationForest(n_estimators=n, max_samples=s, max_features=f, random_state=seed, n_jobs=-1).fit(sub)
    return lambda X, r=None: -m.score_samples(X)


def fit_pca(X, var, seed, n_fit):
    rs = np.random.RandomState(seed)
    sub = X[rs.choice(len(X), min(n_fit, len(X)), replace=False)]
    m = PCA(n_components=var, random_state=seed).fit(sub)

    def score(X, r=None):
        return np.concatenate([((x - m.inverse_transform(m.transform(x))) ** 2).mean(1) for x in np.array_split(X, max(1, len(X) // 100000))])
    return score


def train_net(cfg, fs, tr, va, kind, hidden, latent, seed):
    mcfg = dict(cfg["model"], hidden=hidden, latent_dim=latent)
    set_seed(seed)
    model = MultiModalSSL(fs.slices, mcfg, use_role=True) if kind == "ssl" else MLPAutoencoder(fs.slices, mcfg)
    train_model(model, tr["X"], tr["role"], va["X"], va["role"], mcfg, log, tag=f"{kind} h={hidden} z={latent}")
    return model


def pick(rows, method, default):
    """best candidate by mean pseudo-anomaly AUC, unless it beats the default by no more than TIE."""
    t = pd.DataFrame([r for r in rows if r["method"] == method])
    best = t.loc[t["mean"].idxmax()]
    dflt = t.loc[t["params"] == str(default)].iloc[0]
    chosen = best if best["mean"] - dflt["mean"] > TIE else dflt
    return chosen["params"], float(chosen["mean"]), float(dflt["mean"])


def select(a):
    cfg = load_config(ROOT / P1)
    fs = load_feature_space(cfg)
    tr, va = load_split(cfg, "train"), load_split(cfg, "val")
    Xb, rb, sets = pseudo(cfg, fs, va)
    rows, models = [], {}
    n_fit = cfg["baselines"]["n_fit_rows"]

    def add(method, params, score, t0):
        r = dict(method=method, params=str(params), **pseudo_aucs(score, Xb, rb, sets), seconds=round(time.time() - t0, 1))
        rows.append(r)
        log.info("%-18s %-22s mean %.4f", method, params, r["mean"])

    for h, z in NEURAL_GRID:
        for kind in ("ssl", "ae"):
            t0 = time.time()
            m = models[(kind, h, z)] = train_net(cfg, fs, tr, va, kind, h, z, SEED)
            add(f"{kind}_knnrole", (h, z), knn_scorer(cfg, m, tr, DEFAULTS["k"], cfg["data"]["seed"]), t0)
            if kind == "ae":
                add("ae_recon", (h, z), lambda X, r, m=m: batched_components(m, X, r)["rec"], t0)
    sel = {}
    for method, kind in (("ssl_knnrole", "ssl"), ("ae_knnrole", "ae")):
        p, _, _ = pick(rows, method, DEFAULTS["neural"])
        sel[method] = dict(hidden=eval(p)[0], latent_dim=eval(p)[1])
        m = models[(kind, *eval(p))]
        for k in K_GRID:
            add(f"{method}_k", k, knn_scorer(cfg, m, tr, k, cfg["data"]["seed"]), time.time())
        sel[method]["k"] = int(pick(rows, f"{method}_k", DEFAULTS["k"])[0])
    p, _, _ = pick(rows, "ae_recon", DEFAULTS["neural"])
    sel["ae_recon"] = dict(hidden=eval(p)[0], latent_dim=eval(p)[1])
    for params in IF_GRID:
        t0 = time.time()
        add("iforest", params, fit_iforest(tr["X"], params, SEED, n_fit), t0)
    sel["iforest"] = dict(zip(("n_estimators", "max_samples", "max_features"), eval(pick(rows, "iforest", DEFAULTS["iforest"])[0])))
    for v in PCA_GRID:
        t0 = time.time()
        add("pca", v, fit_pca(tr["X"], v, SEED, n_fit), t0)
    sel["pca"] = dict(n_components=float(pick(rows, "pca", DEFAULTS["pca"])[0]))

    OUT.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).round(4).to_csv(OUT / "selection_p1.csv", index=False)
    summary = []
    for method in ("ssl_knnrole", "ssl_knnrole_k", "ae_knnrole", "ae_knnrole_k", "ae_recon", "iforest", "pca"):
        default = DEFAULTS["k"] if method.endswith("_k") else DEFAULTS["neural"] if method in ("ssl_knnrole", "ae_knnrole", "ae_recon") \
            else DEFAULTS[method]
        p, best, dflt = pick(rows, method, default)
        t = pd.DataFrame([r for r in rows if r["method"] == method])
        summary.append(dict(method=method, default=str(default), default_mean_auc=dflt, selected=p, selected_mean_auc=best,
                            best_candidate=t.loc[t["mean"].idxmax(), "params"], best_mean_auc=float(t["mean"].max()),
                            changed=p != str(default)))
    pd.DataFrame(summary).round(4).to_csv(OUT / "selection_p1_summary.csv", index=False)
    (OUT / "selected_p1.json").write_text(json.dumps(sel, indent=2))
    print(pd.DataFrame(summary).round(4).to_string(index=False))
    print(json.dumps(sel, indent=2))


def rf_val_split(cfg, sup):
    if cfg["data"].get("dataset") == "unsw_nb15":
        return train_test_split(np.arange(len(sup["y"])), test_size=0.2, stratify=sup["y"], random_state=42)
    order = np.argsort(sup["ts"], kind="stable")
    cut = int(len(order) * 0.8)
    return order[:cut], order[cut:]


def rf_model(params, seed):
    n, d, l = params
    return RandomForestClassifier(n_estimators=n, max_depth=d, min_samples_leaf=l, class_weight="balanced_subsample",
                                  n_jobs=-1, random_state=seed)


def select_rf(a):
    cfg = load_config(ROOT / a.config)
    sup = load_split(cfg, "sup")
    fit_i, val_i = rf_val_split(cfg, sup)
    yv = sup["y"][val_i]
    info = dict(config=a.config, fit_rows=len(fit_i), fit_attacks=int(sup["y"][fit_i].sum()), val_rows=len(val_i),
                val_attacks=int(yv.sum()), val_attack_types="; ".join(sorted(set(sup["label"][val_i][yv == 1]))))
    log.info("RF validation split: %s", info)
    if yv.sum() == 0 or yv.sum() == len(yv):
        raise SystemExit(f"RF validation split of {a.config} has a single class; PR-AUC undefined: {info}")
    rows = []
    for params in RF_GRID:
        t0 = time.time()
        m = rf_model(params, SEED).fit(sup["X"][fit_i], sup["y"][fit_i])
        rows.append(dict(params=str(params), pr_auc=average_precision_score(yv, m.predict_proba(sup["X"][val_i])[:, 1]),
                         seconds=round(time.time() - t0, 1)))
        log.info("rf %-16s PR-AUC %.4f", params, rows[-1]["pr_auc"])
    t = pd.DataFrame(rows)
    best = t.loc[t.pr_auc.idxmax()]
    dflt = t.loc[t.params == str(DEFAULTS["rf"])].iloc[0]
    chosen = best if best.pr_auc - dflt.pr_auc > TIE else dflt
    name = Path(a.config).stem
    OUT.mkdir(parents=True, exist_ok=True)
    t.round(4).to_csv(OUT / f"selection_rf_{name}.csv", index=False)
    sel = dict(**info, default=str(DEFAULTS["rf"]), default_pr_auc=float(dflt.pr_auc), best=best.params,
               best_pr_auc=float(best.pr_auc), selected=chosen.params, selected_pr_auc=float(chosen.pr_auc))
    (OUT / f"selected_rf_{name}.json").write_text(json.dumps(sel, indent=2))
    print(t.round(4).sort_values("pr_auc", ascending=False).to_string(index=False))
    print(json.dumps(sel, indent=2))


def seed_dirs(cfg, name, seed):
    res = ROOT / f"results_e11_{name}" if seed == cfg["data"]["seed"] else ROOT / f"results_e11_{name}_seed{seed}"
    c = copy.deepcopy(cfg)
    c["data"]["seed"] = seed
    c["paths"]["results_dir"] = res
    c["paths"]["models_dir"] = res / "models"
    (res / "scores").mkdir(parents=True, exist_ok=True)
    return c


def final(a):
    cfg = load_config(ROOT / P1)
    sel = json.loads((OUT / "selected_p1.json").read_text())
    fs = load_feature_space(cfg)
    tr, va = load_split(cfg, "train"), load_split(cfg, "val")
    tests = {d: load_split(cfg, f"test_{d}") for d in cfg["data"]["test_days"]}
    specs = method_specs(fs)
    n_fit, fpr = cfg["baselines"]["n_fit_rows"], cfg["scoring"]["target_fpr"]
    for seed in SEEDS:
        c = seed_dirs(cfg, "cic2017_monday", seed)
        c["scoring"]["latefuse_knn"] = False
        log.info("=== E11 final, seed %d -> %s", seed, c["paths"]["results_dir"])
        res = c["paths"]["results_dir"]
        done = lambda step: (res / f".done_{step}").exists()
        mark = lambda step: (res / f".done_{step}").touch()
        s = sel["ssl_knnrole"]
        cs = copy.deepcopy(c)
        cs["model"].update(hidden=s["hidden"], latent_dim=s["latent_dim"])
        cs["scoring"]["knn_k"] = s["k"]
        if not done("ssl"):
            train_neural(cs, "ssl_mm_role", specs["ssl_mm_role"], fs, tr, va, tests)
            mark("ssl")
        # AE: reconstruction score and role-kNN score were selected separately
        r, k = sel["ae_recon"], sel["ae_knnrole"]
        ca = copy.deepcopy(c)
        ca["model"].update(hidden=r["hidden"], latent_dim=r["latent_dim"])
        ca["scoring"]["knn_k"] = k["k"]
        if not done("ae_recon"):
            train_neural(ca, "ae_concat", specs["ae_concat"], fs, tr, va, tests)
            mark("ae_recon")
        if (r["hidden"], r["latent_dim"]) != (k["hidden"], k["latent_dim"]) and not done("ae_knnrole"):
            tmp = c["paths"]["results_dir"] / "_ae_knnrole"
            ck = copy.deepcopy(c)
            ck["model"].update(hidden=k["hidden"], latent_dim=k["latent_dim"])
            ck["scoring"]["knn_k"] = k["k"]
            ck["paths"]["results_dir"], ck["paths"]["models_dir"] = tmp, tmp / "models"
            tmp.mkdir(parents=True, exist_ok=True)
            train_neural(ck, "ae_concat", specs["ae_concat"], fs, tr, va, tests)
            shutil.copy(tmp / "scores" / "ae_concat_knnrole.npz", c["paths"]["results_dir"] / "scores" / "ae_concat_knnrole.npz")
            shutil.rmtree(tmp)
            mark("ae_knnrole")
        for name, score in (("iforest", fit_iforest(tr["X"], tuple(sel["iforest"].values()), seed, n_fit)),
                            ("pca_recon", fit_pca(tr["X"], sel["pca"]["n_components"], seed, n_fit))):
            t0 = time.time()
            val = score(va["X"])
            lat = (time.time() - t0) / len(val) * 1e6
            _save_scores(c, name, val, _threshold(val, fpr), {d: score(t["X"]) for d, t in tests.items()}, lat, tests)
        if "sig" in va:                                     # signature baseline unchanged, for completeness of the tables
            _save_scores(c, "suricata_signature", va["sig"].astype(np.float32), 0.5,
                         {d: t["sig"].astype(np.float32) for d, t in tests.items()}, 0.0, tests)
        (c["paths"]["results_dir"] / "e11_selected.json").write_text(json.dumps(sel, indent=2))


def final_rf(a):
    cfg = load_config(ROOT / a.config)
    name = Path(a.config).stem
    sel = json.loads((OUT / f"selected_rf_{name}.json").read_text())
    params = eval(sel["selected"])
    sup, va = load_split(cfg, "sup"), load_split(cfg, "val")
    tests = {d: load_split(cfg, f"test_{d}") for d in cfg["data"]["test_days"]}
    base = cfg["paths"]["results_dir"]
    for seed in SEEDS:
        c = seed_dirs(cfg, name.removeprefix("config_"), seed)
        m = rf_model(params, seed).fit(sup["X"], sup["y"])
        t0 = time.time()
        val = m.predict_proba(va["X"])[:, 1]
        lat = (time.time() - t0) / len(val) * 1e6
        _save_scores(c, "rf_supervised", val, 0.5, {d: m.predict_proba(t["X"])[:, 1] for d, t in tests.items()}, lat, tests)
        # the shipped proposed model of the same seed, so clean_eval can pair it with the tuned RF (H6)
        src = (base if seed == cfg["data"]["seed"] else base.parent / f"{base.name}_seed{seed}") / "scores" / "ssl_mm_role_knn.npz"
        if src.exists():
            shutil.copy(src, c["paths"]["results_dir"] / "scores" / src.name)
        log.info("rf %s seed %d done", params, seed)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stage", choices=["select", "select-rf", "final", "final-rf"])
    ap.add_argument("--config", help="RF stages: config of the protocol")
    a = ap.parse_args()
    {"select": select, "select-rf": select_rf, "final": final, "final-rf": final_rf}[a.stage](a)


if __name__ == "__main__":
    main()
