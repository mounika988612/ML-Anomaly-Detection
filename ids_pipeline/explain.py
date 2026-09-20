"""Explainability for alerts of the main model (ssl_mm_role).

Three attribution methods are compared (RQ3):
  native : per-feature reconstruction error (free, model-specific)
  shap   : Shapley values of the calibrated anomaly score (KernelSHAP if `shap` imports,
           otherwise a built-in permutation-sampling estimator of the same quantity)
  lime   : local linear surrogate of the anomaly score
Quality is measured with deletion fidelity (score drop when the top-k features are reset to
benign values vs random-k), stability across seeds, cross-method agreement and runtime.
"""
import json
import pickle
import time

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch

from .analyst_report import Baseline, PcapContext, Suricata2017Context, build_report, raw_features, raw_roles
from .data import _adapter, load_feature_space, load_split
from .features import ROLE_NAMES
from .models import MLPAutoencoder, MultiModalSSL, batched_components
from .utils import get_logger

log = get_logger()
METHOD = "ssl_mm_role"


def _load(cfg, method=METHOD):
    meta = pickle.load(open(cfg["paths"]["work_dir"] / "models" / f"{method}.pkl", "rb"))
    cls = MLPAutoencoder if meta["spec"]["kind"] == "ae" else MultiModalSSL
    model = cls(meta["slices"], cfg["model"], meta["spec"]["use_role"])
    model.load_state_dict(torch.load(cfg["paths"]["work_dir"] / "models" / f"{method}.pt"))
    model.eval()
    return model, meta


def permutation_shapley(f, x, bg, n_perm, rs):
    """Monte-Carlo Shapley values: average marginal contribution over random feature orders,
    switching features from a random background row to the instance."""
    d = len(x)
    phi = np.zeros(d)
    rank = np.stack([rs.permutation(d) for _ in range(n_perm)])           # rank[p, j] = position of j
    steps = np.arange(d + 1)[None, :, None]
    mask = rank[:, None, :] < steps                                        # (P, d+1, d)
    base = bg[rs.randint(len(bg), size=n_perm)][:, None, :]
    rows = np.where(mask, x[None, None, :], base).reshape(-1, d).astype(np.float32)
    vals = f(rows).reshape(n_perm, d + 1)
    delta = vals[:, 1:] - vals[:, :-1]                                     # feature entering at step k
    order = np.argsort(rank, axis=1)                                       # order[p, k] = feature at step k
    for p in range(n_perm):
        phi[order[p]] += delta[p]
    return phi / n_perm


def shap_values(f, x, bg, e, rs):
    try:
        import shap
        ex = shap.KernelExplainer(f, bg[rs.choice(len(bg), min(20, len(bg)), replace=False)])
        return np.asarray(ex.shap_values(x[None], nsamples=500, silent=True)).reshape(-1), "shap.KernelExplainer"
    except Exception:
        return permutation_shapley(f, x, bg, e["shap_permutations"], rs), "permutation-Shapley (built-in)"


def lime_values(f, x, lime_exp, n_samples, seed, d):
    np.random.seed(seed)
    ex = lime_exp.explain_instance(x, f, num_features=d, num_samples=n_samples)
    w = np.zeros(d)
    for i, v in ex.as_map()[1 if 1 in ex.as_map() else list(ex.as_map())[0]]:
        w[i] = v
    return w


def jaccard(a, b):
    a, b = set(a), set(b)
    return len(a & b) / max(len(a | b), 1)


def top(v, k):
    return list(np.argsort(-np.abs(v))[:k])


def describe(names, mods, x, phi, k):
    lines = []
    for i in top(phi, k):
        direction = "above" if x[i] > 0 else "below"
        lines.append(f"{names[i]} ({mods[i]}): {abs(x[i]):.1f}σ {direction} the role's normal, "
                     f"{'raises' if phi[i] > 0 else 'lowers'} the score by {abs(phi[i]):.2f}")
    return lines


def run_explain(cfg):
    from lime.lime_tabular import LimeTabularExplainer
    e = cfg["explain"]
    method = e.get("method", METHOD)
    sfx = "" if method == METHOD else f"_{method}"     # do not overwrite the main model's outputs
    res = cfg["paths"]["results_dir"]
    rs = np.random.RandomState(cfg["data"]["seed"])
    fs = load_feature_space(cfg)
    model, meta = _load(cfg, method)
    calib, thr = meta["calibrator"], meta["thr"]
    idx = np.asarray(meta["idx"])       # feature columns the model uses (all of them except for single-modality models)
    names, mods, d = fs.names, fs.modality_of, len(fs.names)
    tr, va = load_split(cfg, "train"), load_split(cfg, "val")
    sc = np.load(res / "scores" / f"{method}.npz")

    def make_f(role):
        def f(X):
            X = np.asarray(X, np.float32)
            r = np.full(len(X), role, np.int8)
            return calib.transform(batched_components(model, X[:, idx], r), r)
        return f

    # --- choose alerts: stratified over attack types (random, not cherry-picked) + some false alarms
    pool = []
    for day in cfg["data"]["test_days"]:
        t = load_split(cfg, f"test_{day}")
        s = sc[f"test_{day}"]
        for i in np.where(s > thr)[0]:
            pool.append((day, i, t["label"][i], float(s[i])))
    df = pd.DataFrame(pool, columns=["day", "i", "label", "score"])
    attack_labels = sorted(set(df.label) - {"Benign"})
    per = max(1, (e["n_alerts"] - 5) // max(len(attack_labels), 1))
    chosen = [df[df.label == l].sample(min(per, (df.label == l).sum()), random_state=1) for l in attack_labels]
    chosen.append(df[df.label == "Benign"].sample(min(5, (df.label == "Benign").sum()), random_state=1))
    alerts = pd.concat(chosen).reset_index(drop=True)
    log.info("explaining %d alerts (%s)", len(alerts), alerts.label.value_counts().to_dict())

    lime_bg = tr["X"][rs.choice(len(tr["X"]), 5000, replace=False)]
    lime_exp = LimeTabularExplainer(lime_bg, feature_names=names, mode="regression",
                                    discretize_continuous=False, random_state=0)
    tests = {day: load_split(cfg, f"test_{day}") for day in cfg["data"]["test_days"]}
    k, records, quality, importance = e["top_k"], [], [], {}
    loader = _adapter(cfg)[0]
    provider = _provider(cfg)
    days_raw, items = {}, []
    base_df = pd.concat([loader(cfg, dd) for dd in cfg["data"]["train_days"]])
    base_df = base_df[base_df.attack == 0]
    base_df = base_df.iloc[np.sort(rs.choice(len(base_df), min(150000, len(base_df)), replace=False))]
    base_raw, base_roles = raw_features(cfg, base_df, names), raw_roles(cfg, base_df)
    baseline = Baseline(base_raw, base_roles, names)
    backend = ""
    for _, a in alerts.iterrows():
        t = tests[a.day]
        x, role = t["X"][a.i], int(t["role"][a.i])
        f = make_f(role)
        bgm = va["role"] == role
        bg = va["X"][bgm] if bgm.sum() >= e["background_size"] else va["X"]
        bg = bg[rs.choice(len(bg), min(e["background_size"], len(bg)), replace=False)]
        bg_med = np.median(bg, axis=0)

        comps = batched_components(model, x[None][:, idx], np.array([role], np.int8), keep_feat=True)
        native = np.zeros(d)
        native[idx] = comps["feat_err"][0]
        t0 = time.time(); phi, backend = shap_values(f, x, bg, e, np.random.RandomState(0)); t_shap = time.time() - t0
        phi2, _ = shap_values(f, x, bg, e, np.random.RandomState(1))
        t0 = time.time(); lw = lime_values(f, x, lime_exp, e["lime_samples"], 0, d); t_lime = time.time() - t0
        lw2 = lime_values(f, x, lime_exp, e["lime_samples"], 1, d)
        attr = {"native": native, "shap": phi, "lime": lw}
        if a.day not in days_raw:
            days_raw[a.day] = loader(cfg, a.day)
        rdf = days_raw[a.day]
        assert abs(float(rdf["ts"].iloc[a.i]) - float(t["ts"][a.i])) < 1e-6, "raw/processed row misalignment"
        items.append(dict(raw=raw_features(cfg, rdf.iloc[[a.i]], names)[0], role=ROLE_NAMES[role], score=float(f(x[None])[0]),
                          phi=phi, phi2=phi2, base=baseline.get(role), ts=float(t["ts"][a.i]),
                          dst_port=float(rdf["Dst Port"].iloc[a.i]) if "Dst Port" in rdf else None))
        f_x, f_med = float(f(x[None])[0]), float(f(bg_med[None])[0])
        row = dict(day=a.day, label=a.label, role=ROLE_NAMES[role], score=f_x)
        for m, v in attr.items():
            xd = x.copy(); ix = top(v, k); xd[ix] = bg_med[ix]
            rd = []
            for _ in range(5):
                xr = x.copy(); ir = rs.choice(d, k, replace=False); xr[ir] = bg_med[ir]; rd.append(f(xr[None])[0])
            denom = f_x - f_med
            if denom < 0.5:       # alert barely above the benign reference: fidelity ratio undefined
                denom = np.nan
            row[f"{m}_deletion_drop"] = (f_x - float(f(xd[None])[0])) / denom
            row[f"{m}_random_drop"] = (f_x - float(np.mean(rd))) / denom
        row.update(stab_native=1.0, stab_shap=jaccard(top(phi, k), top(phi2, k)),
                   stab_lime=jaccard(top(lw, k), top(lw2, k)),
                   agree_native_shap=jaccard(top(native, k), top(phi, k)),
                   agree_native_lime=jaccard(top(native, k), top(lw, k)),
                   agree_shap_lime=jaccard(top(phi, k), top(lw, k)),
                   sec_shap=t_shap, sec_lime=t_lime)
        quality.append(row)
        if a.label != "Benign":
            imp = np.abs(phi) / max(np.abs(phi).sum(), 1e-9)
            importance.setdefault(a.label, []).append(imp)
        share = {m: float(np.abs(phi)[[i for i in range(d) if mods[i] == m]].sum() / max(np.abs(phi).sum(), 1e-9))
                 for m in fs.slices}
        records.append(dict(day=a.day, true_label=a.label, role=ROLE_NAMES[role], score=f_x, threshold=thr,
                            modality_share=share, summary=describe(names, mods, x, phi, 5),
                            native_top=[names[i] for i in top(native, 5)],
                            shap_top=[names[i] for i in top(phi, 5)], lime_top=[names[i] for i in top(lw, 5)]))
    q = pd.DataFrame(quality)
    q.to_csv(res / f"explanation_per_alert{sfx}.csv", index=False)
    summ = q.drop(columns=["day", "label", "role", "score"]).mean(skipna=True).round(3)
    summ.to_csv(res / f"explanation_quality{sfx}.csv", header=["mean"])
    log.info("shap backend: %s\n%s", backend, summ.to_string())
    with open(res / f"explanations{sfx}.json", "w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=1)
    with open(res / f"explanations{sfx}.md", "w", encoding="utf-8") as fh:
        fh.write(f"# Alert explanations ({method}, attribution backend: {backend})\n\n")
        for i, r in enumerate(records):
            fh.write(f"## Alert {i + 1}: {r['day']} | role={r['role']} | score {r['score']:.1f} "
                     f"(threshold {r['threshold']:.1f}) | ground truth: {r['true_label']}\n\n")
            fh.write("Modality contribution: " + ", ".join(f"{m} {v:.0%}" for m, v in r["modality_share"].items()) + "\n\n")
            fh.writelines(f"- {ln}\n" for ln in r["summary"])
            fh.write("\n")
    if importance:
        M = pd.DataFrame({l: np.mean(v, axis=0) for l, v in importance.items()}, index=names).T
        cols = M.mean().sort_values(ascending=False).index[:15]
        fig, ax = plt.subplots(figsize=(11, 3 + .3 * len(M)))
        im = ax.imshow(M[cols].values, aspect="auto", cmap="viridis")
        ax.set_xticks(range(len(cols)), cols, rotation=60, ha="right", fontsize=8)
        ax.set_yticks(range(len(M)), M.index, fontsize=8)
        fig.colorbar(im, label="mean normalised |SHAP|")
        ax.set_title("Which features drive alerts, per attack type")
        fig.tight_layout()
        fig.savefig(res / f"shap_by_attack{sfx}.png", dpi=150)
        plt.close(fig)
    build_report(cfg, method, fs, alerts, items, thr, provider, res, sfx)


def _provider(cfg):
    if cfg["data"].get("dataset") == "suricata2017":
        return Suricata2017Context(cfg)
    rp = cfg.get("report")
    return PcapContext(rp["capture_dir"], rp["day"], rp["attacker"]) if rp else None
