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
from .data import _adapter, check_aligned, load_feature_space, load_split
from .features import ROLE_NAMES
from .models import MLPAutoencoder, MultiModalSSL, batched_components, batched_embed
from .scoring import Calibrator, LatentKNN, tail_score, tail_score_ext
from .train import seed_results_dir
from .utils import get_logger

log = get_logger()
METHOD = "ssl_mm_role"


def _load(cfg, method=METHOD, models_dir=None):
    d = models_dir or cfg["paths"]["work_dir"] / "models"
    meta = pickle.load(open(d / f"{method}.pkl", "rb"))
    cls = MLPAutoencoder if meta["spec"]["kind"] == "ae" else MultiModalSSL
    model = cls(meta["slices"], cfg["model"], meta["spec"]["use_role"])
    model.load_state_dict(torch.load(d / f"{method}.pt"))
    model.eval()
    return model, meta


def _seed_models_dir(cfg, seed):
    """models of one seed: the config's own seed in work_dir/models, extra seeds in `<results_dir>_seed<N>/models` (multiseed.py)"""
    return cfg["paths"]["work_dir"] / "models" if seed == cfg["data"]["seed"] else seed_results_dir(cfg, seed) / "models"


def _ensemble_scorer(cfg, meta, d, tr, va):
    """`ssl_mm_ensemble`: explains the unsaturated score (TailEnsemble.transform(extrapolate=True), equal to the detector's
    score wherever no level exceeds its benign 99th percentile). Rebuilds, per seed, the role-aware latent-kNN score of `ssl_mm_role` (the kNN reference is refitted
    exactly as in train.train_neural: same seed, same benign training rows) and the five experts, then applies the saved
    TailEnsemble. Native attribution: per seed the experts' per-feature errors weighted by their tail evidence, seed mean."""
    scfg, fusion, members = cfg["scoring"], meta["fusion"], []
    zero = lambda n: np.zeros(n, np.float32)
    for seed in meta["spec"]["seeds"]:
        md = _seed_models_dir(cfg, seed)
        model, m = _load(cfg, "ssl_mm_role", md)
        idx = np.asarray(m["idx"])
        knn = LatentKNN(scfg.get("knn_k", 5), scfg.get("knn_ref", 10000), scfg.get("knn_ref_role", 5000), True,
                        scfg["min_role_samples"], seed).fit(batched_embed(model, tr["X"][:, idx], tr["role"]), tr["role"])
        vd = knn.distances(batched_embed(model, va["X"][:, idx], va["role"]), va["role"])
        kc = Calibrator(0.0, False, scfg["min_role_samples"], scfg.get("min_scale_ratio", 0.5)).fit({"rec": vd, "xmod": zero(len(vd))}, va["role"])
        experts = {p: _load(cfg, p, md) for p in meta["spec"]["parts"][1:]}
        members.append((model, idx, knn, kc, experts))

    def raw(X, r):
        X = np.asarray(X, np.float32)
        out = []
        for model, idx, knn, kc, experts in members:
            dd = knn.distances(batched_embed(model, X[:, idx], r), r)
            m = {"ssl_mm_role_knn": kc.transform({"rec": dd, "xmod": zero(len(dd))}, r)}
            m.update({p: em["calibrator"].transform(batched_components(emod, X[:, np.asarray(em["idx"])], r), r)
                      for p, (emod, em) in experts.items()})
            out.append(m)
        return out

    def score(X, r):
        # unsaturated version of the detector score: strong alerts sit at the empirical ceiling (~10.85), where no single
        # feature can move the score, so attributions of the saturated score failed the deletion test (README section 9)
        return fusion.transform(raw(X, r), extrapolate=True)
    score.raw, score.fusion = raw, fusion       # for scripts/xai_eval.py (refits the fusion of randomised models)

    def native(x, role):
        out, r = np.zeros(d), np.array([role], np.int8)
        for (_, _, _, _, experts), m, ref in zip(members, raw(x[None], r), fusion.refs):
            for p, (emod, em) in experts.items():
                idx = np.asarray(em["idx"])
                fe = batched_components(emod, x[None][:, idx], r, keep_feat=True)["feat_err"][0]
                out[idx] += fe / max(fe.sum(), 1e-12) * float(tail_score_ext(m[p], ref[p], presorted=True)[0]) / len(members)
        return out
    return score, native, meta["thr"]


def _scorer(cfg, method, d, tr=None, va=None):
    """-> score(X, roles) on the full feature matrix, native(x, role) -> per-feature attribution over all d features, threshold.
    `ssl_mm_experts` (train.fuse_experts) is the min-p fusion of the single-modality experts; its native attribution is each
    expert's per-feature reconstruction error, rescaled so an expert's features share that expert's tail evidence (-log p)."""
    meta = pickle.load(open(cfg["paths"]["work_dir"] / "models" / f"{method}.pkl", "rb"))
    if meta["spec"]["kind"] == "ensemble":
        return _ensemble_scorer(cfg, meta, d, tr, va)
    if meta["spec"]["kind"] != "experts":
        model, meta = _load(cfg, method)
        calib, idx = meta["calibrator"], np.asarray(meta["idx"])

        def score(X, r):
            return calib.transform(batched_components(model, np.asarray(X, np.float32)[:, idx], r), r)

        def native(x, role):
            out = np.zeros(d)
            out[idx] = batched_components(model, x[None][:, idx], np.array([role], np.int8), keep_feat=True)["feat_err"][0]
            return out
        return score, native, meta["thr"]

    experts = {p: _load(cfg, p) for p in meta["spec"]["parts"]}
    refs = meta["refs"]

    def expert_tail(X, r):
        X = np.asarray(X, np.float32)
        return {p: tail_score(m["calibrator"].transform(batched_components(model, X[:, np.asarray(m["idx"])], r), r), refs[p], presorted=True)
                for p, (model, m) in experts.items()}

    def score(X, r):
        return np.max(list(expert_tail(X, r).values()), 0).astype(np.float32)
    score.experts, score.refs = experts, refs   # for scripts/xai_eval.py (refits the refs of randomised models)

    def native(x, role):
        out, r = np.zeros(d), np.array([role], np.int8)
        ts = expert_tail(x[None], r)
        for p, (model, m) in experts.items():
            idx = np.asarray(m["idx"])
            fe = batched_components(model, x[None][:, idx], r, keep_feat=True)["feat_err"][0]
            out[idx] = fe / max(fe.sum(), 1e-12) * float(ts[p][0])
        return out
    return score, native, meta["thr"]


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
        # background 20->40, nsamples 500->1200: KernelSHAP variance falls with more coalition samples;
        # cost is negligible here (~0.05s/alert measured), so this buys cross-seed stability cheaply.
        ex = shap.KernelExplainer(f, bg[rs.choice(len(bg), min(40, len(bg)), replace=False)])
        return np.asarray(ex.shap_values(x[None], nsamples=1200, silent=True)).reshape(-1), "shap.KernelExplainer"
    except Exception:
        return permutation_shapley(f, x, bg, e["shap_permutations"], rs), "permutation-Shapley (built-in)"


LIME_NUM_FEATURES = 30   # let LIME's own feature selection pick a subset instead of fitting all d
                         # coefficients on n_samples perturbations (that was underdetermined and unstable)


def lime_values(f, x, lime_exp, n_samples, seed, d, num_features=LIME_NUM_FEATURES):
    np.random.seed(seed)
    ex = lime_exp.explain_instance(x, f, num_features=min(num_features, d), num_samples=n_samples)
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
    names, mods, d = fs.names, fs.modality_of, len(fs.names)
    tr, va = load_split(cfg, "train"), load_split(cfg, "val")
    score, native_attr, thr = _scorer(cfg, method, d, tr, va)
    sc = np.load(res / "scores" / f"{method}.npz")

    def make_f(role):
        def f(X):
            return score(X, np.full(len(X), role, np.int8))
        return f

    # --- choose alerts: stratified over attack types (random, not cherry-picked) + some false alarms
    pool = []
    for day in cfg["data"]["test_days"]:
        t = load_split(cfg, f"test_{day}")
        check_aligned(sc, day, t, method)
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

    # one LIME explainer per role, background matched to that role (mirrors the per-alert SHAP background
    # below); a single dataset-wide background was fitting the local surrogate against the wrong notion of
    # "normal" for roles whose benign traffic looks different from the pooled average.
    def _lime_bg(role):
        m = tr["role"] == role
        pool = tr["X"][m] if m.sum() >= e["background_size"] else tr["X"]
        return pool[rs.choice(len(pool), min(5000, len(pool)), replace=False)]

    lime_exps = {r: LimeTabularExplainer(_lime_bg(r), feature_names=names, mode="regression",
                                         discretize_continuous=False, random_state=0)
                for r in range(len(ROLE_NAMES))}
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

        native = native_attr(x, role)
        t0 = time.time(); phi, backend = shap_values(f, x, bg, e, np.random.RandomState(0)); t_shap = time.time() - t0
        phi2, _ = shap_values(f, x, bg, e, np.random.RandomState(1))
        lime_exp = lime_exps[role]
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
