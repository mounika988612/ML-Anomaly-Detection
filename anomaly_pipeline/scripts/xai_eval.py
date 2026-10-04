"""E10 (results_comparison/PREREGISTRATION.md): extended explanation evaluation for RQ3, no human raters needed.

    python scripts/xai_eval.py                                   # all three methods on CIC-IDS2017 P1
    python scripts/xai_eval.py --methods ssl_mm_experts --per-type 3 --n-benign 3 --no-random   # quick smoke run

Checks (definitions in the E10 entry): G modality-level exact Shapley values; F1 deletion with realistic replacement (the
alert's nearest benign validation flow of the same role) as AOPC over k = 1..10 vs random orders; F2 modality deletion;
C counterfactual size; P plausibility against the pre-registered expected modalities; R model-randomisation sanity check;
S simulatability (can a classifier recover the attack type from the explanation alone?). The median-reset deletion test of
explain.py (F0) is reported next to F1. Attributions: native, SHAP and LIME exactly as explain.py computes them.
Outputs: <results_dir>/xai_eval/{per_alert_<m>.csv, attributions_<m>.npz, summary.csv, simulatability.csv, E10_report.md}.
"""
import argparse
import itertools
import sys
import time
from math import factorial
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from scipy.stats import spearmanr
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.model_selection import RepeatedStratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_pipeline import explain as X                                                     # noqa: E402
from ids_pipeline.data import load_feature_space, load_split                              # noqa: E402
from ids_pipeline.features import ROLE_NAMES                                              # noqa: E402
from ids_pipeline.models import batched_components                                        # noqa: E402
from ids_pipeline.scoring import Calibrator, TailEnsemble                                 # noqa: E402
from ids_pipeline.utils import get_logger, load_config                                    # noqa: E402

log = get_logger()
METHODS = ["ssl_mm_ensemble", "ssl_mm_experts", "ssl_mm_role"]
ATTR = ["native", "shap", "lime"]                     # feature-level attributions; G is modality-level
KMAX, N_RANDOM, N_BOOT = 10, 5, 1000
# pre-registered before any E10 run (PREREGISTRATION.md, E10)
EXPECTED = {
    "DoS Hulk": {"http", "flow"}, "DoS GoldenEye": {"http", "flow"}, "DDoS": {"http", "flow"},
    "DoS Slowloris": {"flow", "tcp", "http"}, "DoS Slowhttptest": {"flow", "tcp", "http"},
    "FTP-Patator": {"session", "flow", "tcp"}, "SSH-Patator": {"session", "flow", "tcp"},
    "Portscan": {"tcp", "flow", "dns"}, "Infiltration - Portscan": {"tcp", "flow", "dns"},
    "Botnet": {"http", "flow"},
    "Web Attack - Brute Force": {"http"}, "Web Attack - XSS": {"http"}, "Web Attack - SQL Injection": {"http"},
}
NOT_EVALUATED = {"Heartbleed", "Infiltration"}


def group_shapley(f, x, bg, groups):
    """Exact Shapley values over feature groups. v(S) = mean over background rows of f with the features of the groups in S
    taken from x; with G groups this needs 2^G * len(bg) evaluations (5 modalities: 32 x 100)."""
    G = len(groups)
    masks = list(itertools.product([0, 1], repeat=G))
    rows = np.repeat(bg[None], len(masks), 0).copy()
    for s, m in enumerate(masks):
        for g in range(G):
            if m[g]:
                rows[s][:, groups[g]] = x[groups[g]]
    v = f(rows.reshape(-1, len(x)).astype(np.float32)).reshape(len(masks), len(bg)).mean(1)
    pos = {m: i for i, m in enumerate(masks)}
    phi = np.zeros(G)
    for m in masks:
        n = sum(m)
        for g in range(G):
            if not m[g]:
                w = factorial(n) * factorial(G - n - 1) / factorial(G)
                with_g = list(m); with_g[g] = 1
                phi[g] += w * (v[pos[tuple(with_g)]] - v[pos[m]])
    return phi, float(v[pos[tuple([1] * G)]]), float(v[pos[tuple([0] * G)]])


def boot_ci(v, rs, n=N_BOOT):
    v = np.asarray(v, float)
    v = v[np.isfinite(v)]
    if len(v) < 3:
        return np.nan, np.nan, np.nan
    b = rs.choice(len(v), (n, len(v))).astype(int)
    m = v[b].mean(1)
    return float(v.mean()), float(np.quantile(m, .025)), float(np.quantile(m, .975))


def randomise_loader(va, seed=123):
    """explain._load replacement for check R: same architecture, weights re-initialised, calibrator refitted on the benign
    validation flows exactly as train.py fits it (so the randomised score is on a comparable scale)."""
    orig = X._load

    def load(cfg, method=X.METHOD, models_dir=None):
        model, meta = orig(cfg, method, models_dir)
        torch.manual_seed(seed)
        for mod in model.modules():
            if hasattr(mod, "reset_parameters"):
                mod.reset_parameters()
        model.eval()
        meta = dict(meta)
        c = meta.get("calibrator")
        if c is not None:
            idx = np.asarray(meta["idx"])
            meta["calibrator"] = Calibrator(c.w, c.role_aware, c.min_n, c.min_scale_ratio).fit(
                batched_components(model, va["X"][:, idx], va["role"]), va["role"])
        return model, meta
    return orig, load


def build_scorer(cfg, method, d, tr, va, randomised=False):
    if not randomised:
        return X._scorer(cfg, method, d, tr, va)
    orig, load = randomise_loader(va)
    X._load = load
    try:
        score, native, thr = X._scorer(cfg, method, d, tr, va)
    finally:
        X._load = orig
    if hasattr(score, "fusion"):            # ensemble: refit every tail level on the randomised members' validation scores
        score.fusion.refs = TailEnsemble(score.fusion.knn, score.fusion.experts).fit(score.raw(va["X"], va["role"])).refs
    elif hasattr(score, "refs"):            # experts: refit each expert's benign validation reference
        for p, (model, m) in score.experts.items():
            v = m["calibrator"].transform(batched_components(model, va["X"][:, np.asarray(m["idx"])], va["role"]), va["role"])
            score.refs[p] = np.sort(v.astype(np.float64))
    return score, native, thr


def sample_alerts(cfg, score, thr, tests, per_type, n_benign):
    pool = []
    for day, t in tests.items():
        s = np.concatenate([score(t["X"][i:i + 200000], t["role"][i:i + 200000]) for i in range(0, len(t["X"]), 200000)])
        for i in np.where(s > thr)[0]:
            pool.append((day, i, t["label"][i], float(s[i])))
    df = pd.DataFrame(pool, columns=["day", "i", "label", "score"])
    parts = [df[df.label == l].sample(min(per_type, (df.label == l).sum()), random_state=1)
             for l in sorted(set(df.label) - {"Benign"})]
    parts.append(df[df.label == "Benign"].sample(min(n_benign, (df.label == "Benign").sum()), random_state=1))
    counts = df.label.value_counts().to_dict()
    return pd.concat(parts).reset_index(drop=True), counts


def attributions(f, x, bg, lime_exp, native_attr, role, e, groups, d):
    t0 = time.time()
    a = {"native": native_attr(x, role)}
    a["shap"], _ = X.shap_values(f, x, bg, e, np.random.RandomState(0))
    a["lime"] = X.lime_values(f, x, lime_exp, e["lime_samples"], 0, d)
    a["G"], v_all, v_none = group_shapley(f, x, bg, groups)
    return a, time.time() - t0, v_all, v_none


def evaluate_method(cfg, method, fs, tr, va, tests, args, rs_boot):
    e, d = cfg["explain"], len(fs.names)
    mods = list(fs.slices)
    groups = [np.arange(*fs.slices[m]) for m in mods]
    mod_of = np.array([mods.index(m) for m in fs.modality_of])
    score, native_attr, thr = build_scorer(cfg, method, d, tr, va)
    alerts, counts = sample_alerts(cfg, score, thr, tests, args.per_type, args.n_benign)
    log.info("[%s] threshold %.3f; alerts available %s; explaining %d", method, thr, counts, len(alerts))

    rs = np.random.RandomState(cfg["data"]["seed"])
    from lime.lime_tabular import LimeTabularExplainer
    lime_exps, val_by_role = {}, {}

    def lime_for(role):
        if role not in lime_exps:
            m = tr["role"] == role
            pool = tr["X"][m] if m.sum() >= e["background_size"] else tr["X"]
            pool = pool[np.random.RandomState(role).choice(len(pool), min(5000, len(pool)), replace=False)]
            lime_exps[role] = LimeTabularExplainer(pool, feature_names=fs.names, mode="regression",
                                                   discretize_continuous=False, random_state=0)
        return lime_exps[role]

    def background(role):
        m = va["role"] == role
        bg = va["X"][m] if m.sum() >= e["background_size"] else va["X"]
        return bg[rs.choice(len(bg), min(e["background_size"], len(bg)), replace=False)]

    def nearest_benign(x, role):
        if role not in val_by_role:
            m = va["role"] == role
            val_by_role[role] = va["X"][m] if m.sum() >= 1 else va["X"]
        V = val_by_role[role]
        return V[np.argmin(((V - x) ** 2).sum(1))]

    rows, store = [], {k: [] for k in ATTR + ["G", "x", "score"]}
    for n, a in alerts.iterrows():
        t = tests[a.day]
        x, role = t["X"][a.i].astype(np.float32), int(t["role"][a.i])
        f = (lambda role: (lambda Z: score(np.asarray(Z, np.float32), np.full(len(Z), role, np.int8))))(role)
        bg = background(role)
        attr, sec, _, _ = attributions(f, x, bg, lime_for(role), native_attr, role, e, groups, d)
        nn = nearest_benign(x, role)
        f_x, f_nn, f_med = (float(v) for v in f(np.stack([x, nn, np.median(bg, 0)])))
        row = dict(day=a.day, i=int(a.i), label=a.label, role=ROLE_NAMES[role], score=f_x, f_nn=f_nn, sec_attr=sec)

        # F0: explain.py's median-reset deletion at k = top_k (for comparison with F1)
        den0 = f_x - f_med if f_x - f_med >= 0.5 else np.nan
        k0 = e["top_k"]
        Z, tags = [], []
        for m in ATTR:
            z = x.copy(); ix = X.top(attr[m], k0); z[ix] = np.median(bg, 0)[ix]; Z.append(z); tags.append(("F0", m))
        for r in range(N_RANDOM):
            z = x.copy(); ix = rs.choice(d, k0, replace=False); z[ix] = np.median(bg, 0)[ix]; Z.append(z); tags.append(("F0", "random"))
        # F1: realistic replacement from the nearest benign flow, AOPC over k = 1..KMAX
        orders = {m: np.argsort(-np.abs(attr[m])) for m in ATTR}
        orders.update({f"random{r}": rs.permutation(d) for r in range(N_RANDOM)})
        for m, o in orders.items():
            for k in range(1, KMAX + 1):
                z = x.copy(); z[o[:k]] = nn[o[:k]]; Z.append(z); tags.append(("F1", m))
        # F2: replace the top-ranked modality vs each other modality
        mod_rank = {m: np.argsort(-np.array([np.abs(attr[m])[mod_of == g].sum() for g in range(len(mods))])) for m in ATTR}
        mod_rank["G"] = np.argsort(-attr["G"])
        for g in range(len(mods)):
            z = x.copy(); z[groups[g]] = nn[groups[g]]; Z.append(z); tags.append(("F2", g))
        # C: counterfactual - replace features in attribution order (most score-raising first) until below threshold
        cf = {m: np.argsort(-attr[m]) for m in ["shap", "lime", "native"]}
        cf["diff"] = np.argsort(-np.abs(x - nn))
        for m, o in cf.items():
            for k in range(1, d + 1):
                z = x.copy(); z[o[:k]] = nn[o[:k]]; Z.append(z); tags.append(("C", m))
        vals = f(np.stack(Z))
        tag = pd.DataFrame(tags, columns=["chk", "m"]); tag["v"] = vals

        rd = tag[(tag.chk == "F0") & (tag.m == "random")].v.mean()
        for m in ATTR:
            row[f"F0_{m}"] = (f_x - tag[(tag.chk == "F0") & (tag.m == m)].v.iloc[0]) / den0
        row["F0_random"] = (f_x - rd) / den0
        den1 = f_x - f_nn if f_x - f_nn >= 0.5 else np.nan
        aopc = lambda m: float(np.mean(f_x - tag[(tag.chk == "F1") & (tag.m == m)].v.values)) / den1
        for m in ATTR:
            row[f"F1_{m}"] = aopc(m)
        row["F1_random"] = float(np.mean([aopc(f"random{r}") for r in range(N_RANDOM)]))
        f2 = tag[tag.chk == "F2"].v.values
        for m in ATTR + ["G"]:
            top_g = mod_rank[m][0]
            row[f"F2_{m}"] = (f_x - f2[top_g]) / den1
            row[f"F2_{m}_random"] = float(np.mean([(f_x - f2[g]) / den1 for g in range(len(mods)) if g != top_g]))
            row[f"top_mod_{m}"] = mods[top_g]
        for m in cf:
            v = tag[(tag.chk == "C") & (tag.m == m)].v.values
            hit = np.where(v <= thr)[0]
            row[f"C_{m}"] = float(hit[0] + 1) if f_nn <= thr and len(hit) else np.nan
        exp = EXPECTED.get(a.label)
        if exp:
            row["P_chance"] = len(exp) / len(mods)
            for m in ATTR + ["G"]:
                row[f"P_{m}"] = float(row[f"top_mod_{m}"] in exp)
        rows.append(row)
        for m in ATTR + ["G"]:
            store[m].append(attr[m])
        store["x"].append(x); store["score"].append(f_x)
        if n % 10 == 0:
            log.info("[%s] %d/%d alerts (%.1fs attribution)", method, n + 1, len(alerts), sec)

    per = pd.DataFrame(rows)
    A = {k: np.asarray(v) for k, v in store.items()}

    # R: randomised model, same alerts, same backgrounds-by-seed
    if not args.no_random:
        rscore, rnative, _ = build_scorer(cfg, method, d, tr, va, randomised=True)
        rs_bg = np.random.RandomState(cfg["data"]["seed"])
        for j, a in alerts.iterrows():
            t = tests[a.day]
            x, role = t["X"][a.i].astype(np.float32), int(t["role"][a.i])
            f = (lambda role: (lambda Z: rscore(np.asarray(Z, np.float32), np.full(len(Z), role, np.int8))))(role)
            m_ = va["role"] == role
            bgp = va["X"][m_] if m_.sum() >= e["background_size"] else va["X"]
            bg = bgp[rs_bg.choice(len(bgp), min(e["background_size"], len(bgp)), replace=False)]
            ra, _, _, _ = attributions(f, x, bg, lime_for(role), rnative, role, e, groups, d)
            for m in ATTR + ["G"]:
                rho = spearmanr(np.abs(A[m][j]), np.abs(ra[m])).correlation
                per.loc[j, f"R_{m}"] = rho if np.isfinite(rho) else 1.0 if np.allclose(np.abs(A[m][j]), np.abs(ra[m])) else 0.0
            if j % 20 == 0:
                log.info("[%s] randomised %d/%d", method, j + 1, len(alerts))

    out = args.out
    per.to_csv(out / f"per_alert_{method}.csv", index=False)
    np.savez_compressed(out / f"attributions_{method}.npz", label=per.label.values, **A)

    # summary with bootstrap CIs over alerts
    summ = []
    add = lambda chk, m, v, crit, passed: summ.append(dict(method=method, check=chk, attribution=m, mean=v[0], lo=v[1], hi=v[2],
                                                            criterion=crit, passed=passed if np.isfinite(v[0]) else None))
    for m in ATTR:
        add("F0 median-reset deletion (k=top_k) - random", m, boot_ci(per[f"F0_{m}"] - per["F0_random"], rs_boot),
            "CI > 0", None)
        v = boot_ci(per[f"F1_{m}"] - per["F1_random"], rs_boot)
        add("F1 realistic AOPC - random", m, v, "CI > 0", bool(v[1] > 0))
    for m in ATTR + ["G"]:
        v = boot_ci(per[f"F2_{m}"] - per[f"F2_{m}_random"], rs_boot)
        add("F2 top-modality deletion - random", m, v, "CI > 0", bool(v[1] > 0))
    for m in ["shap", "lime", "native", "diff"]:
        c = per[f"C_{m}"]
        summ.append(dict(method=method, check="C counterfactual size (median features)", attribution=m,
                         mean=float(c.median()), lo=float((c <= 10).mean()), hi=float(c.notna().mean()),
                         criterion="lo = share within 10 features, hi = share reached at all", passed=None))
    att = per[per.label.isin(EXPECTED)]
    if len(att):
        chance = float(att["P_chance"].mean())
        for m in ATTR + ["G"]:
            v = boot_ci(att[f"P_{m}"], rs_boot)
            add("P plausibility (top modality expected)", m, v, f"CI lo > chance {chance:.2f}", bool(v[1] > chance))
    if "R_shap" in per:
        for m in ATTR + ["G"]:
            v = boot_ci(per[f"R_{m}"], rs_boot)
            add("R Spearman trained vs randomised", m, v, "mean < 0.5", bool(v[0] < 0.5))
    return per, A, pd.DataFrame(summ)


def simulatability(method, per, A, mods):
    """S: 5x5 repeated stratified CV; macro-F1 for attack type (types with >= 5 alerts), ROC-AUC for attack vs false alarm."""
    lab = per.label.values
    norm = lambda M: M / np.maximum(np.abs(M).sum(1, keepdims=True), 1e-12)
    d = A["x"].shape[1]
    inputs = {"score only": A["score"][:, None], "random": np.random.RandomState(0).randn(len(lab), d),
              "features x": A["x"], "G (modality Shapley)": norm(A["G"])}
    for m in ATTR:
        inputs[m] = norm(A[m])
    out = []
    keep = pd.Series(lab).map(pd.Series(lab).value_counts()) >= 5
    multi = keep.values & (lab != "Benign")
    binary = lab != "Benign"
    for name, Xin in inputs.items():
        clf = make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, class_weight="balanced"))
        res = {}
        for task, mask, y in [("attack type macro-F1", multi, lab[multi] if multi.any() else None),
                              ("attack vs false alarm ROC-AUC", np.ones(len(lab), bool), binary.astype(int))]:
            if y is None or len(set(y)) < 2 or min(pd.Series(y).value_counts()) < 5:
                res[task] = (np.nan, np.nan); continue
            Xm, sc = Xin[mask], []
            for trn, tst in RepeatedStratifiedKFold(n_splits=5, n_repeats=5, random_state=0).split(Xm, y):
                clf.fit(Xm[trn], y[trn])
                if task.startswith("attack type"):
                    sc.append(f1_score(y[tst], clf.predict(Xm[tst]), average="macro"))
                else:
                    sc.append(roc_auc_score(y[tst], clf.predict_proba(Xm[tst])[:, 1]))
            res[task] = (float(np.mean(sc)), float(np.std(sc)))
        for task, (mu, sd) in res.items():
            out.append(dict(method=method, task=task, input=name, mean=mu, std=sd))
    df = pd.DataFrame(out)
    if df["mean"].isna().all():
        df["passed"] = None
        return df
    for task in df.task.unique():
        floor = df[(df.task == task) & (df.input == "score only")].iloc[0]
        bar = floor["mean"] + 2 * floor["std"]
        df.loc[df.task == task, "passed"] = df[df.task == task]["mean"] > bar
    return df


def report(out, summ, sim, counts_note):
    with open(out / "E10_report.md", "w", encoding="utf-8") as fh:
        fh.write("# E10: extended explanation evaluation (RQ3)\n\n")
        fh.write("Pre-registered in `results_comparison/PREREGISTRATION.md` (E10). Means with 95% bootstrap CIs over alerts.\n\n")
        fh.write(counts_note + "\n\n")
        for m, g in summ.groupby("method", sort=False):
            fh.write(f"## {m}\n\n| check | attribution | mean | 95% CI | criterion | passed |\n|---|---|---|---|---|---|\n")
            for _, r in g.iterrows():
                fh.write(f"| {r.check} | {r.attribution} | {r['mean']:.3f} | [{r.lo:.3f}, {r.hi:.3f}] | {r.criterion} | "
                         f"{'' if r.check.startswith(('F0', 'C ')) else 'not evaluable' if pd.isna(r['mean']) else 'yes' if r.passed in (True, 'True') else '**no**'} |\n")
            s = sim[sim.method == m]
            if len(s):
                fh.write("\nSimulatability (S), 5x5 repeated stratified CV, logistic regression:\n\n"
                         "| task | input | mean | std | > score-only + 2 std |\n|---|---|---|---|---|\n")
                for _, r in s.iterrows():
                    fh.write(f"| {r.task} | {r.input} | {r['mean']:.3f} | {r['std']:.3f} | "
                             f"{'not evaluable' if pd.isna(r['mean']) else 'yes' if r.passed in (True, 'True') else 'no'} |\n")
            fh.write("\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "config_cic2017_monday.yaml"))
    ap.add_argument("--methods", nargs="+", default=METHODS)
    ap.add_argument("--per-type", type=int, default=15)
    ap.add_argument("--n-benign", type=int, default=30)
    ap.add_argument("--no-random", action="store_true", help="skip check R (model randomisation)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    cfg = load_config(args.config)
    args.out = Path(args.out) if args.out else cfg["paths"]["results_dir"] / "xai_eval"
    args.out.mkdir(parents=True, exist_ok=True)
    fs = load_feature_space(cfg)
    tr, va = load_split(cfg, "train"), load_split(cfg, "val")
    tests = {day: load_split(cfg, f"test_{day}") for day in cfg["data"]["test_days"]}
    rs_boot = np.random.RandomState(0)
    summs, sims, notes = [], [], []
    for method in args.methods:
        t0 = time.time()
        per, A, summ = evaluate_method(cfg, method, fs, tr, va, tests, args, rs_boot)
        summs.append(summ)
        sims.append(simulatability(method, per, A, list(fs.slices)))
        notes.append(f"- {method}: {len(per)} alerts ({per.label.value_counts().to_dict()}), {time.time() - t0:.0f} s")
        pd.concat(summs).to_csv(args.out / "summary.csv", index=False)
        pd.concat(sims).to_csv(args.out / "simulatability.csv", index=False)
        report(args.out, pd.concat(summs), pd.concat(sims), "\n".join(notes))
        log.info("[%s] done in %.0f s", method, time.time() - t0)


if __name__ == "__main__":
    main()
