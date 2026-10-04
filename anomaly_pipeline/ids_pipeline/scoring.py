"""Turns raw anomaly components into one calibrated score, optionally per asset role."""
import numpy as np
import torch

from .features import N_ROLES

_EPS = 1e-8


def tail_score(s, ref, presorted=False):
    """-log of the empirical upper-tail probability of each score among benign reference scores."""
    r = ref if presorted else np.sort(ref)
    return -np.log((len(r) - np.searchsorted(r, s, "right") + 1) / (len(r) + 1))


def tail_score_ext(s, ref, presorted=False, q=0.99):
    """tail_score without the ceiling: above the q-quantile of the benign reference the empirical tail (which stops at
    -log(1/(n+1))) is replaced by an exponential tail fitted to the reference scores above that quantile (mean excess).
    Identical to tail_score up to the quantile. Used only to explain alerts (explain._ensemble_scorer), where a saturated
    score cannot show which features drive it."""
    r = ref if presorted else np.sort(ref)
    s = np.asarray(s, np.float64)
    out = tail_score(s, r, presorted=True)
    k = int(q * len(r))
    u = r[k]
    excess = r[k:] - u
    scale = excess.mean() if excess.mean() > 0 else 1.0
    hi = s > u
    out[hi] = -np.log((len(r) - k) / (len(r) + 1)) + (s[hi] - u) / scale
    return out


def min_p(parts, refs):
    """min-p fusion: the view with the smallest tail probability decides (max of -log p)."""
    return np.max([tail_score(s, r) for s, r in zip(parts, refs)], 0)


def _robust_stats(v):
    med = np.median(v)
    return med, 1.4826 * np.median(np.abs(v - med)) + 1e-6


class Calibrator:
    """Robust z-score of log(component) fitted on benign validation flows.

    role_aware=True keeps separate (median, MAD) per role, falling back to the global statistics
    for roles with fewer than `min_n` validation flows; per-role scale is floored at
    `min_scale_ratio` x the global scale. This is what makes the same absolute
    reconstruction error 'normal' for one asset class and 'anomalous' for another.
    """

    def __init__(self, xmodal_weight=0.5, role_aware=True, min_n=500, min_scale_ratio=0.5):
        self.w, self.role_aware, self.min_n = xmodal_weight, role_aware, min_n
        self.min_scale_ratio = min_scale_ratio

    def fit(self, comps, roles):
        self.keys = ["rec"] + (["xmod"] if self.w > 0 and comps["xmod"].max() > 0 else [])
        self.stats = {}
        for k in self.keys:
            v = np.log(comps[k] + _EPS)
            g = _robust_stats(v)
            table = np.tile(np.array(g), (N_ROLES, 1))
            if self.role_aware:
                for r in range(N_ROLES):
                    m = roles == r
                    if m.sum() >= self.min_n:
                        med, scale = _robust_stats(v[m])
                        # floor: a role with near-identical benign flows must not get a vanishing scale
                        table[r] = (med, max(scale, self.min_scale_ratio * g[1]))
            self.stats[k] = table
        return self

    def transform(self, comps, roles):
        s = 0.0
        for k in self.keys:
            med, mad = self.stats[k][roles.astype(int)].T
            z = (np.log(comps[k] + _EPS) - med) / mad
            s = s + z * (1.0 if k == "rec" else self.w)
        return s.astype(np.float32)


class LatentKNN:
    """Latent-space anomaly score: mean distance of a flow's embedding to its k nearest benign training embeddings.

    per_role=True searches only among benign flows of the same service role (role-aware behavioural
    baseline, objective 4); roles with fewer than `min_ref` benign reference flows fall back to the global
    reference set. per_role=False is a single global baseline. Fitted on benign training data only.
    """

    def __init__(self, k=5, n_ref=10000, n_ref_role=5000, per_role=True, min_ref=500, seed=0):
        self.k, self.n_ref, self.n_ref_role, self.per_role, self.min_ref, self.seed = k, n_ref, n_ref_role, per_role, min_ref, seed

    def fit(self, emb, roles):
        rs = np.random.RandomState(self.seed)
        pick = lambda ix, n: ix if len(ix) <= n else ix[rs.choice(len(ix), n, replace=False)]
        self.ref = torch.from_numpy(emb[pick(np.arange(len(emb)), self.n_ref)])
        self.role_ref = {}
        if self.per_role:
            for r in range(N_ROLES):
                ix = np.where(roles == r)[0]
                if len(ix) >= self.min_ref:
                    self.role_ref[r] = torch.from_numpy(emb[pick(ix, self.n_ref_role)])
        return self

    def _dist(self, e, ref, bs=4096):
        out = [torch.cdist(torch.from_numpy(e[i:i + bs]), ref).topk(self.k, largest=False).values.mean(1).numpy()
               for i in range(0, len(e), bs)]
        return np.concatenate(out)

    def distances(self, emb, roles):
        out = np.zeros(len(emb), np.float32)
        for r in np.unique(roles):
            m = roles == r
            out[m] = self._dist(emb[m], self.role_ref.get(int(r), self.ref))
        return out


class TailEnsemble:
    """`ssl_mm_ensemble` (E9 selection C5, PREREGISTRATION.md): per seed, min-p of the role-aware latent-kNN score and the
    min-p fusion of the single-modality experts; then the mean over seeds. Every level works on tail scores
    (-log upper-tail probability among that level's own benign validation scores), so tied benign scores cannot dominate.
    fit/transform take one dict {score name: raw score array} per seed, aligned row by row."""

    def __init__(self, knn="ssl_mm_role_knn", experts=()):
        self.knn, self.experts = knn, list(experts)

    def _seed(self, raw, ref, fit, extrapolate=False):
        t = tail_score_ext if extrapolate else tail_score
        tk = t(raw[self.knn], ref[self.knn], presorted=True)
        te = np.max([t(raw[p], ref[p], presorted=True) for p in self.experts], 0)
        if fit:
            ref["_experts"] = np.sort(te)
        c = np.maximum(tk, t(te, ref["_experts"], presorted=True))
        if fit:
            ref["_minp"] = np.sort(c)
        return t(c, ref["_minp"], presorted=True)

    def fit(self, val_members):
        self.refs = [{k: np.sort(np.asarray(v, np.float64)) for k, v in m.items()} for m in val_members]
        for m, ref in zip(val_members, self.refs):
            self._seed({k: np.asarray(v, np.float64) for k, v in m.items()}, ref, fit=True)
        return self

    def transform(self, members, extrapolate=False):
        """extrapolate=True: the unsaturated score for explanations (tail_score_ext); same value below each level's 99th percentile"""
        return np.mean([self._seed({k: np.asarray(v, np.float64) for k, v in m.items()}, ref, fit=False, extrapolate=extrapolate)
                        for m, ref in zip(members, self.refs)], 0).astype(np.float32)
