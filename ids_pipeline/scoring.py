"""Turns raw anomaly components into one calibrated score, optionally per asset role."""
import numpy as np
import torch

from .features import N_ROLES

_EPS = 1e-8


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
