import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from xai_eval import group_shapley  # noqa: E402


def test_group_shapley_efficiency_and_additive_case():
    rs = np.random.RandomState(0)
    groups = [np.arange(0, 2), np.arange(2, 5), np.arange(5, 6)]
    x, bg = rs.randn(6), rs.randn(20, 6)
    # additive model: each group's Shapley value is its own contribution relative to the mean background
    w = rs.randn(6)
    f = lambda Z: Z @ w
    phi, v_all, v_none = group_shapley(f, x, bg, groups)
    assert np.isclose(phi.sum(), v_all - v_none)
    for g, idx in enumerate(groups):
        assert np.isclose(phi[g], ((x[idx] - bg[:, idx].mean(0)) * w[idx]).sum())
    # interaction: f = product of two groups' sums is split equally between them
    f2 = lambda Z: Z[:, 0] * Z[:, 2]
    x2, bg2 = np.array([1., 0, 1, 0, 0, 0]), np.zeros((1, 6))
    phi2, _, _ = group_shapley(f2, x2, bg2, groups)
    assert np.allclose(phi2, [0.5, 0.5, 0.0])
