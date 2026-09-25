import numpy as np

from ids_pipeline.features import FeatureSpace, add_context_features, assign_roles, raw_columns
from ids_pipeline.scoring import Calibrator, LatentKNN


def test_feature_space_state_roundtrip(benign):
    fs = FeatureSpace(8.0).fit(benign)
    fs2 = FeatureSpace.from_state(fs.get_state())
    x1, r1 = fs.transform(benign.head(100))
    x2, r2 = fs2.transform(benign.head(100))
    np.testing.assert_allclose(x1, x2, rtol=0, atol=1e-6)
    assert (r1 == r2).all() and fs2.slices == fs.slices


def test_constant_columns_dropped_and_not_required(benign):
    fs = FeatureSpace().fit(benign)
    assert "Bwd URG Flags" not in fs.names
    assert "Bwd URG Flags" not in fs.required_columns()
    assert {"Dst Port", "Protocol"} <= set(fs.required_columns())


def test_transform_clips_extremes(benign):
    fs = FeatureSpace(8.0).fit(benign)
    x, _ = fs.transform(benign.head(10) * 1e9)
    assert np.abs(x).max() <= 8.0 and np.isfinite(x).all()


def test_raw_columns_maps_protocol():
    assert raw_columns(["proto_tcp", "Flow Duration"]) == ["Dst Port", "Flow Duration", "Protocol"]


def test_role_assignment():
    r = assign_roles(np.array([80, 22, 53, 3306, 5000, 60000, 10]))
    assert r.tolist() == [0, 1, 3, 5, 7, 8, 6]


def test_latent_knn_far_points_score_higher():
    rs = np.random.RandomState(0)
    ref, roles = rs.normal(size=(2000, 4)).astype(np.float32), rs.randint(0, 2, 2000).astype(np.int8)
    knn = LatentKNN(k=5, min_ref=100).fit(ref, roles)
    near = knn.distances(rs.normal(size=(50, 4)).astype(np.float32), np.zeros(50, np.int8))
    far = knn.distances((rs.normal(size=(50, 4)) + 10).astype(np.float32), np.zeros(50, np.int8))
    assert far.min() > near.max()


def test_calibrator_centres_validation_scores():
    rs = np.random.RandomState(0)
    comps = {"rec": rs.lognormal(size=5000), "xmod": np.zeros(5000)}
    roles = np.zeros(5000, np.int8)
    s = Calibrator(0.0, False).fit(comps, roles).transform(comps, roles)
    assert abs(np.median(s)) < 1e-3


def test_context_features_match_brute_force(benign):
    rs = np.random.RandomState(0)
    df = benign.head(600).assign(ts=np.sort(rs.randint(0, 300, 600)).astype(float) + 1e6)
    df["Tot Fwd Pkts"] = rs.choice([1.0, 2.0], len(df))          # make repeated flow shapes likely
    for c in ("Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts"):
        df[c] = 1.0
    ctx = add_context_features(df)
    t, p = df["ts"].to_numpy(), df["Dst Port"].to_numpy()
    shape = df[["Dst Port", "Protocol", "Tot Fwd Pkts"]].to_numpy()
    for i in rs.choice(len(df), 40, replace=False):
        win = (t > t[i] - 60) & (t <= t[i])
        same = (shape == shape[i]).all(1)
        assert ctx["ctx_flows_60s"].iat[i] == win.sum()
        assert ctx["ctx_port_flows_1s"].iat[i] == ((t == t[i]) & (p == p[i])).sum()
        assert ctx["ctx_shape_60s"].iat[i] == (win & same).sum()
        prev = t[same & (t < t[i])]
        assert ctx["ctx_shape_gap"].iat[i] == (t[i] - prev.max() if len(prev) else 3600.0)
        assert ctx["ctx_ports_1s"].iat[i] == len(set(p[t == t[i]]))
    fs = FeatureSpace(8.0, context=True).fit(ctx)
    assert "temporal_context" in fs.slices and {"ctx_shape_60s", "ctx_shape_gap"} <= set(fs.names)
    assert FeatureSpace.from_state(fs.get_state()).slices == fs.slices
    assert "temporal_context" not in FeatureSpace(8.0).fit(ctx).slices


def test_fn_mask_removes_duplicate_block_negatives():
    """InfoNCE with fn_mask drops negatives that share a modality block with the anchor: if every flow has the same block b,
    every negative is dropped and the masked loss is 0; if all blocks are distinct, the mask changes nothing."""
    import torch
    from ids_pipeline.models import MultiModalSSL
    mcfg = dict(hidden=8, modality_dim=4, latent_dim=4, role_dim=2, proj_dim=4, mask_ratio=0.0, modality_dropout=0.0,
                contrastive_weight=1.0, temperature=0.2)
    sl = {"a": (0, 3), "b": (3, 5)}
    torch.manual_seed(0)
    x = torch.randn(16, 5)
    x[:, 3:5] = 0.0                                    # block b absent (all zero) for every flow
    ps = [torch.nn.functional.normalize(torch.randn(16, 4), dim=-1) for _ in sl]
    plain = MultiModalSSL(sl, mcfg)._contrast([p.clone() for p in ps], x)
    masked = MultiModalSSL(sl, mcfg, fn_mask=True)._contrast([p.clone() for p in ps], x)
    assert masked.item() == 0.0
    assert plain.item() > 1.0
    x[:, 3:5] = torch.randn(16, 2)                     # all blocks distinct: the mask changes nothing
    assert torch.isclose(MultiModalSSL(sl, mcfg, fn_mask=True)._contrast(ps, x), MultiModalSSL(sl, mcfg)._contrast(ps, x))
