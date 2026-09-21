import numpy as np

from ids_pipeline.features import FeatureSpace, assign_roles, raw_columns
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
