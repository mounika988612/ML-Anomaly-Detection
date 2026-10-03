"""Shared fixtures: a synthetic CICFlowMeter-style dataset and a tiny trained model bundle.

Everything is generated in-process (no dataset download, seconds on CPU), so the suite runs in CI.
"""
import logging

import numpy as np
import pandas as pd
import pytest

from ids_pipeline.bundle import export_bundle
from ids_pipeline.features import MODALITIES, FeatureSpace
from ids_pipeline.models import MultiModalSSL
from ids_pipeline.models import train_model as fit_model
from ids_pipeline.utils import set_seed

PROTO = {"proto_tcp", "proto_udp", "proto_other"}
FEATURE_COLS = sorted({c for cols in MODALITIES.values() for c in cols if c not in PROTO})
CONSTANT_COLS = {"Bwd URG Flags", "CWE Flag Count"}          # constant in benign traffic -> dropped by the feature space
PORTS = [80, 443, 22, 53, 3306, 40000]


def make_flows(n, seed=0, attack=False):
    """benign flows share a low-rank structure and a per-port scale; attacks blow up every feature."""
    rs = np.random.RandomState(seed)
    latent = rs.normal(size=(n, 3))
    load = np.random.RandomState(123).normal(size=(3, len(FEATURE_COLS)))
    base = np.exp(2.0 + 0.4 * (latent @ load) + 0.1 * rs.normal(size=(n, len(FEATURE_COLS))))
    if attack:
        base = base * rs.uniform(30, 300, size=(n, 1))
    df = pd.DataFrame(base, columns=FEATURE_COLS)
    for c in CONSTANT_COLS:
        df[c] = 0.0
    df["Dst Port"] = rs.choice(PORTS, n)
    df["Protocol"] = rs.choice([6, 17], n, p=[0.8, 0.2])
    df["Flow Duration"] = df["Flow Duration"].abs()
    return df


def small_cfg():
    return dict(
        data=dict(seed=0),
        model=dict(hidden=32, modality_dim=8, latent_dim=8, role_dim=4, proj_dim=8, mask_ratio=0.25,
                   modality_dropout=0.1, contrastive_weight=0.1, temperature=0.2, epochs=12, batch_size=256,
                   lr=0.003, weight_decay=1e-5, patience=3),
        scoring=dict(target_fpr=0.02, xmodal_weight=0.5, min_role_samples=50, knn_k=5, knn_ref=2000, knn_ref_role=1000))


@pytest.fixture(scope="session")
def benign():
    return make_flows(4000, seed=1)


@pytest.fixture(scope="session")
def attacks():
    return make_flows(200, seed=2, attack=True)


@pytest.fixture(scope="session")
def bundle_dir(tmp_path_factory, benign):
    cfg = small_cfg()
    set_seed(0)
    train, val = benign.iloc[:3200], benign.iloc[3200:]
    fs = FeatureSpace(8.0).fit(train)
    xtr, rtr = fs.transform(train)
    xva, rva = fs.transform(val)
    spec = dict(kind="ssl", mods=list(fs.slices), use_role=True, role_aware=True)
    idx, sl = fs.subset(spec["mods"])
    model = MultiModalSSL(sl, cfg["model"], True)
    fit_model(model, xtr[:, idx], rtr, xva[:, idx], rva, cfg["model"], logging.getLogger("test"), tag="test")
    out = tmp_path_factory.mktemp("bundle")
    export_bundle(cfg, out, "ssl_mm_role_knn", fs, spec, idx, model,
                  dict(X=xtr, role=rtr), dict(X=xva, role=rva))
    return out


@pytest.fixture(scope="session")
def detector(bundle_dir):
    from ids_pipeline.service import Detector
    return Detector(bundle_dir)
