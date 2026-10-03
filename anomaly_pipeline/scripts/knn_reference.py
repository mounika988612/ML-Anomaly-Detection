"""E5 (results_comparison/PREREGISTRATION.md): coverage of the latent-kNN benign reference set, rescored from trained models.

    python scripts/knn_reference.py --config config_context_clean.yaml --variant dedup --models ssl_mm_flow ssl_only_temporal_context

The shipped scorer compares a flow with a random 10k (global) / 5k (per role) sample of benign training embeddings. Many of them are
exact duplicates, and rare-but-benign behaviour is often not sampled at all. Such benign flows then have no near neighbour and form
the benign tail that sets the 1%-FPR threshold. Variants (label-free, benign training data only):
  shipped  random 10k / 5k per role (as train.py)
  dedup    the same sizes drawn from the distinct training embeddings (duplicates removed first)
  full     every distinct training embedding (global and per role)
Writes `<results_dir>_knnref_<variant>/scores/<model>_knn[role].npz` in the saved-score format, so evaluate.collect_scores,
run.py evaluate and scripts/clean_eval.py work on it unchanged (the seed-N results dir is used for --seed N).
"""
import argparse
import pickle
import shutil
import sys
import time
from pathlib import Path

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_pipeline.data import load_split                                  # noqa: E402
from ids_pipeline.models import MLPAutoencoder, MultiModalSSL, batched_embed  # noqa: E402
from ids_pipeline.scoring import Calibrator, LatentKNN                    # noqa: E402
from ids_pipeline.train import _save_scores, _threshold                   # noqa: E402
from ids_pipeline.utils import get_logger, load_config                    # noqa: E402

log = get_logger()


class DistinctKNN(LatentKNN):
    """LatentKNN whose reference is drawn from distinct embeddings; n_ref=None keeps all of them."""

    def fit(self, emb, roles):
        _, first = np.unique(emb.round(5), axis=0, return_index=True)
        first = np.sort(first)
        log.info("  %d of %d training embeddings are distinct", len(first), len(emb))
        return super().fit(emb[first], roles[first])

    def _dist(self, e, ref, bs=None):
        return super()._dist(e, ref, bs=max(64, int(5e7 // len(ref))))     # distance block <= 200 MB for large references


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--variant", choices=["shipped", "dedup", "full"], required=True)
    ap.add_argument("--models", nargs="+", required=True)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()
    cfg = load_config(args.config)
    scfg, seed = cfg["scoring"], args.seed or cfg["data"]["seed"]
    src = cfg["paths"]["results_dir"]
    mdir = cfg["paths"]["work_dir"] / "models"
    if seed != cfg["data"]["seed"]:
        src = src.parent / f"{src.name}_seed{seed}"
        mdir = src / "models"
    out = src.parent / f"{src.name}_knnref_{args.variant}"
    (out / "scores").mkdir(parents=True, exist_ok=True)
    cfg["paths"]["results_dir"] = out
    tr, va = load_split(cfg, "train"), load_split(cfg, "val")
    tests = {d: load_split(cfg, f"test_{d}") for d in cfg["data"]["test_days"]}
    torch.set_num_threads(4)
    for name in args.models:
        with open(mdir / f"{name}.pkl", "rb") as f:
            meta = pickle.load(f)
        spec, idx, sl = meta["spec"], meta["idx"], meta["slices"]
        model = (MultiModalSSL(sl, cfg["model"], spec["use_role"], spec.get("lam"), spec.get("fn_mask", False)) if spec["kind"] == "ssl"
                 else MLPAutoencoder(sl, cfg["model"]))
        model.load_state_dict(torch.load(mdir / f"{name}.pt", map_location="cpu"))
        model.eval()
        emb_tr = batched_embed(model, tr["X"][:, idx], tr["role"])
        emb_va = batched_embed(model, va["X"][:, idx], va["role"])
        emb_te = {d: batched_embed(model, t["X"][:, idx], t["role"]) for d, t in tests.items()}
        variants = [(f"{name}_knn", spec["role_aware"])] + ([(f"{name}_knnrole", True)] if spec["kind"] == "ae" else [])
        for vname, per_role in variants:
            t0 = time.time()
            big = 10 ** 9
            n_ref, n_role = (big, big) if args.variant == "full" else (scfg.get("knn_ref", 10000), scfg.get("knn_ref_role", 5000))
            cls = LatentKNN if args.variant == "shipped" else DistinctKNN
            knn = cls(scfg.get("knn_k", 5), n_ref, n_role, per_role, scfg["min_role_samples"], seed).fit(emb_tr, tr["role"])
            zero = lambda n: np.zeros(n, np.float32)
            vd = knn.distances(emb_va, va["role"])
            kc = Calibrator(0.0, False, scfg["min_role_samples"], scfg.get("min_scale_ratio", 0.5)).fit({"rec": vd, "xmod": zero(len(vd))}, va["role"])
            ks = lambda e, r: kc.transform({"rec": knn.distances(e, r), "xmod": zero(len(e))}, r)
            kval = ks(emb_va, va["role"])
            ktest = {d: ks(emb_te[d], tests[d]["role"]) for d in tests}
            _save_scores(cfg, vname, kval, _threshold(kval, scfg["target_fpr"]), ktest, (time.time() - t0) / len(kval) * 1e6, tests)
            log.info("[%s/%s] reference %d global, %s per role; scored in %.0fs", vname, args.variant, len(knn.ref),
                     {int(r): len(v) for r, v in knn.role_ref.items()}, time.time() - t0)
    for f in ("rf_supervised.npz",):                       # keep evaluate's supervised reference rows available
        if (src / "scores" / f).exists():
            shutil.copy(src / "scores" / f, out / "scores" / f)


if __name__ == "__main__":
    main()
