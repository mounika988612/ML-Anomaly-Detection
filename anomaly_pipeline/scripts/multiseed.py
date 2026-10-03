"""Seed robustness: retrain selected methods with other seeds and report mean +- std over seeds.

    python scripts/multiseed.py --config config_context.yaml --seeds 1 2 3 4
    python scripts/multiseed.py --config config_context.yaml --seeds 1 2 3 4 --summary-only

The config's own run (its `data.seed`, results in `paths.results_dir`) counts as one seed; each extra seed writes to
`<results_dir>_seed<N>/` (scores, metrics, models). The processed split (prepare) is shared, so the spread measures
training randomness (weight init, masking, modality dropout, kNN reference sample, baseline subsamples), not the data split.
Summary: `<results_dir>/multiseed_{overall,recall_per_attack}{,_adapted}.csv`.
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ids_pipeline.evaluate import run_evaluate  # noqa: E402
from ids_pipeline.train import run_train  # noqa: E402
from ids_pipeline.utils import get_logger, load_config, set_seed  # noqa: E402

log = get_logger()
METHODS = ["ssl_mm_flow", "ssl_only_temporal_context", "ssl_mm_role", "ae_concat", "iforest", "pca_recon", "rf_supervised"]
METRICS = ["roc_auc", "pr_auc", "precision", "recall", "f1", "fpr", "mcc", "incident_recall", "false_alerts_per_hour"]


def seed_dir(base, seed):
    return base.parent / f"{base.name}_seed{seed}"


def summarise(base, seeds):
    dirs = {seeds[0]: base, **{s: seed_dir(base, s) for s in seeds[1:]}}
    for sfx in ("", "_adapted"):
        ov, pa = [], []
        for s, d in dirs.items():
            f = d / f"metrics_overall{sfx}.csv"
            if not f.exists():
                log.warning("missing %s", f)
                continue
            ov.append(pd.read_csv(f).assign(seed=s))
            pa.append(pd.read_csv(d / f"recall_per_attack{sfx}.csv").drop(columns="n_flows")
                      .melt(id_vars="attack", var_name="method", value_name="recall").assign(seed=s))
        ov, pa = pd.concat(ov), pd.concat(pa)
        common = set.intersection(*(set(g.method) for _, g in ov.groupby("seed")))      # methods present for every seed
        ov, pa = ov[ov.method.isin(common)], pa[pa.method.isin(common)]
        agg = ov.groupby("method")[[m for m in METRICS if m in ov]].agg(["mean", "std"])
        agg.columns = [f"{m}_{st}" for m, st in agg.columns]
        agg.insert(0, "n_seeds", ov.groupby("method").size())
        agg = agg.sort_values("roc_auc_mean", ascending=False).round(4)
        agg.to_csv(base / f"multiseed_overall{sfx}.csv")
        pat = pa.groupby(["attack", "method"])["recall"].agg(["mean", "std"]).round(4)
        pat.to_csv(base / f"multiseed_recall_per_attack{sfx}.csv")
        show = agg[[c for c in agg.columns if c.split("_")[0] in ("n", "roc", "pr", "recall", "fpr", "mcc")]]
        log.info("\n[%s] mean/std over seeds %s:\n%s", sfx or "fixed", sorted(ov.seed.unique()), show.to_string())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--seeds", type=int, nargs="+", required=True, help="extra seeds (the config's own seed is added)")
    ap.add_argument("--only", nargs="*", default=METHODS)
    ap.add_argument("--summary-only", action="store_true")
    args = ap.parse_args()
    base_cfg = load_config(args.config)
    base, own = base_cfg["paths"]["results_dir"], base_cfg["data"]["seed"]
    extra = [s for s in args.seeds if s != own]
    if not args.summary_only:
        for s in extra:
            cfg = load_config(args.config)
            cfg["data"]["seed"] = s
            out = seed_dir(base, s)
            cfg["paths"]["results_dir"], cfg["paths"]["models_dir"] = out, out / "models"
            out.mkdir(exist_ok=True)
            log.info("########## seed %d -> %s", s, out)
            set_seed(s)
            run_train(cfg, args.only)
            run_evaluate(cfg)
    summarise(base, [own] + extra)


if __name__ == "__main__":
    main()
