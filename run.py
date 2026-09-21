"""Pipeline entry point.

    python run.py prepare     # clean CSVs, chronological split, feature space
    python run.py train       # SSL models, ablations and baselines -> score files
    python run.py evaluate    # metrics, per-attack recall, latency, plots
    python run.py explain     # SHAP / LIME / native attribution for top alerts
    python run.py compare --capture-dir <dir> --day <day> --attacker <ip>   # vs Suricata/Zeek on a pcap
    python run.py all
"""
import argparse
import sys

from ids_pipeline.schema import DataError
from ids_pipeline.utils import ConfigError, load_config, set_seed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["prepare", "train", "evaluate", "explain", "compare", "all"])
    ap.add_argument("--config", default=None)
    ap.add_argument("--method", help="explain: model to explain (default ssl_mm_role)")
    ap.add_argument("--only", nargs="*", help="train only these methods")
    ap.add_argument("--capture-dir", help="compare: folder with suri/ and zeek/ outputs of docker_ids.sh")
    ap.add_argument("--day", help="compare: test day the capture belongs to")
    ap.add_argument("--attacker", help="compare: attacker IP")
    args = ap.parse_args()
    cfg = load_config(args.config)
    set_seed(cfg["data"]["seed"])
    if args.method:
        cfg["explain"]["method"] = args.method
    stages = ["prepare", "train", "evaluate", "explain"] if args.stage == "all" else [args.stage]
    for s in stages:
        if s == "prepare":
            from ids_pipeline.data import prepare
            prepare(cfg)
        elif s == "train":
            from ids_pipeline.train import run_train
            run_train(cfg, args.only)
        elif s == "evaluate":
            from ids_pipeline.evaluate import run_evaluate
            run_evaluate(cfg)
        elif s == "compare":
            from pathlib import Path

            from ids_pipeline.signature_compare import run_compare
            run_compare(cfg, Path(args.capture_dir), args.day, args.attacker)
        elif s == "explain":
            from ids_pipeline.explain import run_explain
            run_explain(cfg)


if __name__ == "__main__":
    try:
        main()
    except (ConfigError, DataError) as e:
        sys.exit(f"error: {e}")
