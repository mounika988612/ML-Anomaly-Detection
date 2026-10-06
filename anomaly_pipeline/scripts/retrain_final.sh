#!/bin/bash
# Retrain every final model from the data (CIC-IDS2017 parquet, CSE-CIC-IDS2018 CSVs, UNSW-NB15 CSVs), then regenerate and verify the
# reports with scripts/reproduce_final.sh. Called by `make retrain-final CONFIRM=1`.
#
# WARNING: this OVERWRITES the results_* and work_* folders whose numbers are reported in the thesis. Training is seeded, so the
# scores should be reproduced, but CPU threading in PyTorch can change the last digits; the verification step at the end reports
# any table that differs from the version that existed before. Run time: about 12-15 h on a laptop CPU.
# Order and commands are those of the original runs (logs/run_E7.sh, README "Fixing the operating point", logs/run_E4c.sh, E11).
set -euo pipefail
cd "$(dirname "$0")/.."
P=${PY:-python}
export PY=$P
[ "${CONFIRM:-0}" = "1" ] || { echo "retrain-final overwrites the reported results; rerun with CONFIRM=1"; exit 2; }
SNAP=reproduce_runs/retrain_$(date +%Y%m%d_%H%M%S)
mkdir -p "$SNAP"
echo "Keeping a copy of the reported tables in $SNAP before retraining"
for s in eda e7 e9 e10 crossdata x2 e11 e12 e13 x3 x4; do $P scripts/verify_reproduction.py snapshot "$SNAP" $s; done

echo "### 1/5 E7: CIC-IDS2017 P1 and P2, seeds 42 1 2 (prepare, train, evaluate, explain, multiseed, bootstrap CIs)"
bash logs/run_E7.sh train config_cic2017_monday.yaml config_suricata2017_rebuilt.yaml

echo "### 2/5 X1 experts + E9 ensemble (fused from the saved scores of the three seeds, no retraining)"
for s in "" _seed1 _seed2; do
  rm -rf results_experts_cic2017_monday$s && cp -r results_cic2017_monday$s results_experts_cic2017_monday$s
  IDS_RESULTS_DIR=results_experts_cic2017_monday$s $P -u run.py train --config config_cic2017_monday.yaml --only ssl_mm_experts
done
IDS_RESULTS_DIR=results_experts_cic2017_monday $P -u run.py train --config config_cic2017_monday.yaml --only ssl_mm_ensemble
IDS_RESULTS_DIR=results_experts_cic2017_monday $P -u run.py evaluate --config config_cic2017_monday.yaml

echo "### 3/5 cross-dataset: UNSW-NB15 and CSE-CIC-IDS2018 3-day clean (E4)"
$P -u run.py all --config config_unsw.yaml
M="ssl_mm_flow ssl_only_temporal_context ae_flow ae_only_temporal_context ssl_mm_role ssl_no_contrastive ae_concat iforest pca_recon rf_supervised"
$P -u run.py prepare --config config_multiday_context_clean.yaml
$P -u run.py train --config config_multiday_context_clean.yaml --only $M
$P -u run.py evaluate --config config_multiday_context_clean.yaml
$P -u scripts/multiseed.py --config config_multiday_context_clean.yaml --seeds 1 2 --only ${M% iforest*}

echo "### 4/5 E11: label-free tuning of every method, RF tuning, final runs with the selected settings"
$P -u scripts/e11_tuning.py select
for c in config_suricata2017_rebuilt.yaml config_unsw.yaml config_multiday_context_clean.yaml; do
  $P -u scripts/e11_tuning.py select-rf --config $c
done
rm -f results_e11_cic2017_monday*/.done_*
$P -u scripts/e11_tuning.py final
for c in config_suricata2017_rebuilt.yaml config_unsw.yaml config_multiday_context_clean.yaml; do
  $P -u scripts/e11_tuning.py final-rf --config $c
done

echo "### 5/5 regenerate and verify every report against the copy taken before retraining"
RUN=$SNAP bash scripts/reproduce_final.sh
