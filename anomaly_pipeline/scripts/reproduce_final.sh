#!/bin/bash
# Regenerate every final thesis result from the saved models and score files (no retraining) and verify that the numbers
# are reproduced. Called by `make reproduce-final` (all steps) or `make reproduce-<step>`.
#
#   bash scripts/reproduce_final.sh [step ...]       steps: prepare eda e7 e9 e10 crossdata x2 e11 e12 e13 x3 x4  (default: all)
#
# Before a step overwrites its outputs, scripts/verify_reproduction.py copies them to reproduce_runs/<timestamp>/before/; at the end
# every regenerated table is compared with that copy (reproduce_runs/<timestamp>/verification.csv). Exit code 1 if any differs.
# Run from Git Bash with the mlenv interpreter: PY=/d/SoftwareTools/Users/maida/anaconda3/envs/mlenv/python.exe (or activate mlenv).
# Total run time about 5 h on a laptop CPU (E10 explanations ~1 h, E12 RF refits ~1.5 h, X2 leakage audit ~1 h).
set -uo pipefail
cd "$(dirname "$0")/.."
P=${PY:-python}
RUN=${RUN:-reproduce_runs/$(date +%Y%m%d_%H%M%S)}
ALL="prepare eda e7 e9 e10 crossdata x2 e11 e12 e13 x3 x4"
STEPS=${*:-$ALL}
mkdir -p "$RUN"
LOG="$RUN/run.log"
FAILED=""

E7_EVAL="ssl_mm_role_knn ssl_mm_global_knn ssl_no_contrastive_knn ssl_only_flow_knn ssl_only_tcp_knn ssl_only_dns_knn ssl_only_http_knn
         ssl_only_session_knn ae_concat ae_concat_knn ae_concat_knnrole iforest pca_recon"
E11_P1="ssl_mm_role_knn ae_concat_knnrole ae_concat iforest pca_recon suricata_signature"

snap() { $P scripts/verify_reproduction.py snapshot "$RUN" "$1" | tee -a "$LOG"; }
run() { echo "+ $*" | tee -a "$LOG"; "$@" >> "$LOG" 2>&1 || { echo "  FAILED: $*" | tee -a "$LOG"; FAILED="$FAILED|$*"; }; }

check_inputs() {
  local missing=0
  for f in ../external/cic2017/suricata2017_rebuilt.parquet ../dataset/CICIDS2018/Thursday-22-02-2018.csv \
           ../dataset/UNSW_NB15/UNSW_NB15_training-set.csv ../dataset/UNSW_NB15/UNSW_NB15_testing-set.csv \
           ../external/cic2017/Tuesday/zeek/notice.log work_cic2017_monday/models/ssl_mm_role.pt \
           results_cic2017_monday/scores/ssl_mm_role_knn.npz results_experts_cic2017_monday/scores/ssl_mm_ensemble.npz \
           results_e11_cic2017_monday/scores/ssl_mm_role_knn.npz; do
    [ -e "$f" ] || { echo "missing input: $f"; missing=1; }
  done
  [ $missing -eq 0 ] || { echo "Inputs are missing: build the dataset (make dataset) or retrain (make retrain-final) first."; exit 2; }
}

step_prepare() {   # processed splits of the protocols whose work folder is a disposable cache (deterministic, identical rows)
  for c in config_cic2017_monday config_suricata2017_rebuilt config_unsw config_multiday_context_clean; do
    w=$($P -c "import sys; sys.path.insert(0,'.'); from ids_pipeline.utils import load_config; print(load_config('$c.yaml')['paths']['work_dir'])")
    if [ -f "$w/processed/feature_space.pkl" ]; then echo "  $c: processed split present" | tee -a "$LOG"
    else run $P -u run.py prepare --config $c.yaml; fi
  done
}
step_eda() { snap eda; for d in cic2018 cic2017 unsw; do run $P -u scripts/eda.py --dataset $d; done; }
step_e7() {
  snap e7
  run $P -u scripts/clean_eval.py --config config_cic2017_monday.yaml --seeds 42 1 2 --ref ssl_mm_role_knn --methods $E7_EVAL --modes fixed adapted --tag _e7
  run $P -u scripts/clean_eval.py --config config_suricata2017_rebuilt.yaml --seeds 42 1 2 --ref ssl_mm_role_knn --methods $E7_EVAL rf_supervised --modes fixed adapted --tag _e7
  run $P -u scripts/e7_report.py --p1 config_cic2017_monday.yaml --p2 config_suricata2017_rebuilt.yaml --tag 5day
}
step_e9() { snap e9; run $P -u scripts/e9_devtest.py dev; run $P -u scripts/e9_devtest.py test --select C5; }
step_e10() { snap e10; run $P -u scripts/xai_eval.py; }
step_crossdata() { snap crossdata; run $P -u scripts/clean_eval.py --config config_multiday_context_clean.yaml --seeds 42 1 2 --boot 200; }
step_x2() { snap x2; for p in unsw cic2017_p1 cic2018_3day_clean; do run $P -u scripts/leakage_audit.py --protocols $p; done; }
step_e11() {
  snap e11
  run $P -u scripts/clean_eval.py --config config_cic2017_monday.yaml --results-dir results_e11_cic2017_monday --seeds 42 1 2 --ref ssl_mm_role_knn --methods $E11_P1 --modes fixed --tag e11
  for p in suricata2017_rebuilt unsw multiday_context_clean; do
    run $P -u scripts/clean_eval.py --config config_$p.yaml --results-dir results_e11_$p --seeds 42 1 2 --ref ssl_mm_role_knn --methods ssl_mm_role_knn rf_supervised --modes fixed --tag e11
  done
  run $P -u scripts/clean_eval.py --config config_multiday_context_clean.yaml --seeds 42 --ref ssl_mm_role_knn --methods ssl_mm_role_knn rf_supervised --modes fixed --tag e11default --boot 200
}
step_e12() { snap e12; run $P -u scripts/e12_lofo.py; }
step_e13() { snap e13; run $P -u scripts/e13_zeek.py; }
step_x3() { snap x3; run $P -u scripts/representation_analysis.py; }
step_x4() { snap x4; run $P -u scripts/error_analysis.py; }

echo "reproduce-final: steps [$STEPS] -> $RUN (log: $LOG)" | tee -a "$LOG"
check_inputs
for s in $STEPS; do
  echo "=== $s  $(date +%T)" | tee -a "$LOG"
  "step_$s"
done
echo "=== verify  $(date +%T)" | tee -a "$LOG"
$P scripts/verify_reproduction.py verify "$RUN" | tee "$RUN/verification.txt"
status=${PIPESTATUS[0]}
[ -z "$FAILED" ] || { echo "Steps with failed commands:${FAILED//|/$'\n'  }"; status=1; }
echo "reproduce-final finished $(date +%T), exit $status"
exit $status
