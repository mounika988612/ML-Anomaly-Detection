#!/bin/bash
# retrain only the neural models (baselines are unchanged) and add their latent-kNN variants
cd "$(dirname "$0")"
for cfg in config_suricata2017 config_unsw config config_multiday; do
  work=$(python -c "from ids_pipeline.utils import load_config; print(load_config('$cfg.yaml')['paths']['work_dir'])")
  names=$(ls "$work"/models/*.pkl | xargs -n1 basename | sed 's/.pkl//' | tr '\n' ' ')
  python -u run.py --config $cfg.yaml train --only $names > logs/knn_${cfg}_train.log 2>&1 && \
  python -u run.py --config $cfg.yaml evaluate > logs/knn_${cfg}_eval.log 2>&1
  echo "knn $cfg exit=$?" >> logs/status.txt
done
echo KNNDONE2 >> logs/status.txt
