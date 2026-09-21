#!/bin/bash
cd "$(dirname "$0")"
mkdir -p logs
for cfg in config_suricata2017.yaml config_unsw.yaml config_multiday.yaml config.yaml; do
  python -u run.py --config $cfg all > logs/${cfg%.yaml}.log 2>&1
  echo "$cfg exit=$?" >> logs/status.txt
done
echo ALLDONE >> logs/status.txt
