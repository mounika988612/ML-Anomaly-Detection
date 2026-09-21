#!/bin/bash
cd "$(dirname "$0")"
until grep -q ALLDONE logs/status.txt 2>/dev/null; do sleep 20; done
python -u run.py --config config_unsw.yaml all > logs/config_unsw.log 2>&1
echo "config_unsw.yaml(retry) exit=$?" >> logs/status.txt
echo UNSWDONE >> logs/status.txt
