#!/bin/bash
cd "/d/Thesis source code/anomaly_pipeline"
until grep -q "^config.yaml exit" logs/status.txt 2>/dev/null; do sleep 15; done
python -u run.py --config config.yaml compare --capture-dir ../external/pcap/thu22 --day Thursday-22-02-2018 --attacker 18.218.115.60 > logs/compare_thu22.log 2>&1
echo "compare exit=$?" >> logs/status.txt
