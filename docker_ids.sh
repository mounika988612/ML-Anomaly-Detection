#!/bin/bash
# Run Suricata (Emerging Threats Open rules) and Zeek offline on a CSE-CIC-IDS2018 pcap using Docker.
# usage: ./docker_ids.sh <capture-dir>      (capture-dir contains pcap/<victim capture file>)
# Fetch a single victim capture without downloading the 47 GB day archive:
#   python -c "from remotezip import RemoteZip; RemoteZip('https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Original%20Network%20Traffic%20and%20Log%20data/Thursday-22-02-2018/pcap.zip').extract('pcap/UCAP172.31.69.28', '<capture-dir>')"
set -e
DIR="$(cygpath -w "$(cd "$1" && pwd)" 2>/dev/null || (cd "$1" && pwd))"
PCAP=$(ls "$1"/pcap | head -1)
mkdir -p "$1/suri" "$1/zeek"
export MSYS_NO_PATHCONV=1
docker run --rm --entrypoint /bin/sh -v "$DIR:/data" jasonish/suricata:latest -c \
  "suricata-update -q; suricata -r /data/pcap/$PCAP -l /data/suri -k none"
docker run --rm -v "$DIR:/data" -w /data/zeek zeek/zeek:latest \
  zeek -C -r /data/pcap/$PCAP local protocols/ssh/detect-bruteforcing protocols/ftp/detect-bruteforcing
