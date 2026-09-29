#!/bin/bash
# Rebuild of the Suricata2017 dataset, step 1: run Suricata (and optionally Zeek) offline on one official CIC-IDS2017
# day pcap (https://www.unb.ca/cic/datasets/ids-2017.html -> PCAPs/<Day>-WorkingHours.pcap).
# usage: scripts/cic2017_suricata.sh <Day-WorkingHours.pcap> <Day> [out-root] [--zeek]
#   out-root defaults to ../external/cic2017; writes <out-root>/rules/ (once, shared by all days) and <out-root>/<Day>/{suri,zeek}
# Step 2: python scripts/build_suricata2017.py --root <out-root>
#
# Pinned for reproducibility: the Suricata image by digest, and one ET Open rule file downloaded on the first run and
# reused for every day (delete <out-root>/rules to refresh it; then rerun all five days).
# HOME_NET is the testbed LAN, so the NATed attacker address 172.16.0.1 counts as external for the ET rules.
set -euo pipefail
PCAP="$1"; DAY="$2"; ROOT="${3:-../external/cic2017}"; ZEEK="${4:-}"
SURI_IMAGE="${SURI_IMAGE:-jasonish/suricata@sha256:7ca2546f7f2735f621b981b6a5ec84fb962984636f7629a1a2fa6a324d4b6840}"   # 8.0.7
ZEEK_IMAGE="${ZEEK_IMAGE:-zeek/zeek:9.0.0}"
win() { cygpath -w "$(cd "$1" && pwd)" 2>/dev/null || (cd "$1" && pwd); }
mkdir -p "$ROOT/rules" "$ROOT/$DAY/suri"
PDIR=$(win "$(dirname "$PCAP")"); PNAME=$(basename "$PCAP"); RDIR=$(win "$ROOT/rules"); ODIR=$(win "$ROOT/$DAY")
export MSYS_NO_PATHCONV=1

if [ ! -s "$ROOT/rules/suricata.rules" ]; then
  docker run --rm --entrypoint /bin/sh -v "$RDIR:/rules" "$SURI_IMAGE" -c \
    "suricata-update -q --no-test --no-reload -o /rules && date -u +%Y-%m-%dT%H:%M:%SZ > /rules/fetched_utc.txt"
fi

docker run --rm --entrypoint /bin/sh -v "$PDIR:/pcap:ro" -v "$RDIR:/rules:ro" -v "$ODIR:/out" "$SURI_IMAGE" -c "
  suricata -V > /out/suri/version.txt
  sha256sum /rules/suricata.rules > /out/suri/rules.sha256
  sha256sum '/pcap/$PNAME' > /out/suri/pcap.sha256
  rm -f /out/suri/eve.json
  suricata -r '/pcap/$PNAME' -l /out/suri -k none -S /rules/suricata.rules \
    --set 'vars.address-groups.HOME_NET=[192.168.10.0/24]' \
    --set stream.memcap=1gb --set stream.reassembly.memcap=2gb --set flow.memcap=1gb"
echo "$SURI_IMAGE" > "$ROOT/$DAY/suri/image.txt"

if [ "$ZEEK" = "--zeek" ]; then
  mkdir -p "$ROOT/$DAY/zeek"
  docker run --rm -v "$PDIR:/pcap:ro" -v "$ODIR:/out" -w /out/zeek "$ZEEK_IMAGE" zeek -C -r "/pcap/$PNAME" local
fi
