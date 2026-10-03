# CIC-IDS2017 (Suricata telemetry): provenance and build from the official pcaps

## Why the dataset is built from the pcaps

CIC-IDS2017 is the primary dataset of the thesis, used as real multi-source telemetry: Suricata's flow, TCP, DNS, HTTP and
session events per flow. A third-party Suricata version of CIC-IDS2017 (Hugging Face) was used in early experiments and then
withdrawn and deleted (2026-10-03), because its provenance was undocumented and its labels disagreed with CIC's documentation
(see `results_comparison/PREREGISTRATION.md`). The dataset is therefore built here from the official pcaps, with every step
scripted and audited.

## What the rebuild does

1. **Suricata on the official pcaps.** `scripts/cic2017_suricata.sh` runs Suricata 8.0.7 (Docker image pinned by digest) on each
   `<Day>-WorkingHours.pcap`. One ET Open rule file is downloaded once and reused for all five days (its sha256 and fetch date are recorded).
   `HOME_NET = 192.168.10.0/24` (the testbed LAN), checksum validation off (`-k none`), memcaps raised so no state is lost
   (`flow.memcap`, `tcp.segment_memcap_drop` are checked in the audit). Optionally Zeek 9.0.0 on the same pcap (`--zeek`) as a second sensor.
2. **Flow table.** `scripts/build_suricata2017.py` groups every eve.json event by Suricata `flow_id` (flow, dns, http, fileinfo, tls,
   ssh, ftp, anomaly) into one row per flow, in the schema `adapters/suricata2017.py` and the analyst report read. Nothing is filtered: every Suricata flow is a row, except the unexplained attacker-pair flows described below.
   Suricata 8 DNS records (eve v3) are converted to the per-query layout the adapter parses.
3. **Labels from the published attack schedule only.** `docs/cic2017_attack_schedule.csv` lists, per attack: day, attacker IP, victim
   IP(s), start and end (testbed local time, UTC-3), as published at https://www.unb.ca/cic/datasets/ids-2017.html.
   A flow is labelled with an attack if it is between the attacker and the victim (either direction; `fwd` = attacker to victim only)
   and starts inside the window, with the end minute included and 60 s of margin at each end (`--pad`). Every other flow is BENIGN.
   Suricata alerts are never used for labels.
4. **Flows the schedule cannot explain are excluded, not guessed.** A flow between an attacker-only address and its victim
   (`outside_window = drop`) that starts outside every window of that day is removed and counted per 10 minutes in the audit.
5. **Signature baseline.** `alerted` (= `sig`) means at least one ET Open rule fired on the flow. Suricata's own decoder/stream event
   rules (SID 2200000-2299999, e.g. "invalid checksum", which fire on most flows of these captures) are only counted (`n_engine_alerts`).
6. **Audit.** Every build writes `LABEL_AUDIT.md` and `manifest.json` next to the parquet (see "Checks before using the data").

### Addresses at the capture point
The capture is on the LAN side of the firewall. Attacks from outside (Kali 205.174.165.73, Win 8.1 205.174.165.69-71) are NATed by the
firewall and appear with source **172.16.0.1** (the firewall's inside address) against the web server 192.168.10.50 or 192.168.10.51.
Traffic that the victims start themselves (Botnet ARES C&C, Infiltration sessions) goes out to **205.174.165.73** and is recorded with
that address. Section 4 of the audit (who talks to each victim during its window) checks this assumption on the data.

## Reproduce

Download the five pcaps from the CIC page above (registration form; ~52 GB) into `dataset/CICIDS2017/`. Each day's eve.json
needs 1.5-2.5 GB while it is processed. Then, from `anomaly_pipeline/` in Git Bash, with Docker Desktop running (README section 4):

```bash
export PY=/path/to/envs/mlenv/python.exe
for d in Monday Tuesday Wednesday Thursday Friday; do
  bash logs/run_E7.sh sensors $d ../dataset/CICIDS2017/$d-WorkingHours.pcap   # Suricata, flows.parquet, eve.json deleted
done
bash logs/run_E7.sh parquet          # all days -> suricata2017_rebuilt.parquet + LABEL_AUDIT.md (read it before training)
bash logs/run_E7.sh train config_cic2017_monday.yaml config_suricata2017_rebuilt.yaml
```
Output: `../external/cic2017/suricata2017_rebuilt.parquet`, `manifest.json`, `LABEL_AUDIT.md`. Zeek is optional
(`scripts/cic2017_suricata.sh ... --zeek`) and was not used for the thesis results. `scripts/build_suricata2017.py --cic-csv-dir`
adds an optional cross-check against CIC's TrafficLabelling CSVs. Tests: `tests/test_build_suricata2017.py`.

## Checks before using the data

Read `LABEL_AUDIT.md`, section by section:
1. **Provenance.** `flow.memcap`, `tcp.segment_memcap_drop`, `detect.alert_queue_overflow` are 0 on every day, and every day has the same rules sha256.
2. **Counts.** Every scheduled attack has flows. Suricata and Zeek counts for the same rule agree in size (they define flows differently, so not exactly).
3. **Per row.** The first and last labelled flows of each attack lie inside the window, and `in_pad` is small. Many pad-zone flows mean the window is too narrow.
   Destination ports match the attack (FTP-Patator 21, SSH-Patator 22, Heartbleed 444, web and DoS attacks 80).
4. **Who talks to the victim.** The scheduled pair dominates each window. A large unscheduled pair means the attacker address is wrong.
5. **Dropped flows.** A few scattered flows are fine. A cluster next to a window means the window must be widened, and the widening must be documented.
6. **Alerts.** BENIGN has a non-zero ET alert rate (0.71% in the build). This is expected, and it is the honest false-positive rate of the signature baseline.
7. **CIC's own CSVs** (optional `--cic-csv-dir`, TrafficLabelling CSVs with IPs and timestamps): CIC's attack flows use the same pairs and fall in the same windows.

Before the first build, also compare `docs/cic2017_attack_schedule.csv` line by line with the CIC page. It was transcribed from that page, and
it is the only label input.

## Known limitations (state them in the thesis)
- **Time-window labels.** Traffic between the attacker and the victim inside the window is labelled attack, including failed attempts and
  the victim's replies. This is the same unit CIC used. Engelen et al., "Troubleshooting an intrusion detection dataset: the CICIDS2017 case
  study" (IEEE SPW 2021), is the reference for the known CIC labelling issues.
- **Infiltration - Portscan** labels every flow from the infected host 192.168.10.8 to the LAN during 15:04-15:45, so its benign traffic in
  that window (e.g. DNS to 192.168.10.3) is included. The audit lists its destination ports so the effect can be quantified.
- **ET Open rules from 2026 on 2017 traffic** know these attacks in hindsight. The signature baseline is therefore an optimistic upper
  bound for a signature IDS at the time.
- **Suricata flows are not CICFlowMeter flows** (different timeouts and splitting), so counts are not comparable one-to-one with the CIC CSVs.
- **Cool disk (MAC, 192.168.10.25)** is on the schedule but may have little or no network traffic in the capture; the audit shows it.

## Answer for "who made this data and how do you know the labels are correct?"

"I ran Suricata 8.0.7 with a frozen ET Open rule set myself on the official CIC-IDS2017 pcaps from UNB. Every flow Suricata produced is in
the dataset. Labels come only from CIC's published attack schedule, by attacker IP, victim IP and attack time window. Alerts are never used.
The build is scripted, pinned by image digest and file hashes, and the label audit shows for every attack that the traffic falls inside
the documented window and comes from the documented attacker. I did not use a third-party Suricata version of the dataset because its
provenance was undocumented and its labels were inconsistent with CIC's documentation."
