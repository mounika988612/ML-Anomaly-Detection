# Suricata2017: provenance and rebuild from the official CIC-IDS2017 pcaps

## Why the dataset is rebuilt

The results in `results_suricata2017*/` use `yasirchemmakh/Cicids2017_Suricata_Logs` (Hugging Face). That dataset has no README, no
author or paper, no Suricata version or rule set, no licence and no description of how CIC labels were matched to Suricata flows.
Inspecting the parquet (`external/suricata2017/suricata2017_all.parquet`, 1,668,626 rows) shows problems beyond the missing documentation:

| check | HF parquet | what CIC-IDS2017 documents |
|---|---|---|
| Thursday web attacks | 13 SQL Injection flows; no Brute Force, no XSS | Brute Force 09:20-10:00, XSS 10:15-10:35, SQLi 10:40-10:42 |
| Thursday "Portscan" | 60,336 flows | no port-scan attack on Thursday (the infiltrated host scans the LAN, labelled Infiltration) |
| Heartbleed | 1 flow | 20-minute attack |
| Suricata alerts on BENIGN flows | 0 of 1,177,087 (0.00%) | ET Open always fires INFO/POLICY rules on normal enterprise traffic |
| alerted flows that are attacks | 735 of 735 | |
| ICMP flows | none | present in the pcaps |

Zero alerts on 1.18M benign flows cannot occur naturally. Either benign flows with alerts were removed, or labels were derived partly
from alerts. In both cases the Suricata signature baseline (`sig`) had perfect precision by construction, and the row count (1.67M vs
~2.8M CIC flows) shows unexplained filtering. None of this can be defended, so the dataset is rebuilt from the original pcaps.

## What the rebuild does

1. **Suricata on the official pcaps.** `scripts/cic2017_suricata.sh` runs Suricata 8.0.7 (Docker image pinned by digest) on each
   `<Day>-WorkingHours.pcap`. One ET Open rule file is downloaded once and reused for all five days (its sha256 and fetch date are recorded).
   `HOME_NET = 192.168.10.0/24` (the testbed LAN), checksum validation off (`-k none`), memcaps raised so no state is lost
   (`flow.memcap`, `tcp.segment_memcap_drop` are checked in the audit). Optionally Zeek 9.0.0 on the same pcap (`--zeek`) as a second sensor.
2. **Flow table.** `scripts/build_suricata2017.py` groups every eve.json event by Suricata `flow_id` (flow, dns, http, fileinfo, tls,
   ssh, ftp, anomaly) into one row per flow, in the schema of the HF parquet, so `adapters/suricata2017.py` and the analyst report read
   it unchanged. Nothing is filtered: every Suricata flow is a row, except the unexplained attacker-pair flows described below.
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

Download the five pcaps from the CIC page above (registration form; ~51 GB; about 20 GB more for eve.json). Then, from `anomaly_pipeline/` (Git Bash/WSL):

```bash
P=/path/to/CIC-IDS-2017/PCAPs
for d in Monday Tuesday Wednesday Thursday Friday; do
  f=$(ls $P | grep -i "^$d-") && bash scripts/cic2017_suricata.sh "$P/$f" $d ../external/cic2017 --zeek
  python scripts/build_suricata2017.py --root ../external/cic2017 --days $d     # flows.parquet per day; eve.json can then be deleted
done
python scripts/build_suricata2017.py --root ../external/cic2017 [--cic-csv-dir /path/to/TrafficLabelling]
python run.py --config config_suricata2017_rebuilt.yaml all
python run.py --config config_suricata2017_rebuilt_context.yaml all
```
Output: `../external/cic2017/suricata2017_rebuilt.parquet`, `manifest.json`, `LABEL_AUDIT.md`. The `*_rebuilt*` configs use their own
work and result directories; the HF results stay where they are for comparison. Tests: `tests/test_build_suricata2017.py`.

## Checks before using the data

Read `LABEL_AUDIT.md`, section by section:
1. **Provenance.** `flow.memcap`, `tcp.segment_memcap_drop`, `detect.alert_queue_overflow` are 0 on every day, and every day has the same rules sha256.
2. **Counts.** Every scheduled attack has flows. Suricata and Zeek counts for the same rule agree in size (they define flows differently, so not exactly).
3. **Per row.** The first and last labelled flows of each attack lie inside the window, and `in_pad` is small. Many pad-zone flows mean the window is too narrow.
   Destination ports match the attack (FTP-Patator 21, SSH-Patator 22, Heartbleed 444, web and DoS attacks 80).
4. **Who talks to the victim.** The scheduled pair dominates each window. A large unscheduled pair means the attacker address is wrong.
5. **Dropped flows.** A few scattered flows are fine. A cluster next to a window means the window must be widened, and the widening must be documented.
6. **Alerts.** BENIGN has a non-zero ET alert rate (unlike the HF data). This is expected, and it is the honest false-positive rate of the signature baseline.
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
the documented window and comes from the documented attacker. I replaced the Hugging Face version because its provenance was undocumented
and its labels were inconsistent with CIC's documentation: web attacks were missing, there was a port scan on the wrong day, and no benign
flow carried a single alert."
