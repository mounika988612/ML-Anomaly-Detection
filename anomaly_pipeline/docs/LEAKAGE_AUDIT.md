# Leakage and data-integrity audit (X2; reproduce with `python scripts/leakage_audit.py`)

Post hoc and descriptive (`results_comparison/PREREGISTRATION.md`, X2): written after the E1–E10 test results were known. It changes no
reported number. Every check runs on the model input itself: each protocol's split is rebuilt with the pipeline's own loader, label
exclusions, train/validation cut and feature space. Tables: `results_comparison/leakage_audit/L<n>_<protocol>.csv`.

| protocol | config | train (benign only) | test |
|---|---|---|---|
| CIC-IDS2017 P1 | `config_cic2017_monday.yaml` | Monday | Tue–Fri |
| CSE-CIC-IDS2018 3-day clean | `config_multiday_context_clean.yaml` | Wed-14, Thu-15, Wed-21 | Thu-22, Thu-01, Fri-02 |
| UNSW-NB15 | `config_unsw.yaml` | benign part of the official training set | official test set |

## Verdict

No check found leakage that could inflate the reported results of the unsupervised methods (the SSL model, the AE, iForest, PCA).
Three findings still matter for how the results are read:

1. **UNSW-NB15, supervised RF.** Up to 48% of the test attacks are byte-identical to rows in the labelled training pool, so the RF's
   0.985 ROC-AUC partly reflects memorisation, not generalisation.
2. **CIC-IDS2017, label artefacts.** Many attack-labelled flows are identical to benign Monday flows. These limit the recall any
   flow-level detector can reach, so they push the reported numbers *down*, not up.
3. **CIC-IDS2017, benign repetition.** About 45% of the benign test flows are identical to a benign training flow, which makes the
   false-positive rate easier to keep low than on unfamiliar traffic.

## L1 Split integrity: passed

On CIC-IDS2017 and CSE-CIC-IDS2018, every test day starts after the last training row. On every training day, the validation rows come
after that day's training rows. UNSW-NB15 has no timestamps, so its train/test split is the official one and its validation slice is a
seeded random 15%; this was already stated as a limitation in the README.

## L2 Preprocessing fitted on training data only: passed (P1)

Refitting the feature space on the benign training rows gives exactly the shipped statistics (maximum difference 0.0). The rebuilt test
matrices are byte-identical to the cached `processed/test_*.npz`. The scaler, clipping and constant-column filter therefore see no test
data, and the audit checks what the models were really given.

## L3 / L4 Exact and near duplicates across the split

Each value is the share of test rows whose model input (standardised features + role) also occurs in the benign training period. Near
means a Euclidean distance below 0.1 to the nearest of 200,000 benign training rows.

**CIC-IDS2017 P1**

| test label | identical to benign training | near-identical | identical to a benign *test* flow |
|---|---|---|---|
| Benign | 43–46% per day | 67–72% | – |
| Web Attack – XSS | **95.3%** | 95.3% | 95.7% |
| Web Attack – Brute Force | **88.8%** | 88.9% | 89.1% |
| Infiltration (14 flows) | 71% | 71% | – |
| DoS Slowhttptest | 66.5% | 66.5% | 66.5% |
| Portscan | 0.3% | **50.0%** (median distance 2·10⁻⁷) | 0.3% |
| Infiltration – Portscan | 3.6% | 4.4% | 46.0% |
| DoS Slowloris | 42.5% | 42.5% | 42.4% |
| DoS Hulk, DDoS, GoldenEye, FTP/SSH-Patator, Botnet, SQLi, Heartbleed | ≤ 0.5% | ≤ 1.1% | ≤ 0.5% |

The CIC-IDS2017 labels are time windows: every flow between the scheduled attacker and victim inside the window is labelled as
attack. In the feature space many of those flows are ordinary connections that also occur on Monday. Portscan's near-duplicates
differ from benign flows only by float rounding. This is the same effect `docs/LABEL_AUDIT.md` found for Infiltration in
CSE-CIC-IDS2018. It sets a **recall ceiling** that applies to every detector that judges single flows: at most about 5% for XSS, 11%
for Web Brute Force, 34% for Slowhttptest and 50% for Portscan. Detectors that score identical inputs identically, which includes the
SSL model, the baselines and the Random Forest, cannot separate these flows from benign ones. This deflates recall and ROC-AUC; it
cannot inflate them.

**CSE-CIC-IDS2018 3-day clean**: no test row of any label is identical to a training row. Fewer than 0.1% of benign rows are
near-identical. The reason is the 12 temporal-context features, which describe the traffic around each flow and so differ from day to
day. Within a day, the cleaning step already drops duplicate rows (`data.clean_day`).

**UNSW-NB15**

| test label | identical to benign training | identical to a *labelled* training-pool row (seen by the RF) |
|---|---|---|
| Benign | 3.5% | 4.1% |
| DoS | 0% | **48.0%** |
| Reconnaissance | 0% | **32.1%** |
| Analysis | 0% | 17.9% |
| Exploits | 0% | 15.9% |
| Generic | 0% | 15.0% |
| Fuzzers, Shellcode, Backdoor, Worms | ≤ 0.4% | ≤ 4.2% |

The unsupervised models never see these rows, because they train on benign data only. The supervised RF does: for a large share of
the test attacks, the exact same input was in its training set with the same label. Its UNSW-NB15 result should be described as "same
attack types, partly the same flows", not as generalisation.

## L5 Identifier and label leakage in the features: passed

No model feature on any protocol is an identifier (IP address, port number, Flow ID, timestamp, row id, TCP sequence base) or is
derived from labels or IDS decisions (`Label`, `class`, `truth`, `sig`, `alerted`, `pad_zone`). On CIC-IDS2017 the Suricata alert
events are not parsed into features, and Suricata's decision is kept only as the separate `suricata_signature` baseline. Features
with "port" in the name (CIC-2018 `ctx_port_*`, UNSW `ct_*_dport_ltm` / `ct_*_sport_ltm` / `is_sm_ips_ports`) are counts or flags, not
port numbers. The **service role** is derived from the destination port (UNSW: the `service` field). This is part of the design and is
the only port information the models get.

## L6 Identifier shortcuts (not used, but how strong they would be)

ROC-AUC of each identifier alone, using in-sample target encoding (an optimistic upper bound):

| identifier | CIC-IDS2017 P1 | CSE-CIC-IDS2018 | UNSW-NB15 |
|---|---|---|---|
| Flow ID (5-tuple) | 1.000 | – | – |
| destination IP / source IP | 0.994 / 0.992 | – | – |
| destination port | 0.962 | 0.941 | – |
| minute of day | 0.949 | 0.804 | – |
| service role (**used by the models**) | 0.890 | 0.776 | 0.680 |
| proto / service / state | – | protocol 0.617 | 0.748 / 0.691 / 0.801 |
| raw row `id` | – | – | 0.725 (file order) |

Because the labels come from attacker IPs and time windows, an IP or time feature would make CIC-IDS2017 almost perfectly separable
for any supervised model. That is why no identifier is a feature. The role is used, but only to condition an unsupervised model: the
role embedding, the per-role kNN reference and the per-role calibration all use benign data only. The model therefore cannot learn that
some roles carry more attacks. The role does, however, change which benign flows count as neighbours, which is the intended effect
(H5).

## L7 Session / flow overlap (P1): passed

No attack flow's 5-tuple occurs on Monday, except 2.5% of Infiltration – Portscan. 38% of the benign test 5-tuples do recur on Monday;
these are recurring connections such as DNS and NetBIOS.

## L8 Single-feature artefacts

Over all attacks pooled, no single feature reaches an AUC of 0.95. The best are 0.82 (P1, `proto_udp`), 0.85 (CIC-2018,
`ctx_shape_1s`) and 0.78 (UNSW, `dload`). Per attack type, some single features do separate an attack from all benign traffic:

- **P1:** SSH-Patator by `has_ssh` (0.998), FTP-Patator by `n_ftp` (0.995), Portscan by `bytes_ts` (0.994), DDoS / DoS Hulk by
  `bytes_per_pkt_tc` (0.98–0.99), Botnet by `http_url_len` (0.96). These are the attacks' real behaviour (a login flood *is* SSH
  traffic). They also reflect the testbed, though: there is almost no benign SSH or FTP in the test period, so "uses SSH" alone flags the
  attack. Real networks with a lot of benign SSH would make SSH-Patator harder.
- **CSE-CIC-IDS2018:** Bot by `ctx_shape_60s` (0.976). The bot sends the same beacon again and again, which is exactly what the context
  view was built to catch.
- **UNSW-NB15:** Generic by `ct_dst_sport_ltm` (0.971), Analysis / Backdoor by `proto_other` (0.94). The TTL fields that the
  literature calls a UNSW artefact are weaker here (`ct_state_ttl` 0.77 pooled, `sttl` 0.80 for Fuzzers).

## L9 Future information

- **Temporal context (CSE-CIC-IDS2018):** the counts use trailing windows, and the time since the previous similar flow only looks
  back. Two exceptions: flows within the same second count each other (timestamps have 1-second resolution), and `ctx_ports_10s` uses
  fixed 10-second buckets, so it can include up to 9 seconds of later flows. Compared with a strictly trailing count, the two versions
  have a Spearman correlation of 0.78–0.88, and the per-day attack-vs-benign AUC changes by at most 0.013 (`L9_cic2018_3day_clean.csv`).
  The context is computed over all flows of a day, with labels unused, the same way a sensor would see them.
- **Thresholds:** the fixed threshold is a quantile of benign validation scores, which come from the training period only. The
  `*_adapted` variant recalibrates on the first 30 minutes of each test day, treated as unlabelled, and leaves those 30 minutes out of
  the metrics. That makes it transductive, but it uses no labels and no data from later in the day.
- **Label exclusions:** the Wed-21 rule (`docs/LABEL_AUDIT.md`) is based on attack labels, but it only removes flows. It never adds or
  changes a feature.
