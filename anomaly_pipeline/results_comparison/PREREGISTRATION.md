# Pre-registered follow-up experiments (written 2026-09-25, before any of these runs)

> **Note (2026-10-03): Hugging Face Suricata2017 data withdrawn.** The entries E1, E3, E4, E5 and E6 below were partly run on the
> third-party Hugging Face Suricata version of CIC-IDS2017 (`yasirchemmakh/Cicids2017_Suricata_Logs`, `config_suricata2017*.yaml`).
> That data was withdrawn because its provenance was undocumented and its labels disagreed with CIC's documentation, and on 2026-10-03 the
> data, its configs, result folders and logs were deleted. Those entries are kept unchanged as the historical record; their
> Suricata2017 numbers can no longer be reproduced and are not reported as results. CIC-IDS2017 is evaluated from the official pcaps
> in E7 (end of this file).
> (This file was truncated by a failed write on a full disk on 2026-10-03 and restored from the Claude Code file-history backup of
> 2026-09-25 plus the session transcripts; the content is unchanged.)

Goal: address the weaknesses listed in the comparison without test-set tuning. All runs use the shipped
hyper-parameters and the unchanged two-view design (context features and min-p fusion as designed on the
CSE-CIC-IDS2018 2-day protocol). No setting is changed after seeing these results; every outcome is reported.

| # | Weakness | Experiment | Primary metric | Counts as improved if |
|---|---|---|---|---|
| E1 | Botnet recall and false alerts on Suricata2017 (flow-only model: Botnet 0.40, 24 false alerts/h) | `config_suricata2017_context.yaml`: same 12 temporal-context features + two-view (`ssl_mm_twoview_knn`), held-out dataset for this design | fixed-threshold ROC-AUC, MCC, Botnet recall, grouped false alerts/h | two-view MCC >= flow-only MCC and Botnet recall > 0.40 |
| E2 | Two-view result only shown on the protocol it was designed on | `config_multiday_context.yaml` (3-day protocol), never run before | adapted ROC-AUC / MCC of `ssl_mm_twoview_knn` vs best baseline | two-view beats every baseline on adapted ROC-AUC and MCC |
| E3 | Contrastive term not shown to help (0.981 vs 0.975, one seed) | `scripts/multiseed.py` on Suricata2017, seeds 1 2 3 4 (+ own 42) for `ssl_mm_role`, `ssl_no_contrastive`, `ae_concat` | ROC-AUC and MCC mean +- std over 5 seeds | mean difference > 2 x pooled std; otherwise reported as "no measurable effect" |

## E4: clean re-evaluation of two-view fusion (written 2026-09-25, after E1-E3 and the label audit, before any E4 run)

Why a re-run: (1) the label audit (`docs/LABEL_AUDIT.md`) found 358,623 HOIC reverse-direction flows labelled Benign on Wed-21.
They are 99.4% of that day's "benign" test flows in the 2-day protocol and part of the benign training and validation data in the 3-day protocol
(val = last 15% of each day = inside the HOIC window). (2) The two-view design and min-p were chosen on the 2-day test days. (3) E1/E2 were single
seed and had no baseline given the same two views and fusion rule.

Setup, fixed before running. Configs `config_context_clean.yaml` (2-day, **dev**: design was chosen here), `config_multiday_context_clean.yaml`
(3-day, **held-out**), `config_suricata2017_context.yaml` (**held-out**, no label change). Seeds 42, 1, 2. Shipped hyper-parameters, context features and
min-p are unchanged. The only data change is the label exclusion. New comparator `ae_twoview_knnrole`: the plain autoencoder trained on the
same two views (`ae_flow`, `ae_only_temporal_context`), with the same role-aware latent kNN and the same min-p fusion.

| primary metric | definition |
|---|---|
| ROC-AUC | pooled over test days, adapted protocol (per-day recalibration, the documented deployment mode); fixed reported too |
| macro attack AUC | mean over attack types of ROC-AUC(attack type vs all benign), which removes HOIC's weight in the pooled number |
| recall @ 1% test FPR | threshold at the 99th pct of the test benign scores (oracle, label-using). Separates ranking from calibration |
| realized FPR | at the deployable (adapted) 1% threshold; "controlled" = realized pooled FPR <= 1.5% |

Decision rule: two-view SSL beats comparator X on a metric if the seed-averaged paired difference has a 95% block-bootstrap CI above 0
(10-minute time blocks per test day, 500 resamples, the same resamples for every method). Comparators: each single view, `ssl_mm_role_knn`
(all 5 modalities in one embedding), `ae_twoview_knnrole`, `ae_concat_knnrole`, `rf_supervised`. The claim "multiple views beat every single view"
(README) stands only if it holds on both held-out settings. The claim "SSL is responsible" stands only if two-view SSL also beats `ae_twoview_knnrole`.

## E5: recall at a controlled false-alert rate (written 2026-09-25, after dev exploration, before any held-out run)

Dev exploration (CIC 2-day clean, seed 42 only, label-using; reported, not claimed):
- **kNN reference coverage (rejected).** Rescoring with every distinct benign training embedding instead of 10k / 5k per role
  (`scripts/knn_reference.py --variant full`) lowered two-view AUC (0.954 -> 0.932 fixed) and lost XSS (0.47 -> 0.01). Deduplicating
  the reference (`dedup`, 18% duplicates) changed nothing. Not carried forward.
- **Flow-level recall at 1% FPR is separability-limited for Bot and Infiltration.** Oracle recall at 1% test FPR: Bot 2-6%, Infiltration
  5-26% for every view. 17.6% of Infiltration flows are identical to benign flows (docs/LABEL_AUDIT.md). The adapted two-view HOIC
  recall flips between 99.5% and ~1% with small reference changes: the Wed-21 threshold rests on 155 flows.
- **Window-level test (carried forward).** At the flow threshold, almost every busy benign (role, 5-min) window contains flagged flows
  (73% of benign windows, 48 false alerts/h for two-view SSL). A binomial test on the count of flagged flows per window, calibrated on
  benign validation windows, gave 0.2% benign-window FPR (0.12 false alerts/h) and kept HOIC (100% of flows in alerted windows) and
  Infiltration (34%), but lost the low-volume web attacks (0%) and Bot (5%).
- **Two-tier policy (rejected).** Adding an alert for any single flow above the 0.1% threshold brought back 23 false alerts/h (35% of
  benign windows).

Pre-registered test (`scripts/window_alerts.py`, definition in its docstring; window = `incident_gap_sec` 300 s, q = `target_fpr` 1%, fixed
validation calibration, nothing tuned). Settings: CIC 3-day clean and Suricata2017 context (held-out), and CIC 2-day clean (dev), seeds 42 1 2,
methods as in E4. Primary: benign-window FPR and false alerts/h (controlled = benign-window FPR <= 1.5%), attack-window recall, share of each
attack type's flows in an alerted window. Compared with "any flagged flow alerts the window" on the same scores.
Counts as improved if, on both held-out settings, the window test keeps benign-window FPR <= 1.5% while the any-flag rule does not, and it
keeps >= 50% of the any-flag rule's attack-window recall. The recall lost (per attack type) is reported either way. This is a change in the unit
of alerting, not a better detector; flow-level recall at 1% FPR is not claimed to improve.

## E6: why the contrastive term does not help, and a targeted fix (written 2026-09-25, before any label-using run of the fix)

Diagnosis so far (`scripts/contrastive_diagnostics.py`, Suricata2017 seed 42, label-free parts). In a 256-flow InfoNCE batch, 97% / 93% / 82% / 50%
of flows share their exact tcp / http / session / dns block with another flow whose full record differs. These are mostly absent protocol blocks (all
zero). Identical blocks give identical embeddings, so these negatives cannot be told apart from the positive. The trained contrastive model's
validation InfoNCE is 5.20 vs 5.55 at chance: the term barely trains, so removing it (the ablation) removes almost nothing.
Label-free check of the fix (train/val only, no scores): masking those false negatives (`fn_mask`, `models.MultiModalSSL._contrast`) lets the
solvable part of the loss train (masked InfoNCE 1.25 vs 2.35 for the shipped model).

Hypothesis: once the contrastive term can train, it helps. Method `ssl_mm_role_fnmask` = `ssl_mm_role` + `fn_mask`, all other settings
shipped (contrastive_weight 0.1 unchanged, nothing tuned). Compared with `ssl_no_contrastive` and `ssl_mm_role`, all `_knn` scored.
Settings and seeds: Suricata2017 (`config_suricata2017.yaml`, seeds 42 1 2 3 4, as E3), CIC 2-day clean and 3-day clean (seeds 42 1 2, as E4).
Metrics: ROC-AUC and MCC (fixed and adapted), recall @ 1% test FPR. Rule as E3: an effect is claimed if the mean difference > 2 x pooled
std over seeds; otherwise it is reported as "no measurable effect". Reported either way, together with the achieved validation InfoNCE.

Not attempted: (a) HTTP payload modality on CIC-2018 Thu-22 (no benign inbound web traffic to train on, see
memory note / chat), (b) fixed-threshold drift on CIC-2018 Wed-21 (handled by the existing per-day recalibration).

## Outcomes of E4-E6 (written 2026-09-26, after all runs; nothing was changed after seeing results)
Tables: `results_*/clean_eval_{adapted,fixed}[_e6].csv` (seed-mean metrics, 95% block-bootstrap CIs of paired differences, 200 resamples;
rank-binned to 20,000 bins, AUC error < 1e-4), `results_*/window_alerts_summary.csv`, `results_*/multiseed_overall*.csv`.

**E4 (two-view).** Differences are two-view SSL minus comparator, ROC-AUC [95% CI].
| setting | vs AE two-view | vs flow view | vs context view | vs best single embedding | two-view realized FPR |
|---|---|---|---|---|---|
| 3-day clean, adapted (held-out) | **+0.021 [0.016, 0.026]** | **-0.015 [-0.031, -0.001]** | +0.143 (recall@1%: **-0.041 [-0.086, -0.005]**) | +0.015 [0.006, 0.024] | 1.1% |
| 3-day clean, fixed (held-out) | **+0.023 [0.018, 0.027]** | +0.017 [0.008, 0.027] | +0.144 (recall@1% -0.003, n.s.) | +0.032 [0.019, 0.050] | 1.5% |
| Suricata2017, adapted (held-out) | +0.009 [0.001, 0.018] (macro n.s.) | +0.005 n.s. (macro **-0.034**) | -0.001 n.s. | **-0.006 [-0.010, -0.002]** | **6.9%** |
| Suricata2017, fixed (held-out) | +0.008 [0.001, 0.016] (macro n.s.) | +0.007 n.s. (macro **-0.039**) | -0.001 n.s. | **-0.006 [-0.011, -0.003]** | **7.3%** |
| 2-day clean (dev) | +0.007 / +0.009 | +0.40 / +0.05 | +0.05 / +0.06 | > 0 | 0.9% / 1.7% |
- "Multiple views beat every single view": **not supported**. It fails on both held-out settings (3-day adapted: the flow view ranks higher and the
  context view has higher recall at 1% FPR; Suricata2017: single 5-modality embeddings rank higher and the FPR is not controlled).
- "SSL is responsible (vs the AE given the same views and fusion)": **supported on the 3-day protocol** (both modes, all CIs > 0), **partly on
  Suricata2017** (ROC-AUC CI > 0, macro attack AUC and recall at 1% n.s.).
- The two-view SSL adapted operating point is fragile on the 2-day protocol: MCC 0.494 +- 0.398 over seeds (the Wed-21 threshold rests on
  155 flows), vs 0.686 +- 0.023 for the AE two-view.

**E5 (window alerting, two-view SSL).** 3-day: benign-window FPR 0.3% (0.26 false alerts/h) vs 64% (48/h) for any-flag, but only 16% of the
any-flag attack-window recall kept (0.137 vs 0.881). Suricata2017: 1.7% (1.3/h) vs 33% (26/h), with 72% of recall kept. Each held-out setting fails
one half of the criterion, so **E5 is not met**. False alerts fall 20-190x everywhere; the cost is recall on low-volume attacks (web, SQLi, Bot).

**E6 (fn-mask contrastive).** Seed rule: **no measurable effect** on any setting (all |differences| < 2 x seed std). The block-bootstrap CIs
put fn-mask slightly *below* `ssl_no_contrastive` on CIC (ROC-AUC -0.012 to -0.024, CIs < 0) and below `ssl_mm_role` in recall@1% on
Suricata2017 (-0.17 to -0.19). The mask did make the term train (masked InfoNCE 1.25 vs 2.35; 5 seeds). Post hoc and label-using, so a
lead, not a claim: the fn-mask head's cross-modal inconsistency `xmod` becomes a strong anomaly score (AUC 0.938 +- 0.008 vs 0.820 +- 0.092;
Botnet 0.96, SQLi 0.95), which the latent-kNN score does not use. Naive min-p fusion with it lowers pooled AUC (0.963).

## E7: CIC-IDS2017 (rebuilt from the official pcaps) as the primary dataset (written 2026-10-02, before any Tue-Fri pcap was processed)

Data: `../external/cic2017/suricata2017_rebuilt.parquet` from `scripts/cic2017_suricata.sh` + `scripts/build_suricata2017.py`
(Suricata 8.0.7 pinned, frozen ET Open rules, labels only from `docs/cic2017_attack_schedule.csv`). The schedule, the `--pad 60`
default and the build script are frozen as of this entry. `LABEL_AUDIT.md` is read before any model is trained; if an audit check
fails, the fix is documented here *before* training, and only then are models run. All hyper-parameters are the shipped defaults
(no tuning on this dataset). Seeds 42, 1, 2; 95% block-bootstrap CIs of paired differences (`scripts/clean_eval.py`, 600 s blocks).

| protocol | config | train (benign only) | test | supervised RF |
|---|---|---|---|---|
| **P1 (primary)** | `config_cic2017_monday.yaml` | Monday | Tue, Wed, Thu, Fri (all attacks unseen) | not applicable (Monday has no attack labels) |
| P2 | `config_suricata2017_rebuilt.yaml` | Monday, Tuesday | Wed, Thu, Fri | trained on Mon-Tue labelled flows (FTP/SSH-Patator) |

Methods: `ssl_mm_role_knn` (proposed), `ssl_mm_global_knn`, `ssl_no_contrastive_knn`, `ssl_only_<modality>_knn`, `ae_concat`,
`ae_concat_knn`, `ae_concat_knnrole`, `iforest`, `pca_recon`, `suricata_signature` (ET Open), the hybrid "Suricata OR proposed",
and `rf_supervised` (P2 only). Reference for paired CIs: `ssl_mm_role_knn`. Primary mode: fixed (benign-validation) threshold, 1% target FPR;
the per-day adapted mode is reported as secondary.

Hypotheses (expectations come from the HF Suricata2017 data, which is not independent of this design):
| # | RQ | claim | supported if (P1, seed mean) |
|---|---|---|---|
| H1 | RQ1 | SSL detects unseen attacks | `ssl_mm_role_knn` ROC-AUC >= 0.90 and paired CI > 0 vs each of `ae_concat`, `iforest`, `pca_recon` |
| H2 | RQ1/RQ4 | the proposed model beats the rule-based IDS at a controlled false-alert rate | recall of `ssl_mm_role_knn` > recall of `suricata_signature` and its realised benign FPR <= 2% |
| H3 | complementarity | signatures + anomaly model together | incident recall of the hybrid >= max(incident recall of either alone) |
| H4 | RQ2 | multiple telemetry sources help | `ssl_mm_role_knn` ROC-AUC CI > 0 vs every `ssl_only_<modality>_knn` |
| H5 | obj. 4 | role-aware baselines help | `ssl_mm_role_knn` ROC-AUC CI > 0 vs `ssl_mm_global_knn` |
| H6 | RQ1 | zero-day gap of supervised learning | (P2) `rf_supervised` recall on Wed-Fri at its 0.5 threshold < `ssl_mm_role_knn` recall |
| H7 | fair scorer | the gain is not only the kNN scorer | `ssl_mm_role_knn` ROC-AUC CI > 0 vs `ae_concat_knnrole` |

Also reported, without a hypothesis: the ET alert rate on Monday (pure benign traffic, the signature IDS's false-positive rate),
per-attack recall, false alerts per hour, MCC, PR-AUC, and time to detect. Every outcome is reported, including failed hypotheses.

### E7a amendment: three-day interim run (written 2026-10-02, after only Monday's Suricata output existed; Tue/Wed not yet processed)
Only Monday, Tuesday and Wednesday pcaps are available, so E7 is first run on these three days. Nothing else changes (methods,
hyper-parameters, seeds, hypotheses H1-H7, thresholds, label schedule, `--pad`). Zeek is skipped for disk space (it was optional).
| protocol | config | train (benign only) | test | attacks in test |
|---|---|---|---|---|
| P1-3d (primary) | `config_cic2017_3day.yaml` | Monday | Tuesday, Wednesday | FTP-/SSH-Patator, DoS Slowloris/Slowhttptest/Hulk/GoldenEye, Heartbleed |
| P2-3d | `config_cic2017_3day_sup.yaml` | Monday, Tuesday | Wednesday | DoS x4, Heartbleed; RF trained on Tuesday's labelled Patator flows |
H3 (hybrid) and H6 (zero-day gap) are evaluated as stated. Results are labelled "three-day interim" and are superseded by the full
five-day E7 run if Thursday/Friday are processed later; both are reported. Web attacks, Infiltration, Botnet, PortScan and DDoS are
not covered by the interim run.
- Audit note (2026-10-02, Mon+Tue audit read, before any model run): Tuesday has 428 attacker->victim flows on port 22 at 15:00-15:20,
  i.e. SSH-Patator continued ~20 min past CIC's published end (15:00). They stay **excluded** (`outside_window = drop`); the published
  window is not widened. Excluded flows are in neither the benign nor the attack set, so no method gains from this; the test set has
  428 fewer SSH-Patator flows. All other Mon/Tue checks pass (no memcap/overflow loss, same rules sha256, scheduled pair dominates,
  ports 21/22). ET alert rate on BENIGN flows: 2.10% (Monday), 1.25% (Mon+Tue).
- Audit note (2026-10-02, full Mon-Wed audit read, before any model run): all provenance checks pass on Wednesday. 2,390 Wednesday flows are
  excluded as unscheduled attacker-pair traffic; 2,248 of them are 192.168.10.51 -> 172.16.0.1:443 (the Heartbleed victim's ordinary HTTPS
  to the firewall address, all day) and 127 are 192.168.10.50 -> 172.16.0.1. None of them is labelled; the one Heartbleed flow is on port 444
  as documented. Excluded, not relabelled (~0.8% of Wednesday benign). Heartbleed has n = 1 flow, so its recall is 0 or 1 and is not
  interpreted. ET alert rate: BENIGN 0.95%, DoS Hulk/GoldenEye/Slowloris 0.00%, Slowhttptest 0.02%, FTP-Patator 48.7%, SSH-Patator 1.0%.
- Note (2026-10-02 20:50): the Thursday and Friday pcaps arrived while E7a was running. E7a was stopped after its seed-42 run of
  P1-3d (train/evaluate complete; seed 1 incomplete and discarded; P2-3d never started), so the full five-day E7 (P1, P2 as written above)
  can run without two heavy jobs in parallel. The E7a seed-42 numbers are kept in `results_cic2017_3day/` and are reported as a single-seed
  interim result, superseded by E7. Nothing in E7 was changed after seeing them.
- Audit note (2026-10-03, full five-day audit read, before any E7 model run): provenance passes on all five days (0 memcap/overflow
  loss, one rules sha256). Thursday/Friday windows are dominated by the scheduled pairs with the expected ports (web 80, Botnet 8080,
  DDoS 80). Two documented deviations, neither relabelled: (1) Friday: 1,456 flows from the five bot hosts to the C&C
  205.174.165.73:8080 continue at ~42 per 10 min from 11:02 to 17:00, after CIC's published Botnet window; they are excluded
  (`outside_window = drop`), so the Botnet class is the 743 in-window flows. (2) Thursday Infiltration - Portscan includes ~3,000 DNS
  flows from the infected host 192.168.10.8 (time-window label, known limitation). Thursday excludes 110 scattered flows.
  Infiltration (14 flows) and Heartbleed (1) are too small to interpret per class. ET alert rate on BENIGN: 0.71% (all days).

## Outcomes of E7 (written 2026-10-03, after all runs; nothing was changed after seeing results)
Tables and figures: `results_comparison/E7_5day_tables.md`, `table_E7_5day_*.csv`, `figE7_5day_*.png` (`scripts/e7_report.py`);
raw: `results_cic2017_monday*/`, `results_suricata2017_rebuilt*/` (`clean_eval_*__e7.csv`, `multiseed_*.csv`). Seeds 42, 1, 2; fixed threshold.

| H | outcome | evidence (P1 unless stated; paired ROC-AUC differences, 95% block-bootstrap CI) |
|---|---|---|
| H1 | **not supported** | ROC-AUC 0.945 +- 0.006 (>= 0.90), but vs AE +0.008 [-0.019, +0.034], vs iForest -0.009 [-0.043, +0.017], vs PCA +0.021 [-0.004, +0.043] |
| H2 | supported | recall 0.115 vs Suricata 0.004; realised FPR 0.50% (Suricata 0.28%) |
| H3 | supported | incident recall hybrid 0.91 vs proposed 0.70 vs Suricata 0.73 |
| H4 | supported | every single-source model below: flow +0.013 [+0.005, +0.020], tcp +0.186, http +0.136, session +0.489, dns +0.736 (all CIs > 0) |
| H5 | supported | vs global +0.153 [+0.007, +0.329] |
| H6 | supported | (P2) RF recall 0.004 (ROC-AUC 0.612) vs proposed 0.070 (0.951) on Wed-Fri |
| H7 | **not supported** | vs AE + same role-kNN scorer +0.009 [-0.025, +0.044]; the AE+kNN has higher recall (0.295) and MCC (0.435) |
- Operating point unstable across seeds: proposed recall 0.005 / 0.007 / 0.334 (seeds 42 / 1 / 2) at a stable ROC-AUC (0.938-0.950); the
  Monday-calibrated threshold falls just above or below the DoS Hulk/DDoS score cluster. Same pattern for the no-contrastive and iForest models.
- Suricata ET Open: 0.71% of benign flows alerted (2.10% on Monday, 889 alerted flows/h); 0.00% on Botnet, DoS Hulk/GoldenEye/Slowloris,
  DDoS and Web Brute Force; it catches FTP-Patator (0.49), SQLi (0.67), Infiltration (0.21) and Heartbleed (1 flow).
- Contrastive term: no measurable effect again (vs `ssl_no_contrastive_knn` +0.001 [-0.001, +0.003]).
- Post hoc, not a claim: the single-modality reconstruction score `ssl_only_tcp` had the best seed-42 result (ROC-AUC 0.974, recall 0.86, MCC 0.86).

## X1: exploratory score fusion after E7 (written 2026-10-03, POST HOC: chosen after the E7 test labels were seen)
Not pre-registered and not a confirmatory result. After E7 (H1 and H7 not supported), score-level variants of the SSL models were
compared on the saved E7 score files with `scripts/explore_fusion.py` (no retraining; every variant calibrated on benign validation
data only, but **compared on the P1 Tue-Fri labels**). Output: `results_explore/`.

Erratum within this entry: a first variant, the mean of robust z-scores of the single-modality experts, looked very strong (P1
ROC-AUC 0.981, recall 0.845). It was a numerical artifact: 74-92% of benign validation flows have identical tcp/http/session
features, so those experts' benign MAD is 0, the calibrator floors the scale at 1e-6 and every deviation from the most common
benign pattern scores ~1e7 (then ~1e15 after the second z-scoring). It is discarded and not reported as a result.

Kept variant `ssl_mm_experts` (`train.fuse_experts`): min-p fusion of the single-modality SSL experts `ssl_only_<modality>`
(each expert's score -> -log upper-tail probability among its own benign validation scores; the most extreme expert decides).
Min-p was taken from the existing two-view design (E1-E4), not chosen among the variants by test results; the mean-of-tails
variant (T1) is in `results_explore/` for completeness.

| study (fixed threshold, 1% target FPR) | `ssl_mm_experts` ROC-AUC / PR-AUC / recall / MCC / FPR | recall at equal 1% FPR | E7 `ssl_mm_role_knn` | best baseline |
|---|---|---|---|---|
| CIC-IDS2017 P1 (3 seeds) | 0.951 +- 0.007 / 0.891 / 0.429 +- 0.172 / 0.535 / 1.7% | 0.372 | 0.945 / 0.858 / 0.115 / 0.177; 0.218 | iForest ROC-AUC 0.953; AE+kNN MCC 0.435, 0.210 |
| CIC-IDS2017 P2 (3 seeds; shares Wed-Fri with P1) | 0.960 +- 0.002 / 0.928 / 0.411 / 0.513 / 1.5% | 0.280 | 0.951 / 0.895 / 0.070 / 0.180; 0.157 | AE+kNN ROC-AUC 0.961, MCC 0.400, 0.263 |
| CSE-CIC-IDS2018 2-day (seed 42) | 0.557 / 0.354 / 0.015 / -0.030 | 0.008 | 0.775 | AE+kNN 0.741 |
| UNSW-NB15 (seed 42) | 0.872 / 0.896 / 0.422 / 0.485 | 0.422 | 0.928 / 0.947 / 0.665 / 0.662 | AE+kNN 0.928 |

- On CIC-IDS2017 it ranks as well as the best baseline (ROC-AUC tie with iForest / AE+kNN) and gives the highest recall and MCC
  at the 1% operating point, but its fixed-threshold recall is still seed-dependent (std 0.17). It is worse than the E7 model on
  CSE-CIC-IDS2018 and UNSW-NB15, whose "modalities" are column groups of one flow record.
- Side finding: the single-modality experts' calibrated reconstruction scores are heavily tied on benign data (MAD = 0). E7's H4
  used the `_knn` variants and is not affected; the post-hoc note on `ssl_only_tcp` above refers to such a tied score.

## E8: confirmatory test of `ssl_mm_experts` on Terma telemetry (written 2026-10-03, before any Terma data exists)
Purpose: an independent test of the X1 variant on data it was not selected on. Frozen as of this entry: the fusion recipe
(`train.fuse_experts`), the shipped hyper-parameters of `config_cic2017_monday.yaml` (model, scoring, baselines), seeds 42, 1, 2,
fixed benign-validation threshold at 1% target FPR as primary mode, `scripts/clean_eval.py` paired block-bootstrap CIs (600 s blocks).
To be fixed *before any Terma label is looked at* and appended here: the Terma adapter and its modality list (one modality per
Suricata/Zeek event type; any new feature such as TLS 1.3 is added then), the role mapping (asset role / zone), the train period
(earliest period, treated as benign) and the test period, and how labels are obtained (red-team windows, incident tickets).

| # | claim | supported if (test period, seed mean) |
|---|---|---|
| H8.1 | expert fusion beats the E7 method on real multi-source telemetry | `ssl_mm_experts` ROC-AUC paired CI > 0 vs `ssl_mm_role_knn` |
| H8.2 | it beats the unsupervised baselines | ROC-AUC paired CI > 0 vs each of `iforest` and `ae_concat_knnrole` |
| H8.3 | more detections at the same false-alert rate | recall at equal realised benign FPR 1% > that of `ssl_mm_role_knn`, `iforest`, `ae_concat_knnrole` |
| H8.4 | operating point holds on a new site | realised benign FPR at the fixed threshold <= 2% |

Method under test: `ssl_mm_experts` as defined in X1 (min-p fusion), not the discarded z-score variant.

If Terma data has no attack labels, only H8.4 (on a period assumed benign), false alerts per hour and an analyst review of the
`analyst_report_ssl_mm_experts.md` alerts are reported; H8.1-H8.3 are then reported as "not testable". Every outcome is reported.

## E9: dev/test round to improve the operating point of the SSL model (written 2026-10-03, before any Tuesday-only or Wed-Fri-only number of these candidates was computed)
Why: E7 showed a ranking tie with the unsupervised baselines (H1, H7) and an operating point that swings with the seed. E9 tries
score-level improvements of the *existing* P1 models (seeds 42, 1, 2; trained on Monday benign traffic only, no retraining).
Honest limits: every Tue-Fri label was already seen in E7 / X1 (pooled and per day), so E9 is weaker evidence than E7; Tuesday
has only two attack types (FTP/SSH-Patator), so it is a weak guide for selection. Every outcome is reported.

Split: **dev = Tuesday** (used only to choose a candidate), **test = Wednesday-Friday** (used once, after the choice is recorded).
Thresholds as always: 1 - 0.01 quantile of the benign Monday validation scores. Every fusion/ensemble works on tail scores
(-log upper-tail probability among the method's own benign validation scores), so tied benign scores cannot dominate.

Candidates (SSL family): C0 `ssl_mm_role_knn` (E7 reference, single seed); C1 3-seed ensemble of C0 (mean tail score);
C2 `ssl_mm_experts` (min-p of the five `ssl_only_<modality>` experts, single seed); C3 3-seed ensemble of C2;
C4 min-p of C0 and C2 (single seed); C5 3-seed ensemble of C4.
Selection rule (dev): highest Tuesday PR-AUC (seed mean for single-seed candidates); ties (< 0.005) broken by Tuesday MCC.
Baselines get equal treatment: if the selected candidate is an ensemble, it is compared with 3-seed ensembles of `iforest`,
`ae_concat_knnrole`, `pca_recon` (same mean-tail rule); otherwise with their seed means. `suricata_signature` is reported as is.
Test statistics: `scripts/e9_devtest.py`, paired block bootstrap (600 s blocks within each test day, 500 resamples).

| # | claim (Wed-Fri test) | supported if |
|---|---|---|
| H9.1 | the selected model ranks unseen attacks better than the unsupervised baselines | ROC-AUC paired 95% CI > 0 vs each of `iforest`, `ae_concat_knnrole`, `pca_recon` |
| H9.2 | it is better at the operating point | MCC at the fixed threshold, paired 95% CI > 0 vs each of the same three baselines |
| H9.3 | the operating point stays usable | realised benign FPR at the fixed threshold <= 2% |
| H9.4 | it improves on the E7 model | ROC-AUC or MCC paired 95% CI > 0 vs C0 |

### E9 selection (written 2026-10-03, after the Tuesday dev run, before any Wed-Fri number of the candidates)
Tuesday (294,471 flows, 6,561 attacks), `results_comparison/E9_dev.csv`. PR-AUC: C0 0.231, C1 0.271, C2 0.405, C3 0.405,
C4 0.425, **C5 0.476**. By the rule, **C5 = 3-seed ensemble of min-p(`ssl_mm_role_knn`, `ssl_mm_experts`)** is selected and
frozen. It is an ensemble, so it is compared with the 3-seed ensembles of `iforest`, `ae_concat_knnrole` and `pca_recon`.

### Outcomes of E9 (written 2026-10-03, after the single Wed-Fri run; nothing was changed after seeing results)
Wed-Fri (1,326,344 flows, 504,145 attacks), `results_comparison/E9_test.csv`, fixed threshold, paired differences selected - other with
95% block-bootstrap CIs (500 resamples).

| method | ROC-AUC | PR-AUC | recall | FPR | MCC |
|---|---|---|---|---|---|
| **C5 ens3(min-p(ssl_mm_role_knn, ssl_mm_experts))** | 0.954 | **0.928** | **0.631** | 1.8% | **0.686** |
| C0 `ssl_mm_role_knn` (E7, seed mean) | 0.945 | 0.886 | 0.114 | 0.5% | 0.172 |
| `iforest` ens3 | **0.955** | 0.862 | 0.074 | 1.3% | 0.160 |
| `ae_concat_knnrole` ens3 | 0.941 | 0.907 | 0.210 | 1.0% | 0.347 |
| `pca_recon` ens3 | 0.922 | 0.751 | 0.000 | 0.2% | -0.024 |
| `suricata_signature` | 0.499 | 0.380 | 0.001 | 0.3% | -0.024 |

| H | outcome | evidence |
|---|---|---|
| H9.1 | **not supported** | ROC-AUC vs iForest -0.002 [-0.051, +0.041], vs AE+kNN +0.013 [-0.036, +0.062], vs PCA +0.032 [-0.011, +0.077] |
| H9.2 | supported | MCC vs iForest +0.526 [+0.123, +0.938], vs AE+kNN +0.339 [+0.070, +0.672], vs PCA +0.710 [+0.415, +0.938] |
| H9.3 | supported | realised benign FPR 1.8% |
| H9.4 | supported | vs E7 model: MCC +0.514 [+0.321, +0.704] (ROC-AUC +0.009 [-0.019, +0.049]) |
| vs signatures | (not a hypothesis) | ROC-AUC +0.455 [+0.417, +0.486], MCC +0.709 [+0.424, +0.937] |

## E10: extended explanation evaluation for RQ3 (written 2026-10-04, before any of these checks was run)
Why: the automatic RQ3 checks so far are deletion fidelity with a benign-*median* reset, stability and agreement. For the E9
ensemble, native attribution and LIME failed that test, and the README traces the failure to the reset itself: a mix of median
values is an unusual flow, so the score rises even when random features are reset. No human rating exists yet. E10 adds checks
that do not need analysts; a human study (`docs/analyst_study/`) follows if Terma analysts are available.
Honest limit: the ensemble's median-reset failure has been seen, so the realistic-replacement deletion test (F1) is a post-hoc
change of the test. It is applied to every method equally and the median-reset numbers stay reported next to it.

Setup (`scripts/xai_eval.py`), fixed now. Config `config_cic2017_monday.yaml` (P1, Tue-Fri). Methods: `ssl_mm_ensemble`
(the E9 selected model, primary), `ssl_mm_experts`, `ssl_mm_role`. Alerts: flows above the method's fixed threshold, sampled at
random (seed 1) per attack type, up to 15 per type, plus 30 false alarms (Benign). Attribution methods: native, SHAP
(KernelSHAP as in `explain.py`), LIME (as in `explain.py`) and the new modality-level Shapley values (G). Background: 100 benign
validation flows of the alert's role, as in `explain.py`. Uncertainty: 95% bootstrap CIs over alerts (1000 resamples).

| # | check | definition | a method passes if |
|---|---|---|---|
| G | modality-level Shapley | exact Shapley values over the 5 modalities (32 coalitions); value of a coalition = mean score over the background rows with that coalition's features taken from the alert | (descriptive; also used in P, S) |
| F1 | realistic-replacement deletion | top-k features (k = 1..10) replaced with the values of the alert's nearest benign validation flow of the same role (Euclidean, standardised features); AOPC = mean over k of the normalised score drop; random = same with random feature orders (5 repeats) | AOPC - random AOPC has CI > 0 |
| F2 | modality deletion | the top-1 modality (by G, and by summed abs. attribution for the other methods) replaced from the nearest benign flow vs a random other modality | drop - random drop has CI > 0 |
| C | counterfactual size | features replaced from the nearest benign flow in the method's attribution order until the score falls below the threshold; compared with ordering by abs(x - neighbour) | descriptive (smaller = more actionable); median and share reached within 10 features |
| P | plausibility | share of attack alerts whose top-attributed modality is in the expected set below (written before any E10 run) | hit rate CI lower bound > chance rate (mean of size(expected set)/5) |
| R | model-randomisation sanity check (Adebayo et al. 2018) | all network weights re-initialised (calibrators and kNN refitted as the scorer does), attributions recomputed for the same alerts; Spearman correlation of abs. attributions trained vs randomised | mean Spearman < 0.5 |
| S | simulatability (informativeness) | 5x repeated stratified 5-fold CV, logistic regression; input = L1-normalised attribution vector (+ modality shares); targets: attack type (types with >= 5 alerts; macro-F1) and attack vs false alarm (ROC-AUC). Reference inputs: score only (floor), random vector, the standardised features x (what the model sees) | macro-F1 > score-only macro-F1 + 2 x its CV std |

Expected modalities per attack type (P), from the attack descriptions (CIC 2017 paper, tool documentation), written before any E10 run:
| attack type | expected modalities | reason |
|---|---|---|
| DoS Hulk, DoS GoldenEye, DDoS (LOIC HTTP) | http, flow | HTTP request floods: request counts/URLs and packet/byte volume |
| DoS Slowloris, DoS Slowhttptest | flow, tcp, http | long, near-empty connections; incomplete HTTP requests |
| FTP-Patator, SSH-Patator | session, flow, tcp | repeated short login sessions (FTP / SSH metadata) |
| PortScan, Infiltration - Portscan | tcp, flow, dns | SYN/RST without data; the infiltration label also covers the host's DNS flows |
| Botnet (Ares, HTTP C&C on 8080) | http, flow | periodic HTTP polling |
| Web Attack - Brute Force, XSS, SQL Injection | http | crafted HTTP requests (URL, method, length) |
| Heartbleed, Infiltration | (not evaluated) | 1 and 14 flows |

Every outcome is reported, including failed checks.

### Outcomes of E10 (written 2026-10-04, after the single run; nothing was changed after seeing results)
Report: `results_cic2017_monday/xai_eval/E10_report.md` (also `summary.csv`, `simulatability.csv`, `per_alert_*.csv`). Alerts:
`ssl_mm_ensemble` 191 (30 false alarms), `ssl_mm_experts` 204 (30 false alarms). `ssl_mm_role` (the reconstruction score that
`explain.py` explains by default) raises **0 attack alerts** on Tue-Fri at its fixed threshold (all 2,089 alerts are false alarms),
so only R and C are evaluable for it. Means with 95% bootstrap CIs over alerts; "fails" = criterion not met.

| check | `ssl_mm_ensemble` (E9 model) | `ssl_mm_experts` |
|---|---|---|
| F0 median reset, k = 10 (old test, for comparison) | native +0.06 [-0.01, 0.13], LIME +0.01 [-0.08, 0.09] (fail, as in the README); SHAP +0.28 | SHAP +0.61, native +0.27, LIME +0.13 |
| F1 realistic replacement, AOPC - random | **all pass**: native +0.55 [0.46, 0.63], SHAP +0.41 [0.34, 0.48], LIME +0.25 [0.19, 0.30] | native +0.27, SHAP +0.23 pass; **LIME +0.04 [-0.07, 0.14] fails** |
| F2 top modality - random modality | all pass (SHAP +0.65, native +0.54, G +0.50, LIME +0.34) | all pass (native / SHAP / G +0.98, LIME +0.58) |
| C counterfactual size (median features to fall below the threshold) | native 4, SHAP 6, abs(x - neighbour) 4, LIME 64; reached within 10 features: SHAP 60%, native 60%, LIME 14% (the nearest benign flow itself is above the threshold for 21% of alerts) | native 8, SHAP 5, abs(x - neighbour) 3, LIME 68 |
| P plausibility (chance 0.48 / 0.47) | all pass: LIME 0.95, SHAP 0.89, native 0.89, G 0.87 | all pass: 0.84-0.85 |
| R randomisation, Spearman (pass < 0.5) | native 0.21, SHAP 0.36 pass; **LIME 0.74, G 0.68 fail** | native 0.13, SHAP 0.36 pass; **LIME 0.76, G 0.70 fail** |
| S attack type from the explanation, macro-F1 (score only / random / features x) | 0.21 / 0.08 / 0.98; native 0.97, SHAP 0.90, LIME 0.88, G 0.84: all pass | 0.13 / 0.08 / 0.91; native 0.93, SHAP 0.83, LIME 0.72, G 0.49: all pass |
| S attack vs false alarm, ROC-AUC (bar = score only + 2 std) | score only 0.63 +- 0.14 (bar 0.91); native 0.90, SHAP 0.85, G 0.86, LIME 0.78: **none passes** | score only 0.61 +- 0.10 (bar 0.81); native 0.85, SHAP 0.84 pass; LIME 0.77, G 0.80 fail |

`ssl_mm_role` (30 false alarms only): R native 0.43 passes; SHAP 0.67, LIME 0.76, G 0.92 fail.

- **SHAP and native attribution pass every pre-registered check on both evaluable models** (except false-alarm discrimination on the
  ensemble, which no method passes because the score-only bar is high and noisy).
- **The ensemble's earlier failure was the median-reset test, not the explanations**: with realistic replacement, native (+0.55) and
  LIME (+0.25) pass. This is a post-hoc change of the test (stated in the E10 entry); both versions are reported.
- **LIME is not reliable**: it fails the randomisation check on every model (its attributions barely change when the network is
  random, so they mostly reflect the input), fails realistic fidelity on `ssl_mm_experts`, and its feature order needs 64-68 features to
  reach a benign score. Its high plausibility (0.95) is therefore not evidence about the model.
- **Modality-level Shapley values (G) are faithful (F2) but fail randomisation (0.68-0.70)**: which telemetry source "drives" an alert
  is largely fixed by which source deviates in the input. G is useful as a summary for analysts, not as evidence about the model.
- Simple neighbour comparison (order by abs(x - nearest benign flow)) is as actionable as SHAP (3-4 features), which supports showing
  the nearest normal flow of the same role in the analyst report.
- Explanations recover the attack type almost as well as the raw features (SHAP 0.90 vs 0.98), so they condense rather than add
  information; their value for a person is the condensation, which only the analyst study (`docs/analyst_study/`) can test.

## X2: leakage and data-integrity audit (written 2026-10-05, POST HOC: after E1-E10 test results were seen; descriptive)
Why: the protocol was frozen (E7) without a systematic leakage audit; this audit checks after the fact whether any reported number
could be inflated by leakage. It changes no reported number; if it finds leakage that affects a result, that is reported as a
limitation next to the result, not fixed silently. Script: `scripts/leakage_audit.py`; output `results_comparison/leakage_audit/`;
write-up `docs/LEAKAGE_AUDIT.md`. Protocols: CIC-IDS2017 P1 (`config_cic2017_monday.yaml`), CSE-CIC-IDS2018 3-day clean
(`config_multiday_context_clean.yaml`), UNSW-NB15 (`config_unsw.yaml`). Splits are rebuilt in memory with the pipeline's own loader,
cleaning and feature space (for P1 checked to be identical to the cached `processed/*.npz`), so every check is on what the models see.

| # | check | definition |
|---|---|---|
| L1 | split integrity | train / validation / test time ranges; train and test days disjoint; validation strictly after training rows of each day |
| L2 | preprocessing fit | feature-space statistics refitted on the training benign rows only equal the shipped ones (P1) |
| L3 | exact duplicates across splits | share of test rows (per label) whose model input (standardised features + role) also occurs in the benign training period (train + validation) |
| L4 | near duplicates | Euclidean distance (standardised features) from test rows (sample of up to 5,000 per label) to the nearest of 200,000 benign training rows; share below 0.1 and median |
| L5 | identifier / label leakage | no model feature is an identifier (IP, port number, Flow ID, timestamp, row id) or derived from labels or IDS alerts (`sig`, `alerted`, `class`, `truth`, `Label`) |
| L6 | identifier shortcuts | in-sample target-encoding ROC-AUC (attack vs benign, test period) of identifiers NOT used as features: src/dst IP, Flow ID (P1), dst port, minute of day, role, UNSW `id`; shows how strong a shortcut would be |
| L7 | session / flow overlap | P1: test flows whose Flow ID (5-tuple) occurs in the training day |
| L8 | single-feature artefacts | per model feature, test-period ROC-AUC (max(AUC, 1-AUC)) attack vs benign, pooled and per attack type; >= 0.95 flagged |
| L9 | future information | code review of the temporal-context features and of the threshold / adaptation procedures for use of later data |

## E11: fair hyperparameter tuning of the baselines (written 2026-10-05, after E7-E10 test results were seen, before any E11 run)
Why: only the SSL model had a hyperparameter search (label-free, `scripts/hparam_search.py`, on CSE-CIC-IDS2018); the baselines ran
with defaults. A comparison is only fair if every method gets the same tuning budget and criterion. Honest limit: the test results of
the default configurations are known, so E11 is a robustness check of H1 / H6 / H7, not a fresh test; E7 / E9 numbers stay as reported.
Script: `scripts/e11_tuning.py`; output `results_comparison/E11/`.

Unsupervised methods, protocol P1 (`config_cic2017_monday.yaml`). Selection criterion, identical for every method and identical to
`hparam_search.py`: mean ROC-AUC of 4,000 benign validation flows (seed 1) against two synthetic-anomaly sets built from them
(modality shuffle, feature extreme); model seed 0. No attack label is used. If the best candidate is within 0.002 of the default,
the default is kept (the rule applied to the SSL search).

| method | grid |
|---|---|
| `ssl_mm_role` (scored by `ssl_mm_role_knn`) | hidden {64, 128, 256} x latent_dim {16, 32, 64} (9) |
| `ae_concat` (reconstruction) and `ae_concat_knnrole` | hidden {64, 128, 256} x latent_dim {16, 32, 64} (9; each score selected separately) |
| kNN scorer of `ssl_mm_role_knn` and `ae_concat_knnrole` | k {1, 5, 10, 20} on the selected encoder |
| `iforest` | n_estimators {100, 200, 400} x max_samples {256, 1024, 4096} x max_features {0.5, 1.0} (18) |
| `pca_recon` | explained variance {0.80, 0.90, 0.95, 0.99} (4) |

Supervised `rf_supervised`, on the three protocols where it is reported: CIC-IDS2017 P2 (`config_suricata2017_rebuilt.yaml`), UNSW-NB15,
CSE-CIC-IDS2018 3-day clean. Grid n_estimators {100, 300} x max_depth {10, 20, None} x min_samples_leaf {1, 2, 5} (18). Validation:
the latest 20% (by time) of the labelled training-period pool (`sup`); UNSW-NB15 has no time, so a stratified random 20% (seed 42).
Criterion: PR-AUC on that validation. Only training-period labels are used; the selected setting is refitted on the whole pool.

Evaluation: the selected settings are retrained with seeds 42, 1, 2 and scored like E7 (fixed threshold = 99th percentile of benign
validation scores; paired ROC-AUC differences with 95% block-bootstrap CIs as in `scripts/clean_eval.py`).
Decision rules, fixed now: H1 (proposed vs best unsupervised baseline) and H7 (proposed vs AE with the same role-kNN scorer) are re-read
with the tuned versions of BOTH sides; an outcome changes only if the CI of the paired difference changes sign class (includes 0 vs not).
H6 (P2) is re-read with the tuned RF. All three outcomes are reported whatever they are.

## X3: representation analysis (written 2026-10-05, POST HOC; descriptive)
Why does (or does not) the SSL latent space help? P1, saved models of seeds 42, 1, 2 (no retraining): `ssl_mm_role`, `ssl_no_contrastive`,
`ssl_mm_global`, `ae_concat`, and the standardised input features as reference. Sample: 20,000 benign training-period flows and up to
2,000 test flows per label (seed 0). Script `scripts/representation_analysis.py`; output `results_comparison/representation/`.
Measures: (a) neighbourhood purity: share of the 10 nearest test neighbours with the same label; (b) benign vs attack separation:
ROC-AUC of the distance to the 5 nearest benign training embeddings (global and same-role), and linear-probe ROC-AUC (logistic regression,
5-fold CV) as an upper bound of linear separability; (c) role structure: neighbourhood role purity and per-role separation AUC;
(d) stability across seeds: linear CKA and the overlap (Jaccard) of the 10-nearest-neighbour sets of the same flows; (e) effective
dimensionality (participation ratio of the embedding covariance); (f) 2-D t-SNE figure of the sample.

## X4: error and failure analysis (written 2026-10-05, POST HOC; descriptive)
P1, saved score files, fixed threshold, seeds 42 / 1 / 2: `ssl_mm_role_knn`, `ssl_mm_ensemble`, `ae_concat_knnrole`, `iforest`,
`suricata_signature`. Script `scripts/error_analysis.py`; output `results_comparison/error_analysis/`. Breakdowns of false negatives
(per attack type, role, protocol, flow size in packets, flows identical to benign training flows from X2) and false positives (per role,
destination port, hour, flow size, protocol); attacks missed by every method vs caught by at least one (complementarity); seed
disagreement (flows whose decision flips between seeds) and their distance to the threshold; the features that deviate most (median |z|)
in false positives and false negatives.

### Outcomes of X2 (written 2026-10-05, after the single run)
Write-up `docs/LEAKAGE_AUDIT.md`; tables `results_comparison/leakage_audit/`. No leakage that could inflate the results of the unsupervised
methods: splits chronological (UNSW: official, no time), preprocessing fitted on training rows only (P1 rebuild byte-identical to the
shipped split), no identifier or label-derived feature, no attack 5-tuple of Tue-Fri seen on Monday (except 2.5% of Infiltration - Portscan),
the only future information (10-s port bucket of the CSE-CIC-IDS2018 context) changes per-day AUCs by <= 0.013. Findings that qualify results:
(1) UNSW-NB15: 15-48% of the DoS / Reconnaissance / Analysis / Exploits / Generic test flows are identical to rows of the RF's labelled
training pool, so the RF's 0.985 ROC-AUC is partly memorisation; (2) CIC-IDS2017: XSS 95%, Web Brute Force 89%, Slowhttptest 66%, Slowloris
42% of the attack-labelled flows are identical to benign Monday flows and Portscan 50% near-identical (time-window labels), a recall ceiling
for every flow-level detector (deflates, cannot inflate); (3) CIC-IDS2017: 43-46% of benign test flows are identical to benign training flows.

### Outcomes of X3 and X4 (written 2026-10-05, after the single runs)
Write-up `docs/REPRESENTATION_AND_ERRORS.md`. X3: the SSL latent space is organised by service role (neighbour role purity 0.994 vs 0.940);
that gives it a better *global* kNN separation (0.847 vs input 0.799, AE 0.811), but with a same-role search the AE is as good (0.863 vs
0.857), the mechanism behind H5 supported / H7 not supported. The contrastive term leaves every measure unchanged; latent spaces are
low-rank (participation ratio 2.6-3.4 of 32); 10-NN sets overlap only 67-74% across seeds; the linear probe on the raw input (0.988) beats
every latent space, so the limit is the unsupervised scoring, not the information. X4: misses fall into (a) label-artefact flows near-identical
to benign traffic (17.9% of Tue-Fri attack flows), (b) well-ranked attacks that stay below the 1% benign tail (SSH-Patator, DoS Hulk), and (c) a
threshold at the edge of the DDoS / Portscan / FTP-Patator clusters (seed flips: Portscan recall 0.011 / 0.015 / 0.814). 64-77% of the
`ssl_mm_role_knn` false alarms (seeds 42, 1) are flows Suricata flushed at the end of each capture (`flow_reason = shutdown`, 3.2% of benign
flows), a capture artefact; they stay in every reported number.

### Outcomes of E11 (written 2026-10-05, after the single run of each stage; nothing was changed after seeing results)
Report `results_comparison/E11/E11_report.md`; scores `results_e11_*`. Selected (label-free, P1): SSL hidden 256 / latent 64 / k 1; AE+role-kNN
default encoder / k 1; AE recon hidden 256; iForest 100 trees / 4,096 samples / 0.5 features (criterion 0.729 -> 0.807); PCA 0.99. RF: default
kept on P2 (validation slice held only SSH-Patator, every candidate PR-AUC ~0.02) and UNSW (tie); tuned on CSE-CIC-IDS2018 (100 / 20 / 1).
One execution fix during the run: the final stage crashed on a missing temporary folder (not created before use) after seed 42's SSL and AE
models were trained; the stage was made resumable and continued, with no setting changed.
P1, seeds 42 / 1 / 2, fixed threshold, tuned vs tuned (SSL - method, ROC-AUC): iForest -0.020 [-0.051, -0.009]; AE +0.025 [-0.011, +0.060];
PCA +0.014 [-0.012, +0.028]; AE + role-kNN +0.018 [-0.013, +0.057].
| H | E7 | E11 | changed |
|---|---|---|---|
| H1 | not supported | **not supported; tuned iForest now significantly better on ROC-AUC (0.974 vs 0.953)** | CI class vs iForest: includes 0 -> below 0 |
| H7 | not supported | not supported | no |
| H6 | supported | supported (RF default kept): ROC-AUC 0.951 vs 0.612, recall 0.070 vs 0.004 | no |
- Tuned SSL: ROC-AUC 0.945 -> 0.953, fixed-threshold recall 0.115 -> 0.434 (seed std 0.134) at FPR 0.5%; recall vs tuned iForest
  +0.109 [+0.035, +0.174] at half its FPR. The advantage of the proposed model is its operating point and zero-day behaviour, not ranking.
- CSE-CIC-IDS2018: tuned RF ROC-AUC 0.717 vs default 0.713, recall 0 in both; validation gain on the seen attack does not transfer.
- The label-free criterion improved iForest and PCA on test, left AE + kNN unchanged and made AE reconstruction worse (-0.009).

## E12: leave-one-attack-family-out evaluation of the supervised RF (written 2026-10-05, before any E12 run)
Why: H6 shows the RF failing on unseen attacks in one split only (P2: FTP-Patator seen, everything else unseen). E12 holds out each attack
family in turn, so the generalisation gap of a supervised detector is measured per family against the same RF when the family was seen,
and against the label-free SSL model on identical test rows. This is an "unseen-attack protocol", not a claim about real zero-days.
Script `scripts/e12_lofo.py`; output `results_comparison/E12/`.

Data: CIC-IDS2017 P1 processed splits (feature space fitted on Monday benign, unchanged). Families (>= 500 flows): DoS (Hulk, GoldenEye,
Slowloris, Slowhttptest), DDoS, Brute force (FTP-Patator, SSH-Patator), Web (Brute Force, XSS, SQL Injection), Scan (Portscan, Infiltration -
Portscan), Botnet. Heartbleed (1 flow) and Infiltration (14) are never held out; they are training attacks of every model and not tested.
For each held-out family F, flows of F are split per attack type at the median start time:
- test rows = all Tue-Fri benign flows + the later half of F (other families' attacks are not tested);
- `rf_unseen`: Monday benign (train split) + every attack flow of the other families (at most 50,000 per attack type, random, seeded);
- `rf_seen`: the same plus the earlier half of F (an optimistic reference: the halves may share near-duplicates);
- RF settings: the shipped `SupervisedRF` (100 trees, depth 20, leaf 2, balanced class weights; kept by E11 on P2 and UNSW).
Thresholds: (i) 0.5 (as shipped) and (ii) calibrated, the 99th percentile of the RF's scores on Monday benign validation (the rule of every
unsupervised method). SSL comparison: saved scores of the tuned E11 `ssl_mm_role_knn` (primary) and of the E7 default, with their own fixed
thresholds, no retraining. Seeds 42, 1, 2 (RF seed and sampling seed; the SSL score of the same seed). Metrics per family: recall of F at both
thresholds, ROC-AUC (F vs Tue-Fri benign), FPR. CIs: 10-minute blocks resampled within each test day, 500 resamples, seed-mean statistic.
Decision rules, fixed now:
- H8a (generalisation gap): ROC-AUC(`rf_seen`) - ROC-AUC(`rf_unseen`) has CI > 0 in at least 4 of the 6 families.
- H8b (label-free model vs supervised on unseen families): recall(SSL tuned) - recall(`rf_unseen`, calibrated threshold) has CI > 0 in at
  least 4 of the 6 families. The same difference in ROC-AUC is reported, not decided.
Every outcome is reported.

## E13: Zeek on CIC-IDS2017 as a second operational baseline (written 2026-10-05; Zeek was started on the Tue-Fri pcaps before this entry,
## no Zeek output has been read)
Why: Zeek was only run on one CSE-CIC-IDS2018 capture; on CIC-IDS2017 it was skipped for disk space (E7). E13 adds it on the P1 test days.
Run: `zeek/zeek:9.0.0`, `zeek -C -r <Day>.pcap local protocols/ftp/detect-bruteforcing protocols/ssl/heartbleed misc/detect-traceroute` with
`Site::local_nets = 192.168.10.0/24`, no network access (logs in `external/cic2017/<Day>/zeek/`). Zeek 9 has no scan detector. No tuning.
Zeek alert = an entry in notice.log, except Zeek health notices (`CaptureLoss::*`, `PacketFilter::*`). Flow verdict on the P1 test rows
(the Suricata flows): a flow is Zeek-detected if (a) a notice names the Zeek connection matched to it (notice `uid`; match = same 5-tuple in
either direction, start times within 2 s), or (b) a notice without `uid` has a `src` that is one of the flow's two endpoints and the flow
starts within 30 minutes of the notice. The same rule is applied to benign flows (false positives). Metrics, as for Suricata in E7:
recall per attack type and overall, FPR, alerted benign flows per hour, notice types; plus Zeek OR Suricata and Zeek OR `ssl_mm_role_knn`
(tuned E11, seed 42 and seed mean). Descriptive baseline: no hypothesis; reported whatever the result.

### Outcomes of E12 (written 2026-10-05, after the run; nothing was changed after seeing results)
Report `results_comparison/E12/E12_report.md`. Execution fix (statistics only, no change to models, data or rules): in the first run some
bootstrap resamples contained no attack flow of a family (DDoS, Web, Botnet sit in few 10-minute blocks), which made AUC undefined (NaN CIs)
and recall 0. Those resamples are now dropped for recall, FPR and AUC alike (`resamples_used`: 428-500 of 500); point estimates unchanged.
| H | rule | outcome |
|---|---|---|
| H8a | AUC(rf_seen) - AUC(rf_unseen) CI > 0 in >= 4 / 6 families | **supported, 6 / 6** (Web +0.408, Scan +0.060, DoS +0.029, Botnet +0.021, Brute force +0.011, DDoS +0.005) |
| H8b | recall(tuned SSL) - recall(rf_unseen, calibrated) CI > 0 in >= 4 / 6 | **not supported, 0 / 6** (Scan +0.470 [-0.206, +0.798], Botnet +0.102 [0.000, +0.149]; RF better on Brute force -0.223 [-0.330, -0.074] and DDoS -0.325) |
- rf_unseen ranks unseen families well (AUC 0.93-0.995, Web 0.584) but its calibrated recall collapses for DoS 0.02, Web 0.00, Botnet 0.00,
  Scan 0.19; it stays high where a similar family was seen (DDoS 0.988, Brute force 0.628). Qualifies H6: the P2 RF had seen one attack type.
- Tuned SSL vs rf_unseen on AUC: RF better on DoS, DDoS, Web, Botnet (CI < 0); default SSL recall beats rf_unseen on Botnet (+0.295, CI > 0).

### Outcomes of E13 (written 2026-10-05, after the run)
Report `results_comparison/E13/E13_report.md`. Tue-Fri, 1,620,815 test flows: Zeek recall 0.007, FPR 2.87% (974 alerted benign flows/h) vs
Suricata 0.005 / 0.28% / 93 per h. Zeek detects only FTP-Patator (0.497) and SSH-Patator (0.584), via one FTP::Bruteforcing and one
SSH::Password_Guessing notice, plus the Heartbleed flow; no notice for DoS, DDoS, scans (Zeek 9 has no scan detector), web attacks or SQLi.
All 31,880 SSL::Invalid_Server_Cert notices are on benign flows (94% "unable to get local issuer certificate", mostly public sites: likely a
2025 root store checking 2017 chains, i.e. a replay artefact). Zeek OR tuned SSL: SSH-Patator recall 0.001 -> 0.584, FTP-Patator 0.66 -> 0.83,
overall 0.434 -> 0.438 at FPR 0.53% -> 3.39%.
