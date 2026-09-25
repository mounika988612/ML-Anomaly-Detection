# Explainable self-supervised anomaly detection (CSE-CIC-IDS2018)

## Requirements
You need Python 3.10 or newer. For the complete development setup, install the dependencies and run the test suite with:
```
pip install -r requirements-dev.txt
pytest
```
The serving dependencies are listed separately in `requirements-serve.txt`. If PyTorch cannot run on Windows, use the WSL2 setup described at the end of this document.

## Production use (scoring service)
The research pipeline is complemented by a deployable layer: model **bundle** export, input validation, HTTP API and batch CLI, tests, CI, Docker.
```
ids-detect export --config config_multiday.yaml --out models/prod       # trained run -> pickle-free, checksummed bundle
IDS_API_KEYS=... ids-detect serve --bundle models/prod --host 0.0.0.0    # POST /v1/score, GET /v1/model, /healthz /readyz /metrics
ids-detect score --input flows.csv --bundle models/prod --output scored.csv
ids-detect recalibrate --benign site_benign.csv --bundle models/prod --out models/site   # threshold drift fix, no retraining
pip install -r requirements-dev.txt && pytest                            # 76 tests
```
See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (operations, drift, known limits) and [docs/API.md](docs/API.md) (contract). Not yet validated on customer data.

## Research pipeline
```
python run.py prepare    # clean CSVs -> chronological split -> feature space   (~1 min after first run)
python run.py train      # 8 neural models + 3 baselines -> results/scores/*.npz (~6 min, CPU)
python run.py evaluate   # metrics, per-attack recall, FPR trade-off, time-to-detect, plots
python run.py explain    # native / SHAP / LIME attribution + analyst text (results/explanations.md)
```
Settings are in `config.yaml`. Paths are relative to the config file and overridable with `IDS_DATA_DIR` (default `../dataset/CICIDS2018`), `IDS_WORK_DIR`, `IDS_RESULTS_DIR`. Outputs: `work/` (cache, models), `results/`.

## Protocol
- Train on **benign only** from Wed-14 and Thu-15 (self-supervised, no attack labels). Latest 15% of that benign traffic = validation, used for the alert threshold (99th percentile = 1% target FPR).
- Test on later days only: Wed-21 (DDoS), Thu-22 (web attacks), Thu-01 (infiltration), Fri-02 (bot). No attack type in the test set is seen in training.
- Supervised baseline (Random Forest) is trained on the labelled attacks of the training period, to expose the zero-day gap (RQ1).

## Methods
| name | what it is |
|---|---|
| `ssl_mm_role` | **proposed**: per-modality encoders (volume_timing, packet_size, protocol_flags, bulk_subflow), masked-feature reconstruction + modality dropout + cross-modal InfoNCE, role embedding, per-role score calibration |
| `ssl_mm_global` | same without any role information (objective 4 ablation) |
| `ssl_no_contrastive` | no cross-modal term (SSL ablation) |
| `ssl_only_<modality>` | single-modality models (RQ2) |
| `ssl_mm_twoview_knn` | **two-view** (only with `data.context_features`, see below): `ssl_mm_flow_knn` (4 per-flow modalities) and `ssl_only_temporal_context_knn` (5th modality: traffic context) fused by min-p on tail probabilities |
| `ae_concat`, `iforest`, `pca_recon` | unsupervised baselines |
| `rf_supervised` | supervised baseline |

## Deviations from the proposal you should know about
- **Where the "multi-modal telemetry" claim is actually demonstrated.** CSE-CIC-IDS2018 and UNSW-NB15 have no DNS/TLS/HTTP logs, only CICFlowMeter flow features, so their "modalities" are four views of one flow record (`features.MODALITIES`). Genuine multi-source telemetry (DNS, HTTP, TLS, SSH, FTP, parsed from Suricata's `eve.json`) exists only for **Suricata2017** (`adapters/suricata2017.py`, `MODALITIES` there). Read the thesis's multi-modal claim as demonstrated on Suricata2017; CSE-CIC-IDS2018/UNSW-NB15 demonstrate scale and the zero-day evaluation protocol with flow-derived pseudo-modalities. `features.MODALITIES` / the adapter interface is the extension point for real Zeek/Suricata sources on Terma data.
- **Role = service role from destination port** (web, remote_admin, ...) because this release has no IPs. On Terma data use asset role / network zone.
- The CSVs are truncated at 1,048,576 rows (Excel limit) and contain duplicates; ~20% of Wed-14 rows are duplicates and were dropped.
- `shap` now imports on this machine (0.52.0) and all `explain` results use `shap.KernelExplainer`. `explain.py` still falls back to a built-in permutation-Shapley estimator if `shap` cannot be imported (an earlier Windows Application Control block on numba).
- **Explanation usefulness (RQ3) is only automatically measured so far** (deletion fidelity, cross-seed stability, cross-method agreement in `explanation_quality*.csv`), not rated by a human analyst. A short review of `analyst_report*.md` alerts with the Terma supervisor is planned before submission to close this.
- **No validation on Terma's own traffic or environment.** All results are on public benchmark datasets; the serving layer (`api.py`, `service.py`, `bundle.py`) is production-shaped (bundle export, auth, drift monitoring, recalibration, Docker) but untested against live telemetry, a SIEM, or an asset-role inventory. See `docs/DEPLOYMENT.md` "Known limits" for the full list.

## Two evaluation protocols (both implemented)
| | config | train (benign only) | test |
|---|---|---|---|
| 2-day | `config.yaml` -> `results/` | Wed-14, Thu-15 | Wed-21, Thu-22, Thu-01, Fri-02 |
| 3-day | `config_multiday.yaml` -> `results_multiday/` | Wed-14, Thu-15, Wed-21 | Thu-22, Thu-01, Fri-02 |

Run the second with `python run.py --config config_multiday.yaml all`.
`evaluate` writes every table twice: fixed threshold (from benign validation data) and `*_adapted`
(per-day recalibration: the first 30 min of each test day are used as an unlabeled reference window to
re-centre/re-scale scores and re-derive the threshold; that window is then excluded from the metrics;
the supervised RF is not recalibrated). Validation data = the last 15% of benign traffic of *each* training day.
Per-role score scale is floored at 0.5x the global scale (`min_scale_ratio`); without it roles with
near-identical benign flows got a vanishing scale and the role-aware model produced AUC < 0.5.

## Current findings with the original reconstruction-error score (see results*/metrics_overall*.csv)
_Superseded by the latent-kNN scoring below (`ssl_mm_role_knn`: 2-day 0.779, 3-day 0.829 AUC), which is the proposed method._
Pooled ROC-AUC / recall at ~1% FPR:
- 2-day: all unsupervised methods 0.39-0.59 (proposed `ssl_mm_role` 0.49); Wed-21 HOIC flood is never detected.
- 3-day: `ae_concat` 0.70 > `ssl_mm_global` 0.61 > `ssl_mm_role` 0.58 > iforest/pca ~0.52. The plain autoencoder
  ranks best; the proposed multi-modal SSL model does not beat it in AUC. Recall at 1% FPR stays low (1-7%).
- Per-day recalibration restores the FPR to ~1% but does not improve ranking (AUC unchanged or lower).
- `rf_supervised` (3-day) ranks well (AUC 0.90, PR-AUC 0.78) but its fixed 0.5 threshold flags almost nothing on unseen attacks.
- Explanations (3-day): SHAP and native attribution beat random feature removal (deletion drop 0.29 / 0.27 vs -0.06); LIME is
  close to even (was -0.05 before the LIME fix below). SHAP top-10 stability across seeds is 0.50 (was 0.38). Only Bot /
  Infiltration / SQL-injection alerts fired, so DDoS and brute-force alerts are not explained. See "Explainability fix" below
  for the LIME/SHAP changes and the full before/after numbers on all four datasets.

## Signature IDS comparison (Suricata + Zeek on real pcap)
`docker_ids.sh` runs Suricata (Emerging Threats Open rules) and Zeek offline on the Thu-22 victim capture (172.31.69.28);
`python run.py compare --capture-dir ../external/pcap/thu22 --day Thursday-22-02-2018 --attacker 18.218.115.60`
aligns the labelled attack flows with the attacker's connections and writes `results/signature_comparison_*.csv` and
`results/signature_background_alerts_*.txt`. Suricata counts only "ET ..." signatures (engine/decode events ignored);
Zeek = any non-CaptureLoss notice on the attacker. 362/362 attack flows matched to 131 attacker connections.

Share of attack flows detected (ML models at the 1% FPR validation threshold):
| attack | Suricata ET | Zeek | ae_concat | ssl_mm_global | ssl_mm_role | Suricata OR ML |
|---|---|---|---|---|---|---|
| Brute Force -Web (249) | 0.016 | 0 | 0 | 0 | 0 | 0.016 |
| Brute Force -XSS (79) | 0.899 | 0 | 0.430 | 0.089 | 0 | 0.899 |
| SQL Injection (34) | 0.265 | 0 | 0 | 0 | 0 | 0.265 |

- Suricata detects the XSS attack well (signature exists) but almost none of the web brute force; Zeek raised no notice on the attacker
  (its only notice is an SSH password-guessing alert about an unrelated external host).
- The SSL models add nothing on top of Suricata here: the hybrid equals Suricata alone. Only `ae_concat` (43% of XSS) and
  `pca_recon` (27% / 47% of brute-force-web / XSS) catch anything Suricata misses on the web attacks, but at low recall.
- Suricata also raised 78 ET alerts on non-attacker sources (8.8/h), mostly SIP/port scans from the internet.
- Caveat: a single victim capture, three attack types; not a general claim about signature vs anomaly detection.

## UNSW-NB15 (`config_unsw.yaml` -> `results_unsw/`)
Official train/test partition; models are fit on the benign flows of the training partition only. UNSW has no timestamps and
its files are sorted by class, so the adapter uses a seeded random order (the benign validation slice is a random 15%).
Pooled test (82,332 flows, 55% attacks), ROC-AUC / recall at ~1-2% FPR:
- `ae_concat` 0.91 / 0.64, `ssl_no_contrastive` 0.90 / 0.62, `ssl_mm_global` 0.90 / 0.14, `ssl_mm_role` 0.89 / 0.10,
  iforest 0.83, pca_recon 0.84. Best single modality: `ssl_only_context` 0.85 (recall 0.50).
- `rf_supervised` 0.985 AUC, recall 0.98 at 19% FPR. Caveat: attack types are the same in train and test here, so this is NOT a
  zero-day setting, unlike the CSE-CIC-IDS2018 protocol.
- As on CSE-CIC-IDS2018, the plain autoencoder is as good as or better than the proposed multi-modal SSL model.

## Analyst reports: signature context + plain-language explanation (`ids_pipeline/analyst_report.py`)
`python run.py --config <cfg> [--method <model>] explain` also writes `analyst_report[_<model>].md` and
`analyst_report_summary[_<model>].csv`. Each alert states, in this order:
1. **Verdict / priority** - *CONFIRMED* (Suricata ET signature and the anomaly model both flag the flow; HIGH if signature severity <= 2)
   or *ANOMALY ONLY* (no signature: candidate novel activity or false alarm). Signatures are translated into what they mean.
2. **Why it looks abnormal** - top SHAP features in words with units, against the median / 95th percentile of benign training flows of
   the same service role ("bytes sent by the server: 190 KB vs 242 B normal"). Each is marked *stable* only if it is in the top-k of two
   independent SHAP runs; rule-based behaviour hypotheses ("consistent with a flood / scan / upload / slow attack / web probing ...")
   are built from stable evidence only and are secondary to a signature when one exists.
3. **Network context** - IPs/ports, HTTP URIs, DNS names, TLS server name (from the Suricata record or Zeek http.log).
4. **Next steps** and an explanation-confidence level. The ground-truth label is printed last, for evaluation only.

Signature sources: `suricata2017` config = Suricata alert + protocol fields stored per flow in the dataset; `config*.yaml` `report:` block =
Suricata eve.json + Zeek logs of the Thu-22 pcap (flow matched to an attacker connection by start time + destination port because the
CSV has no IPs). Example: `results_multiday/analyst_report_ae_concat.md` (`--method ae_concat`; `ssl_mm_role` raises no alert on the
Thu-22 web attacks) - 5 of 29 alerts are confirmed by `ET WEB_SERVER Script tag in URI ...` and show the actual `<script>` request.
`results_suricata2017/analyst_report_ssl_only_http.md` shows Suricata "TROJAN ... RAT Checkin" alerts with the bot's HTTP beacon URL.
Limits: on CSE-CIC-IDS2018 and UNSW-NB15 there is no signature source for most flows, so most alerts are ANOMALY ONLY; hypotheses are
heuristics, not diagnoses, and were not evaluated with analysts (RQ3 usefulness remains to be validated, e.g. with the Terma supervisor).

## Explainability fix: role-matched LIME background + capped feature count (`explain.py`)
Two concrete causes were found for LIME's poor showing (deletion-fidelity below random removal, near-zero agreement with SHAP/native):
1. `LimeTabularExplainer` was fit on one dataset-wide background sample. SHAP's background was already per-role (the benign validation flows of
   the same service role as the flow being explained); LIME's was not, so its local surrogate was fit against the wrong notion of "normal" for
   roles whose benign traffic differs from the pooled average. **Fix:** one `LimeTabularExplainer` per role, background = that role's benign
   training flows (falls back to the pooled sample for roles with too few).
2. `explain_instance(..., num_features=d)` forced LIME to fit a coefficient for *every* one of the ~70-90 features from ~1,000 perturbed samples
   per call - underdetermined, so the ridge fit was noisy. **Fix:** `num_features=30`, letting LIME's own selection pick the locally relevant
   subset (only the top 5-10 are used downstream anyway).
`shap.KernelExplainer`'s budget was also raised (background 20->40, `nsamples` 500->1200; measured cost was ~0.05-0.17s/alert, so this is cheap)
to reduce its own cross-seed variance. A separate check - raising `lime_samples` 1000->4000 - made LIME's estimate *more stable* (0.574->0.741 on
the 3-day set) but *less faithful* (deletion drop -0.060->-0.106): more samples converge more confidently onto a linear surrogate that is
systematically, not just noisily, misaligned with this non-linear latent-distance score. `lime_samples` was kept at 1000.

Before -> after (`explanation_quality*.csv`, all four datasets, same trained models, only the attribution methods changed):
| dataset | shap deletion drop | shap stability | lime deletion drop | lime stability | shap-lime agreement |
|---|---|---|---|---|---|
| CIC-2018 2-day | 0.169 -> 0.227 | 0.362 -> 0.517 | **-0.032 -> +0.252** | 0.484 -> 0.778 | 0.096 -> 0.276 |
| CIC-2018 3-day | 0.161 -> 0.293 | 0.376 -> 0.499 | -0.075 -> -0.060 | 0.483 -> 0.574 | 0.062 -> 0.179 |
| Suricata2017 | 0.819 -> 0.815 | 0.654 -> 0.762 | **-0.154 -> +0.412** | 0.646 -> 0.302 | 0.153 -> 0.349 |
| UNSW-NB15 | 0.391 -> 0.403 | 0.401 -> 0.576 | +0.037 -> **-0.096** | 0.365 -> 0.516 | 0.192 -> 0.197 |

**SHAP improved or held on all four datasets** (deletion fidelity flat-to-better, stability up everywhere, +0.10 to +0.22). **LIME improved
sharply on three of four** (2-day and Suricata2017 flipped from worse-than-random to clearly better-than-random deletion fidelity; agreement with
SHAP roughly doubled to tripled on 2-day/3-day/Suricata2017) **but regressed on UNSW-NB15** (+0.037 -> -0.096) - report this honestly, do not
average it away. Reading for RQ3: SHAP and native attribution are the methods to trust for analyst-facing explanations everywhere; LIME is now
informative on three of four telemetry sources but is not reliable enough to lead on, and should stay a secondary cross-check, not the primary
explanation, until the UNSW regression is understood (candidate cause: UNSW's `GenericSpace` features have different scale/sparsity per modality
than the CICFlowMeter/Suricata feature sets, worth checking before trusting LIME there).

## Latent-space scoring: the improved SSL method (`ssl_*_knn`)
**Change.** The original SSL score was mean reconstruction error, which dilutes anomalies and does not use the learned embedding (objective 6).
New score = mean distance of a flow's fused latent embedding to its k=5 nearest benign training embeddings (`scoring.LatentKNN`, 10k reference
flows). `ssl_mm_role_knn` searches only among benign flows of the **same service role** (objective 4), `ssl_mm_global_knn` searches globally.
Pooled calibration on benign validation data (1% target FPR). Nothing uses attack labels. `ae_concat_knn` (global) and `ae_concat_knnrole`
(role-aware) give the plain autoencoder the identical scorer, so gains cannot be attributed to the scoring trick alone.

**Model-selection protocol.** The scoring design was chosen on CSE-CIC-IDS2018 (2-day) and UNSW-NB15. Training hyper-parameters (contrastive
weight, epochs, dropout, mask ratio, size) were checked with a label-free pseudo-anomaly test (swapped modality blocks / extreme features on
benign validation flows); it was flat across all variants, so the defaults were kept. Suricata2017 was used as a confirmation set, but its first result
(threshold far too conservative because the role was normalised twice) led to switching to one pooled calibration, so it is **not** a clean held-out set.

This was re-checked more thoroughly (`scripts/hparam_search.py`, `results_multiday/hparam_search_*.csv`): a 15-candidate label-free grid over
`contrastive_weight` (0-0.4), `mask_ratio` (0.15-0.35), `epochs` (10/20), `latent_dim` (32/64) and `modality_dropout` (0/0.15/0.25) on the 3-day
config, scored by ROC-AUC of real benign validation flows vs. two synthetic-anomaly sets (a shuffled modality block; extreme feature values), never
touching attack labels. Result: again flat, all candidates within ~0.002 AUC of each other on that criterion; the mild best candidate
(`contrastive_weight=0.05`, `mask_ratio=0.35`) was retrained end-to-end and evaluated once on the real (labelled) test set as a check, not as
further tuning — `ssl_mm_role_knn` came back at 0.824 vs. 0.829 for the shipped defaults, i.e. no real change, and `ssl_no_contrastive_knn` still led
at 0.841. **Conclusion: the CIC-2018 3-day gap (contrastive multi-modal role-aware SSL not beating its own no-contrastive ablation) is not a
hyperparameter-tuning problem** under this architecture and this label-free selection criterion; it is reported as a negative result, not chased
further with the shipped config. `modality_dropout=0.15` (the shipped default) *was* confirmed best among 0/0.15/0.25 on this criterion, so the
motivation for forcing cross-modal learning during training is not thrown out, only the contrastive loss term's contribution to the final score.

ROC-AUC / PR-AUC / recall at the benign-validation threshold (fixed threshold, ~1% target FPR):
| dataset | `ssl_mm_role_knn` | `ae_concat_knnrole` | `ae_concat` (old score) | `iforest` | `ssl_mm_role` (old score) | supervised RF | Suricata signatures |
|---|---|---|---|---|---|---|---|
| Suricata2017 | **0.981 / 0.968 / 0.69** | 0.948 / 0.936 / 0.41 | 0.914 / 0.859 / 0.00 | 0.957 / 0.914 / 0.23 | 0.943 / 0.840 / 0.00 | 0.678 / 0.627 / 0.00 | 0.501 / 0.421 / 0.00 |
| UNSW-NB15 | 0.928 / 0.947 / 0.67 | 0.928 / 0.944 / 0.61 | 0.910 / 0.929 / 0.64 | 0.827 / 0.850 / 0.22 | 0.892 / 0.888 / 0.10 | **0.985 / 0.989 / 0.98** | - |
| CIC-2018 3-day | 0.829 / 0.435 / 0.02 | 0.792 / 0.361 / 0.03 | 0.705 / 0.336 / 0.02 | 0.525 / 0.160 / 0.01 | 0.614 / 0.207 / 0.09 | **0.893 / 0.686** / 0.00 | - |
| CIC-2018 2-day | **0.779 / 0.460** / 0.01 | 0.745 / 0.425 / 0.01 | 0.593 / 0.320 / 0.01 | 0.434 / 0.256 / 0.00 | 0.485 / 0.276 / 0.02 | 0.568 / 0.391 / 0.00 | - |
(3-day best SSL variant is `ssl_no_contrastive_knn` 0.842 / 0.479.)

**What this supports.** (1) Ranking quality of the SSL model improved on all four datasets (+0.04 to +0.24 AUC over its own old score) and it beats
`iforest`, PCA and the plain autoencoder's old score everywhere. (2) The role-aware search is what makes the role idea work: on Suricata2017
`ssl_mm_global_knn` is 0.765 AUC vs 0.981 role-aware. (3) On Suricata2017 it is the only method with both high AUC and usable recall at ~1% FPR.

**What it does not support (state this in the thesis).**
- On UNSW it ties the autoencoder given the same scorer; on the CIC-2018 3-day run the variant without the contrastive term is slightly better
  (0.842 vs 0.829), so the cross-modal contrastive objective is not shown to help. `ae_concat_knnrole` is close behind on most sets.
- The supervised RF is better in AUC on UNSW and CIC-2018 3-day (it sees the same attack types in training; not a zero-day setting), although its
  fixed 0.5 threshold flags almost nothing on unseen attacks.
- CIC-2018 recall at the fixed threshold stays 1-4%: benign traffic drifts between days (2-day protocol FPR 16.5% at the validation threshold), so
  the good ranking does not translate into a usable operating point. Per-day recalibration (`*_adapted`) does not fix this.

**vs Suricata/Zeek on the Thu-22 capture (3-day models, share of attack flows detected)** - `results_multiday/signature_comparison_*.csv`:
| attack | Suricata ET | Zeek | `ssl_mm_role_knn` | `ae_concat_knnrole` | Suricata OR `ssl_mm_role_knn` |
|---|---|---|---|---|---|
| Brute Force -Web (249) | 0.016 | 0 | **0.418** | **0.426** | 0.426 |
| Brute Force -XSS (79) | **0.899** | 0 | 0.760 | 0.468 | **0.937** |
| SQL Injection (34) | 0.265 | 0 | 0.147 | 0.353 | 0.353 |
The two are complementary: signatures catch attacks that have a rule (XSS), the SSL model catches behaviour without a rule (web brute force), and the
hybrid is the best of the three on XSS. Single capture, three attack types: an illustration, not a general claim.
Reproduce: `python run_knn.sh`-style retrain via `python run.py --config <cfg> train --only <neural methods>` then `evaluate`.

## Negative result: late-fusion latent-kNN (`*_latefuse_knn`)
Hypothesis: the fused embedding dilutes a signal that is strong in one modality (single-modality `ssl_only_*_knn` models had far higher F1/MCC
at the 1% FPR threshold on Suricata2017 and CIC-2018 3-day). Change (`train.py:_train_latefuse_knn`, `models.py:embed_modalities`): one role-aware
`LatentKNN` per modality on the same encoder, per-modality calibration, max over modalities. Run in WSL2 (torch is blocked by Windows Smart App Control).
Pooled ROC-AUC, fused `ssl_mm_role_knn` vs `ssl_mm_role_latefuse_knn`: CIC-2018 2-day 0.779 vs 0.706; Suricata2017 0.981 vs 0.378; CIC-2018 3-day 0.829 vs 0.769.
**It does not help** and is kept only for reproducibility (max over noisy modalities inflates false alarms). UNSW-NB15 was not run. The
single-modality gap is at the operating threshold (calibration), not necessarily in ranking, so fusion is not shown to be the cause.
**Threshold check (CIC-2018 3-day, `results_multiday/fpr_recall_tradeoff.csv`).** At matched target FPR the fused `ssl_mm_role_knn` and
`ssl_only_packet_size_knn` are similar: recall 0.009/0.016/0.024/0.097/0.479 vs 0.006/0.022/0.394/0.398/0.420 at 0.1/0.5/1/2/5% FPR. The single-modality
model's F1 0.52 comes from one threshold (1%) landing just below a large cluster of attack scores (recall jumps 0.02 -> 0.39); at 5% FPR the fused model is
higher. So the earlier "single modality beats the full model" F1 gap is largely a threshold artifact, not evidence that fusion hurts.
**Threshold-strategy check (3-day, offline on saved scores).** Pooled validation thresholds at the 99 / 99.5 / 99.9th percentile and per-role
validation thresholds all give recall 0.01-0.04 (MCC <= 0.044) for `ssl_mm_role_knn`, `ssl_no_contrastive_knn`, `ae_concat_knnrole`, `ssl_mm_global_knn`.
Even a label-using best-MCC threshold (upper bound, not deployable) needs ~16-25% FPR to reach recall ~0.83 (MCC 0.45-0.56). So the low recall at 1% FPR
is a separability limit of the flow features for Infiltration/Bot (attacks look like benign traffic), not a threshold-selection problem.

## Temporal-context modality and two-view fusion (`config_context.yaml` -> `results_context/`)
**Problem.** On the 2-day protocol every method missed DDoS-HOIC (668,461 flows, 64% of all attack flows), Bot and most Infiltration. The
per-flow modalities cannot see these attacks: one HOIC request looks like ordinary web traffic, and a flood, a beacon or a scan only becomes
visible in aggregate. The CSVs have no IPs, so per-host behaviour is not available either.

**Change 1: a 5th modality, `temporal_context`** (`features.CONTEXT_MODALITY`, `add_context_features`, switched on by `data.context_features: true`).
12 features per flow computed from timestamp, destination port and flow "shape" (dst port, protocol, fwd/bwd packet and byte counts):
flows in the same second and trailing 60 s, overall and to the same port; that port's share of the load; distinct destination ports per 1 s / 10 s
(scanning); near-identical flows per 1 s / 60 s and their share of the port's traffic (floods, bots); seconds since the previous identical flow and
the previous flow to this port (beaconing). Computed over each full cleaned day **before** the train/validation split and any sampling, attacks
included (as a deployed sensor would see them), labels unused. Timestamps have 1 s resolution, so "same second" includes flows later in that second.
Checked against a brute-force count in `tests/test_features_scoring.py`. Default configs are unchanged; the baselines get the same 81 features.

**Change 2: two-view fusion** (`evaluate.TWO_VIEW`, `min_p`). Putting all 5 modalities into one fused embedding (`ssl_mm_role_knn` in
`results_context/`) does not work: the 4 per-flow modalities drown the context signal and HOIC is still ranked *below* benign traffic on its day
(within-day ROC-AUC 0.004, recall 0% at the adapted threshold). Instead `ssl_mm_flow` (SSL-MM on the 4 per-flow modalities) and
`ssl_only_temporal_context` are trained separately, each with its latent-kNN score. Each score is turned into its empirical upper-tail probability
among its own benign reference scores (validation for the fixed threshold, the unlabeled first 30 min of the day for `_adapted`), and the fused score
is the smallest tail probability (max of −log p). The threshold is the (1 − FPR) quantile of the fused reference score. A plain max of the two
calibrated scores fails because the context score has a much heavier benign tail, sets the threshold and hides the web attacks (XSS 0%).

**Results, 2-day protocol, `metrics_overall_adapted.csv` (1% target FPR):**

| method | ROC-AUC | PR-AUC | precision | recall | FPR | MCC | F1 |
|---|---|---|---|---|---|---|---|
| `ssl_mm_twoview_knn` | **0.937** | **0.889** | 0.976 | 0.653 | 0.74% | **0.735** | 0.783 |
| `ssl_only_temporal_context_knn` | 0.874 | 0.866 | 0.982 | 0.661 | 0.57% | 0.744 | 0.790 |
| `ssl_mm_flow_knn` (= `ssl_mm_role_knn` in `results/`) | 0.487 | 0.361 | 0.412 | 0.009 | 0.62% | 0.017 | 0.018 |
| `ssl_mm_role_knn` (5 modalities, one embedding) | 0.572 | 0.360 | 0.587 | 0.028 | 0.92% | 0.072 | 0.054 |
| `rf_supervised` | 0.878 | 0.825 | 0.290 | 0.000 | 0.00% | 0.000 | 0.000 |
| `ae_concat_knnrole` | 0.586 | 0.367 | 0.438 | 0.015 | 0.87% | 0.027 | 0.028 |

**Latest result.** On this 2-day experiment, the two-view SSL model is the strongest method for ranking attacks: it reaches 0.937 ROC-AUC
and 0.735 MCC after per-day recalibration, compared with 0.487 ROC-AUC for the flow-only SSL model and 0.878 for the supervised RF.
The result is not a claim that SSL wins every operating-point metric: the context-only model has slightly higher recall and F1 at this particular
threshold. A second seed gives the same direction, with two-view SSL at 0.855 ROC-AUC versus 0.796 for the role-only SSL model.

Recall per attack (adapted), flow view / context view / **two-view**: HOIC 0 / 0.995 / **0.995**; LOIC-UDP 1.0 / 0.806 / **1.0**;
XSS 0.506 / 0 / **0.468**; Web brute force 0.285 / 0 / **0.273**; SQL injection 0.059 / 0 / 0.029; Infiltration 0.032 / 0.238 / 0.100;
Bot 0.018 / 0.006 / 0.022. The two views are complementary (context: floods and scans; flow: web attacks), and only the fusion gets both, which is
the first result on CSE-CIC-IDS2018 where multiple views beat every single view. `ssl_mm_flow_knn` reproduces the original `ssl_mm_role_knn`
exactly (ROC-AUC 0.7746, fixed threshold), so old and new results are directly comparable.

**Limits.**
- **Depends on per-day recalibration.** With the fixed validation threshold the DDoS day's benign traffic is still flagged almost entirely
  (pooled FPR ~16%, as for every method before; `metrics_overall.csv`), although the context view now also flags the attacks there.
- **Sensitive operating point.** At 0.1% / 0.5% target FPR two-view recall collapses to 0.4% / 0.6% (HOIC sits just above the 1% threshold);
  from 1% to 5% it is stable at 0.65-0.72 (`fpr_recall_tradeoff_adapted.csv`).
- **Bot (2%) and Infiltration (10%) remain mostly missed**; fusion loses part of the context view's Infiltration recall (24%).
  Bot beaconing is probably slower than the 1 s / 60 s windows.
- **Not a clean held-out result.** The context features were designed after seeing which attacks were missed, and min-p was chosen over
  raw max, mean, smooth max and Fisher fusion by comparing them on the labelled test days (`logs/fusion_offline*.py`). The UNSW-NB15 and
  3-day protocols have not been run with this change, and it is a single seed.
- The context view is still derived from CICFlowMeter records, not a separate telemetry source; the multi-source claim remains Suricata2017's.
- The scoring service does not compute context features for single incoming flows; bundles exported from this config are not servable yet.

Reproduce (WSL2): `python run.py prepare --config config_context.yaml`, then `python run.py train --config config_context.yaml --only ssl_mm_flow
ssl_only_temporal_context ssl_mm_role ssl_mm_global ssl_no_contrastive ae_concat iforest pca_recon rf_supervised`, then `python run.py evaluate
--config config_context.yaml` (`logs/run_context.sh` does all three).

## Running in WSL2 (if torch is blocked on Windows)
Windows Smart App Control can block the unsigned DLLs in pip `torch`/`numba` (on this machine it now also blocks scikit-learn), so all
experiments run in the WSL2 venv `.venv-linux` (Python 3.14.4, torch 2.14.0 CPU, scikit-learn 1.9.1, shap 0.52.0); `bash scripts/setup_wsl_env.sh`
creates it. Manually: create a venv, `pip install --index-url https://download.pytorch.org/whl/cpu torch`
and `pip install -r requirements.txt`, then use the normal configs (paths are portable now; the old `config*_wsl.yaml` files were removed), e.g.
`python run.py train --config config_multiday.yaml --only ssl_mm_role` (put the stage before `--only`), then `python run.py evaluate --config config_multiday.yaml`.
