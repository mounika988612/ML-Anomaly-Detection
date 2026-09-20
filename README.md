# Explainable self-supervised anomaly detection (CSE-CIC-IDS2018)

Thesis ML anomaly detection pipeline

```
python run.py prepare    # clean CSVs -> chronological split -> feature space   (~1 min after first run)
python run.py train      # 8 neural models + 3 baselines -> results/scores/*.npz (~6 min, CPU)
python run.py evaluate   # metrics, per-attack recall, FPR trade-off, time-to-detect, plots
python run.py explain    # native / SHAP / LIME attribution + analyst text (results/explanations.md)
```
Settings are in `config.yaml`. Data: `D:/Thesis source code/dataset/CICIDS2018`. Outputs: `work/` (cache, models), `results/`.

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
| `ae_concat`, `iforest`, `pca_recon` | unsupervised baselines |
| `rf_supervised` | supervised baseline |

## Deviations from the proposal you should know about
- **The dataset has no DNS/TLS/HTTP logs**, only CICFlowMeter flow features. "Modalities" are therefore four views of the flow record. `features.MODALITIES` is the extension point for Zeek/Suricata sources 
- **Role = service role from destination port** (web, remote_admin, ...) because this release has no IPs.  use asset role / network zone.
- The CSVs are truncated at 1,048,576 rows (Excel limit) and contain duplicates; ~20% of Wed-14 rows are duplicates and were dropped.
- `shap` cannot be imported on this machine (Windows Application Control blocks numba's `_box.pyd`), so `explain.py` falls back to a built-in permutation-Shapley estimator. If `shap` imports elsewhere it is used automatically (KernelExplainer).

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

## Current findings (see results*/metrics_overall*.csv)
Pooled ROC-AUC / recall at ~1% FPR:
- 2-day: all unsupervised methods 0.39-0.59 (proposed `ssl_mm_role` 0.49); Wed-21 HOIC flood is never detected.
- 3-day: `ae_concat` 0.70 > `ssl_mm_global` 0.61 > `ssl_mm_role` 0.58 > iforest/pca ~0.52. The plain autoencoder
  ranks best; the proposed multi-modal SSL model does not beat it in AUC. Recall at 1% FPR stays low (1-7%).
- Per-day recalibration restores the FPR to ~1% but does not improve ranking (AUC unchanged or lower).
- `rf_supervised` (3-day) ranks well (AUC 0.90, PR-AUC 0.78) but its fixed 0.5 threshold flags almost nothing on unseen attacks.
- Explanations (3-day): SHAP and native attribution beat random feature removal (deletion drop 0.22 / 0.27 vs -0.05); LIME
  does not (-0.05). SHAP top-10 stability across seeds is only ~0.45. Only Bot / Infiltration / SQL-injection alerts fired, so
  DDoS and brute-force alerts are not explained.

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
