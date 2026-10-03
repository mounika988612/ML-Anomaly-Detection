# Explainable self-supervised anomaly detection for network traffic

This is the code behind my master thesis (DTU Compute, in collaboration with Terma A/S). The idea is simple: learn what
normal network traffic looks like from unlabeled telemetry, flag whatever does not fit, and explain each alert in words
an analyst can act on.

My **primary dataset is CIC-IDS2017**. I did not use the usual CSV release. Instead I ran Suricata myself on the five
official pcap files, so the models see real multi-source telemetry: flow records plus TCP, DNS, HTTP and TLS/SSH/FTP
session events, the same kind of data Suricata produces in a real SOC. **CSE-CIC-IDS2018** and **UNSW-NB15** are my two
comparison datasets.

The models only ever train on benign traffic. Every attack in the test data is therefore new to them, which is the
zero-day setting the thesis is about. I compare them with three kinds of baselines:

- **rule-based:** Suricata with the Emerging Threats Open rules (plus Zeek in one capture study),
- **unsupervised ML:** Isolation Forest, PCA reconstruction and a plain autoencoder,
- **supervised ML:** a Random Forest trained on labelled attacks.

On top of the research pipeline there is a small production layer: an exportable model bundle, an HTTP scoring API and
a command-line tool.

**Contents**
1. [Quick start](#1-quick-start)
2. [Setting up the `mlenv` conda environment](#2-setting-up-the-mlenv-conda-environment)
3. [Datasets](#3-datasets)
4. [Running the pipeline](#4-running-the-pipeline)
5. [Project structure](#5-project-structure)
6. [Methods and evaluation protocol](#6-methods-and-evaluation-protocol)
7. [Results on CIC-IDS2017 (primary dataset)](#7-results-on-cic-ids2017-primary-dataset)
8. [Results on the comparison datasets](#8-results-on-the-comparison-datasets)
9. [Explanations and analyst reports](#9-explanations-and-analyst-reports)
10. [Scoring service (production use)](#10-scoring-service-production-use)
11. [Deviations from the proposal and known limits](#11-deviations-from-the-proposal-and-known-limits)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Quick start

Open the **Anaconda Prompt** and run:

```bat
cd /d "D:\Thesis source code\anomaly_pipeline"
conda env create -f environment.yml      :: only the first time (then do the one-time step in section 2)
conda activate mlenv
pytest                                   :: 87 tests, about 2 minutes
python run.py all                        :: CIC-IDS2017: prepare -> train -> evaluate -> explain
```

Without `--config`, `run.py` runs the primary experiment (`config_cic2017_monday.yaml`): train on Monday, test on
Tuesday to Friday. It needs the Suricata flow table `..\external\cic2017\suricata2017_rebuilt.parquet`. If that file is
not there yet, build it from the pcaps first (section 4, "Building CIC-IDS2017 from the pcaps"). Results end up in
`results_cic2017_monday\`.

---

## 2. Setting up the `mlenv` conda environment

Everything runs natively on Windows in an Anaconda environment called `mlenv` (Python 3.11).

### Option A: create it from `environment.yml` (recommended)

```bat
cd /d "D:\Thesis source code\anomaly_pipeline"
conda env create -f environment.yml
conda activate mlenv
```

This installs everything, including the pipeline itself as an editable package (`pip install -e .`), so changes under
`ids_pipeline\` take effect straight away and the `ids-detect` command is available. Then do the one-time step below.

### Option B: install into an existing `mlenv` by hand

```bat
conda activate mlenv
conda install -y numpy pandas pyarrow numba scikit-learn matplotlib pyyaml
python -m pip install torch==2.13.0 --index-url https://download.pytorch.org/whl/cpu
python -m pip install lime shap
python -m pip install -e ".[research,dev]"
```

### One-time step after installing torch: keep a single OpenMP library

numpy and scikit-learn from conda use Intel's OpenMP library (`libiomp5md.dll`), and the pip torch wheel brings its own
copy. With both loaded, Python aborts with `OMP: Error #15 ... libiomp5md.dll already initialized`. The fix is to let
torch use the conda copy by renaming its own:

```bat
conda activate mlenv
ren "%CONDA_PREFIX%\Lib\site-packages\torch\lib\libiomp5md.dll" libiomp5md.dll.bak
```

Do this again whenever torch is reinstalled. Please don't use `KMP_DUPLICATE_LIB_OK=TRUE` instead: Intel documents it
as unsafe, and it can silently give wrong results.

### Things I learned the hard way

- **Use `python -m pip`, not plain `pip`.** On this machine `pip` can point to the *base* environment even when
  `mlenv` is active, and packages then land in the wrong place.
- **Install `pyarrow` and `numba` with conda, not pip.** Only the conda builds work here. `torch` comes from pip (CPU index).
- **Keep exactly one PyTorch.** Don't add conda's `pytorch`, `torchvision` or `torchaudio` on top of the pip torch.

### Check the installation

```bat
python -c "import torch, sklearn, pyarrow, numba, shap, lime, ids_pipeline; print('OK', torch.__version__)"
pytest
```

All 87 tests should pass. The combination I use (checked 2026-09-30): Python 3.11, torch 2.13 CPU, scikit-learn 1.9,
numpy 2.4, pandas 3.0, pyarrow 23 (conda), numba 0.65 (conda), shap 0.51, lime 0.2.

In VS Code, pick `mlenv` as the interpreter (`Ctrl+Shift+P` → *Python: Select Interpreter*) so the editor, terminal
and test runner all agree. The same dependencies also exist as plain pip files: `requirements.txt` (research),
`requirements-serve.txt` (scoring service only) and `requirements-dev.txt` (everything plus pytest and ruff); CI and the
Docker image use these.

---

## 3. Datasets

The data sits next to this folder, not inside it, and is not in git:

```
D:\Thesis source code\
├── anomaly_pipeline\          <- this repository
├── dataset\
│   ├── CICIDS2017\            <- PRIMARY: the five official CIC-IDS2017 pcaps (~52 GB)
│   │   ├── Monday-WorkingHours.pcap        benign only, used for training
│   │   └── Tuesday- Wednesday- Thursday- Friday-WorkingHours.pcap   attack days
│   ├── CICIDS2018\            <- comparison: CSE-CIC-IDS2018 CSVs, one per day
│   └── UNSW_NB15\             <- comparison: UNSW_NB15_training-set.csv (175,341) and UNSW_NB15_testing-set.csv (82,332)
└── external\
    ├── cic2017\               <- my Suricata build of CIC-IDS2017 (section 4)
    │   ├── rules\                       the frozen ET Open rule file (sha256 + fetch date), same for every day
    │   ├── <Day>\flows.parquet          one labelled row per Suricata flow, plus day_manifest.json and Suricata logs
    │   ├── suricata2017_rebuilt.parquet all five days together (1,963,820 flows, 14 attack types)
    │   └── LABEL_AUDIT.md, manifest.json
    └── pcap\                  <- CSE-CIC-IDS2018 victim captures for the Suricata/Zeek comparison (thu22 is the one used)
```

- **CIC-IDS2017** comes from https://www.unb.ca/cic/datasets/ids-2017.html (registration form). Only files with their
  final `*-WorkingHours.pcap` name count; `Unconfirmed *.crdownload` files are unfinished browser downloads and can be
  deleted. Wednesday's file is spelled `Wednesday-workingHours.pcap` with a lower-case `w`.
- **CSE-CIC-IDS2018** is used as the CICFlowMeter CSVs (Wed-14, Thu-15, Wed-21, Thu-22, Thu-01, Fri-02).
- **UNSW-NB15:** use the official file names. The underscore spelling some mirrors use also works. Careful with the
  Hugging Face mirror `Mireu-Lab/UNSW-NB15`: it ships the two files swapped as `test.csv`/`train.csv`, so check the row
  counts above.
- Paths in the configs are relative to the config file. Environment variables override them: `IDS_DATA_DIR`,
  `IDS_UNSW_DIR`, `IDS_SURICATA_PARQUET`, `IDS_CAPTURE_DIR`, `IDS_WORK_DIR` and `IDS_RESULTS_DIR`.

---

## 4. Running the pipeline

### The four stages

Every experiment goes through the same four stages, and `run.py` runs one or all of them:

```bat
python run.py prepare      :: load the data, chronological train/validation/test split, build the feature space
python run.py train        :: train all models and baselines, write anomaly scores
python run.py evaluate     :: metrics, per-attack recall, FPR/recall trade-off, time-to-detect, plots
python run.py explain      :: SHAP / LIME / native attributions + a plain-language analyst report
python run.py all          :: all four in order
```

`prepare` caches its output in the experiment's `work_*` folder, so the second run is much faster. `train` takes the
longest: about a minute per neural model plus a few minutes of latent-kNN scoring each.

### Choosing an experiment

Each config file is one complete experiment with its own `work_*` and `results_*` folder:

| config | dataset / protocol | output folder |
|---|---|---|
| **`config_cic2017_monday.yaml`** (default) | **CIC-IDS2017, protocol P1: train Monday, test Tue–Fri (main result)** | `results_cic2017_monday\` |
| `config_suricata2017_rebuilt.yaml` | CIC-IDS2017, protocol P2: train Mon+Tue, test Wed–Fri (adds the supervised RF) | `results_suricata2017_rebuilt\` |
| `config_cic2017_3day.yaml`, `config_cic2017_3day_sup.yaml` | interim run on Mon–Wed only (superseded) | `results_cic2017_3day*\` |
| `config_cic2018.yaml` | CSE-CIC-IDS2018, 2-day protocol | `results\` |
| `config_multiday.yaml` | CSE-CIC-IDS2018, 3-day protocol | `results_multiday\` |
| `config_context*.yaml`, `config_multiday_context*.yaml` | CSE-CIC-IDS2018 with the temporal-context view (section 8.2); `_clean` = mislabelled flows removed | `results_context*\`, `results_multiday_context*\` |
| `config_unsw.yaml` | UNSW-NB15, official train/test split | `results_unsw\` |

Some examples:

```bat
python run.py all --config config_suricata2017_rebuilt.yaml
python run.py train --config config_cic2017_monday.yaml --only ssl_mm_role ae_concat
python run.py explain --config config_cic2017_monday.yaml --method ssl_mm_experts
python run.py compare --config config_cic2018.yaml --capture-dir ..\external\pcap\thu22 --day Thursday-22-02-2018 --attacker 18.218.115.60
```

With `--only`, the stage comes *before* the options (`train --only ...`).

**Don't overwrite the thesis numbers by accident.** A new run overwrites its `results_*` folder. When experimenting,
redirect the output first:

```bat
set IDS_WORK_DIR=work_test
set IDS_RESULTS_DIR=results_test
python run.py all
```

### What you get

- `work_*\` holds caches, the feature space and the trained models. It can be deleted at any time and is rebuilt on
  the next run (I only keep `work_cic2017_monday\`, which `explain` needs for the primary models).
- `results_*\scores\*.npz` holds the raw validation and test scores of every method.
- `metrics_overall.csv` / `metrics_overall_adapted.csv`: ROC-AUC, PR-AUC, precision, recall, FPR, MCC and F1 per method,
  at the fixed validation threshold and after per-day recalibration.
- `recall_per_attack*.csv`, `fpr_recall_tradeoff*.csv`, `incidents*.csv`, `time_to_detection*.csv` and plots.
- `explanations*.md`, `explanation_quality*.csv` and `analyst_report*.md` (section 9).

### Building CIC-IDS2017 from the pcaps (experiment E7)

This is the one part that needs Docker Desktop, because Suricata runs in a pinned container. In Git Bash, set `PY` to
the `mlenv` interpreter first (plain `python` in Git Bash may be the base environment):

```bash
export PY=/d/SoftwareTools/Users/maida/anaconda3/envs/mlenv/python.exe
for d in Monday Tuesday Wednesday Thursday Friday; do
  bash logs/run_E7.sh sensors $d ../dataset/CICIDS2017/$d-WorkingHours.pcap   # Suricata, ~1 h per day
done
bash logs/run_E7.sh parquet          # suricata2017_rebuilt.parquet + LABEL_AUDIT.md (read the audit before training!)
bash logs/run_E7.sh train config_cic2017_monday.yaml config_suricata2017_rebuilt.yaml   # 3 seeds each + bootstrap CIs (~5 h)
$PY scripts/e7_report.py --p1 config_cic2017_monday.yaml --p2 config_suricata2017_rebuilt.yaml --tag 5day
```

Each day's raw `eve.json` (1.5–2.5 GB) is deleted once its `flows.parquet` is written. Long runs on my laptop need two
precautions: start them so they survive the terminal closing (e.g. through WMI,
`Invoke-CimMethod -ClassName Win32_Process -MethodName Create`), and keep Windows awake with `logs/keep_awake.ps1`.

### Other experiment scripts

The earlier experiments (E1–E6, on CSE-CIC-IDS2018) are kept as bash scripts in `logs\run_*.sh` next to their logs.
Run them from Git Bash after `conda activate mlenv`. `run_all.sh`, `run_knn.sh`, `run_unsw.sh` and `run_compare.sh`
reproduce the first rounds of results, and `docker_ids.sh` runs Suricata and Zeek on any pcap.

---

## 5. Project structure

```
anomaly_pipeline\
├── run.py                     entry point (prepare / train / evaluate / explain / compare)
├── config*.yaml               one file per experiment (section 4)
├── environment.yml, requirements*.txt, pyproject.toml
│
├── ids_pipeline\              the actual code
│   ├── adapters\suricata2017.py   CIC-IDS2017: Suricata events -> five telemetry modalities (flow, tcp, dns, http, session)
│   ├── adapters\unsw.py           UNSW-NB15
│   ├── data.py                loading, chronological splitting (and the CSE-CIC-IDS2018 CSV loader)
│   ├── features.py            feature spaces, service-role assignment, temporal-context features
│   ├── models.py              the multi-modal SSL network and the plain autoencoder
│   ├── baselines.py           Isolation Forest, PCA reconstruction, supervised Random Forest
│   ├── scoring.py             per-role score calibration, latent-kNN scoring, tail-probability (min-p) fusion
│   ├── train.py               trains every method, writes validation/test scores, fuses the modality experts
│   ├── evaluate.py            metrics, per-attack recall, trade-off curves, incidents, plots, hybrids
│   ├── explain.py             SHAP, LIME and native attributions + their quality checks
│   ├── analyst_report.py      turns alerts + attributions + Suricata context into readable reports
│   ├── signature_compare.py   lines up Suricata/Zeek output with labelled flows
│   ├── schema.py, bundle.py, service.py, api.py, cli.py   the production layer (section 10)
│   └── utils.py               config loading (with ${ENV:-default} paths), logging, seeding
│
├── scripts\                   analyses that work on saved scores (no retraining)
│   ├── cic2017_suricata.sh, build_suricata2017.py   CIC-IDS2017 pcaps -> Suricata -> labelled flow table
│   ├── e7_report.py               E7 hypotheses, CIC-IDS2017 tables and figures
│   ├── clean_eval.py, multiseed.py  seed-averaged metrics and bootstrap confidence intervals
│   ├── explore_fusion.py          the post-hoc modality-expert analysis (section 7.4)
│   ├── label_audit.py, knn_reference.py, window_alerts.py, contrastive_diagnostics.py   E4–E6 analyses
│   ├── hparam_search.py, operating_point_analysis.py, alert_aggregation.py, compare_proposed_vs_baselines.py
│   └── eda.py, loadtest.py
│
├── tests\                     pytest suite (87 tests)
├── docs\                      API.md, DEPLOYMENT.md, LABEL_AUDIT.md, SURICATA2017_PROVENANCE.md, cic2017_attack_schedule.csv
├── results_comparison\        PREREGISTRATION.md and the final tables and figures
├── logs\, models\, work_*\, results_*\   experiment scripts and logs, model bundle, caches, outputs   [not in git]
└── Dockerfile, docker-compose.yml, .github\workflows\ci.yml, docker_ids.sh
```

How one run moves through the code:

```
pcap -> Suricata -> parquet ─┐
CSV (2018) / CSV (UNSW) ─────┴─> data.py / adapters ─> features.py ─> train.py ─> scores ─┬─> evaluate.py ─> metrics, plots
                                                      (modalities,   (models.py,          └─> explain.py  ─> analyst_report.py
                                                       roles)         baselines.py, scoring.py)
```

---

## 6. Methods and evaluation protocol

### The proposed model

The model gets one small encoder per telemetry modality. For CIC-IDS2017 those are the Suricata event types: **flow**,
**tcp**, **dns**, **http** and **session** (TLS, SSH, FTP, anomaly events). It learns by self-supervision only:

- **masked-feature reconstruction:** hide a quarter of the features and predict them back,
- **modality dropout:** drop a whole modality now and then, so the model has to use the others,
- **a cross-modal contrastive term** (InfoNCE), which turned out not to matter (section 7.2),
- **a role embedding**, so a web server and a DNS server each get their own idea of "normal".

The final anomaly score (`ssl_mm_role_knn`) is the distance of a flow's latent embedding to its 5 nearest benign
training embeddings **of the same service role**. Nothing in training or scoring uses attack labels.

### All methods

| name | what it is |
|---|---|
| **`ssl_mm_role_knn`** | **the proposed model** with role-aware latent-kNN scoring (pre-registered in E7) |
| `ssl_mm_role` | the same network scored by reconstruction error (the original score) |
| `ssl_mm_global_knn` | no role information at all (ablation for role-awareness) |
| `ssl_no_contrastive_knn` | without the contrastive term (ablation) |
| `ssl_only_<modality>` | a model that sees one telemetry source only (ablation for multi-modality) |
| `ssl_mm_experts` | post-hoc variant: the single-source models fused by min-p (section 7.4) |
| `ae_concat`, `ae_concat_knnrole` | plain autoencoder: reconstruction error, and with the *same* role-aware kNN scorer |
| `iforest`, `pca_recon` | unsupervised ML baselines |
| `rf_supervised` | supervised ML baseline (sees labelled attacks of the training period) |
| `suricata_signature` | rule-based baseline: the flow raised at least one Suricata ET Open alert |
| `hybrid_sig_or_<method>` | Suricata alert OR anomaly alert, the way the two would run side by side |
| `ssl_mm_twoview_knn` | CSE-CIC-IDS2018 only: flow view + temporal-context view fused by min-p (section 8.2) |

### Protocol

- Models train on **benign traffic only**. The latest 15% of each training day's benign traffic is held out as
  validation, and its 99th percentile score becomes the alert threshold (a 1% target false-positive rate).
- Testing uses only **later days**, so no test attack has been seen in training.
- The supervised Random Forest is the exception on purpose: it sees the training period's attacks, which lets me show
  how it fails on attacks it has never seen.

| protocol | config | train (benign only) | test |
|---|---|---|---|
| **CIC-IDS2017 P1 (primary)** | `config_cic2017_monday.yaml` | Monday | Tuesday–Friday, all 14 attack types |
| CIC-IDS2017 P2 | `config_suricata2017_rebuilt.yaml` | Monday, Tuesday | Wednesday–Friday |
| CSE-CIC-IDS2018 2-day | `config_cic2018.yaml` | Wed-14, Thu-15 | Wed-21, Thu-22, Thu-01, Fri-02 |
| CSE-CIC-IDS2018 3-day | `config_multiday.yaml` | Wed-14, Thu-15, Wed-21 | Thu-22, Thu-01, Fri-02 |
| UNSW-NB15 | `config_unsw.yaml` | benign part of the official training set | official test set |

`evaluate` writes every table twice: once with the fixed threshold from the benign validation data, and once
(`*_adapted`) after per-day recalibration, where the first 30 minutes of each test day act as an unlabeled reference
window (and are then left out of the metrics). The fixed threshold is the primary mode.

---

## 7. Results on CIC-IDS2017 (primary dataset)

### 7.1 How the dataset was built

The public CIC-IDS2017 CSVs are CICFlowMeter features, a single source with known labelling problems. I wanted real
multi-source telemetry instead, so `scripts/cic2017_suricata.sh` runs a pinned Suricata 8.0.7 with one frozen ET Open
rule file on each official pcap, and `scripts/build_suricata2017.py` turns its output into one row per Suricata flow.
Labels come **only** from CIC's published attack schedule (`docs/cic2017_attack_schedule.csv`: attacker IP, victim IP,
time window), never from Suricata's alerts.

| day | Suricata flows | benign | attack flows | excluded |
|---|---|---|---|---|
| Monday | 343,005 | 343,005 | none (training day) | 0 |
| Tuesday | 294,902 | 287,910 | FTP-Patator 4,010; SSH-Patator 2,551 | 431 |
| Wednesday | 471,217 | 292,083 | DoS Hulk 161,096; GoldenEye 7,530; Slowhttptest 4,222; Slowloris 3,895; Heartbleed 1 | 2,390 |
| Thursday | 334,452 | 265,761 | Infiltration-Portscan 66,514; Web Brute Force 1,362; XSS 679; Infiltration 14; SQL Injection 12 | 110 |
| Friday | 524,643 | 264,355 | Portscan 161,264; DDoS 96,813; Botnet 743 | 1,468 |

Every build writes a `LABEL_AUDIT.md`, and I read it before training anything. In short:

- Suricata lost no state on any day, and all days use the same rules (same sha256).
- Each attack window is dominated by the scheduled attacker on the expected ports.
- Traffic the schedule can't explain is **excluded, not guessed**: SSH-Patator running ~20 minutes past its published
  end, the Heartbleed victim's normal HTTPS to the firewall, and the bots still beaconing to their C&C after the
  Botnet window. Excluded flows count neither as benign nor as attack.
- Suricata alerts on 0.71% of benign flows (2.10% on Monday). That is the honest false-positive rate of the
  rule-based baseline.

An earlier third-party Suricata version of CIC-IDS2017 from Hugging Face had undocumented provenance and labels that
disagreed with CIC's own documentation. I withdrew and deleted it on 2026-10-03; it only survives as history in
`PREREGISTRATION.md`. Details: `docs/SURICATA2017_PROVENANCE.md`.

### 7.2 Main result: pre-registered experiment E7

I wrote the hypotheses down in `results_comparison/PREREGISTRATION.md` **before** processing any Tuesday–Friday pcap.
E7 uses the shipped hyperparameters (no tuning on this dataset), seeds 42, 1 and 2, and 95% block-bootstrap confidence
intervals of paired differences (`scripts/clean_eval.py`). Tables and figures are in `results_comparison/E7_5day_tables.md`
and `figE7_5day_*.png`.

**P1 (train Monday, test Tue–Fri: 1,620,815 flows, 510,706 attacks), fixed threshold, mean of 3 seeds:**

| method | ROC-AUC | PR-AUC | recall | realised FPR | MCC | incident recall | false alerts/h |
|---|---|---|---|---|---|---|---|
| Suricata ET signatures (rule-based) | 0.501 | 0.316 | 0.004 | 0.28% | 0.01 | 0.73 | 93 |
| **Proposed `ssl_mm_role_knn`** | **0.945 ± 0.006** | 0.858 | 0.115 ± 0.189 | 0.50% | 0.18 | 0.70 | 169 |
| Hybrid: Suricata OR proposed | 0.942 | 0.844 | 0.118 | 0.77% | 0.18 | **0.91** | 261 |
| `ae_concat_knnrole` (AE + same scorer) | 0.936 | **0.875** | **0.295** | 0.96% | **0.44** | 0.88 | 327 |
| `ae_concat` (reconstruction error) | 0.937 | 0.748 | 0.000 | 0.15% | −0.02 | 0.06 | 53 |
| `iforest` | 0.953 | 0.825 | 0.086 | 1.26% | 0.14 | 0.59 | 427 |
| `pca_recon` | 0.923 | 0.704 | 0.000 | 0.17% | −0.02 | 0.09 | 57 |
| `ssl_mm_global_knn` (no roles) | 0.792 | 0.689 | 0.085 | 0.70% | 0.17 | 0.83 | 237 |
| `ssl_no_contrastive_knn` | 0.944 | 0.856 | 0.156 | 0.47% | 0.26 | 0.62 | 160 |

**P2 (train Mon+Tue, test Wed–Fri), fixed:** proposed 0.951 ROC-AUC / recall 0.070; `ae_concat_knnrole` 0.961 / 0.262;
`iforest` 0.957 / 0.050; Suricata 0.499 / 0.001; and the **supervised `rf_supervised` 0.612 / 0.004**. (P1 has no
supervised baseline, because Monday contains no attacks to learn from.)

**The hypotheses and what happened:**

| H | claim | outcome | evidence (P1; paired ROC-AUC difference, 95% CI) |
|---|---|---|---|
| H1 (RQ1) | SSL detects unseen attacks: AUC ≥ 0.90 and beats AE / iForest / PCA | **not supported** | AUC 0.945, but vs AE +0.008 [−0.019, 0.034], vs iForest −0.009 [−0.043, 0.017], vs PCA +0.021 [−0.004, 0.043] |
| H2 (RQ1/RQ4) | beats the rule-based IDS at a controlled false-alert rate | supported | recall 0.115 vs 0.004 at FPR 0.50% |
| H3 | signatures + anomaly model work better together | supported | incident recall 0.91 vs 0.70 / 0.73 |
| H4 (RQ2) | multiple telemetry sources beat every single source | supported | flow +0.013 [0.005, 0.020], tcp +0.19, http +0.14, session +0.49, dns +0.74 (all CIs > 0) |
| H5 (obj. 4) | role-aware beats global | supported | +0.153 [0.007, 0.329] |
| H6 (RQ1) | supervised learning fails on unseen attacks | supported | P2: RF recall 0.004 vs 0.070 |
| H7 | the gain is not only the kNN scorer | **not supported** | vs `ae_concat_knnrole` +0.009 [−0.025, 0.044] |

**Which attacks get caught (P1, fixed, seed mean).** Suricata catches what it has a rule for: FTP-Patator 0.49,
SQL injection 0.67, Infiltration 0.21 and the single Heartbleed flow. It catches nothing of Botnet, DoS, DDoS, Portscan
or Web Brute Force. The proposed model adds Botnet 0.27, Portscan 0.28, FTP-Patator 0.33, Slowloris 0.19 and
Infiltration-Portscan 0.14, but almost no DoS Hulk or DDoS (0.005). `ae_concat_knnrole` catches DDoS 0.98 and Slowloris
0.57, and `iforest` is the only one with some DoS Hulk (0.25) and GoldenEye (0.38). Web XSS, SQL injection and
SSH-Patator stay close to 0 for every anomaly model.

### 7.3 What this means

What the results support:

1. Trained only on benign traffic, the proposed model ranks unseen attacks well (ROC-AUC 0.945 on P1, 0.951 on P2), far
   better than the signature IDS, which sits at chance (0.50) because it alerts on so few attack flows.
2. The supervised Random Forest collapses on attack types it hasn't seen (0.61 AUC, recall 0.004). That is exactly the
   zero-day gap the proposal starts from.
3. Both design choices hold up with confidence intervals on real Suricata telemetry: using several telemetry sources
   beats any single one, and role-aware baselines beat a single global one.
4. Signatures and the anomaly model complement each other: together they find 91% of attack incidents.

What the results do **not** support, and what I state in the thesis:

- The SSL encoder is not shown to be better than simpler unsupervised models. Isolation Forest, PCA and especially the
  autoencoder with the same role-aware kNN scorer are statistically tied with it in ROC-AUC, and the AE+kNN has higher
  recall and MCC. The contrastive term has no measurable effect (vs `ssl_no_contrastive_knn` +0.001 [−0.001, 0.003]).
- The operating point is unstable across seeds. Recall at the fixed threshold is 0.005 / 0.007 / 0.334 for seeds
  42 / 1 / 2 while ROC-AUC barely moves (0.938–0.950): the Monday threshold lands just above or just below the big
  DoS Hulk/DDoS score cluster. Per-day recalibration lifts recall to 0.38 (FPR 1.9%) but doesn't remove the sensitivity.

An interim single-seed run on Monday–Wednesday only (`config_cic2017_3day*.yaml`) gave ROC-AUC 0.919 for the proposed
model and 0.979 for `iforest`. It was superseded by E7.

### 7.4 Exploratory follow-up: fusing the single-source experts (`ssl_mm_experts`)

**This part is post hoc.** I tried it after seeing the E7 test labels, so it is not a thesis claim (it is logged as X1
in `PREREGISTRATION.md`). E7 suggested that one source often carries the signal on its own (the TCP-only model was
strong), so `ssl_mm_experts` keeps the five single-source models separate. Each one is ranked against its own benign
validation scores, and the most extreme one decides (min-p, the same fusion I already used for the two-view model on
CSE-CIC-IDS2018). `train` builds it automatically from the experts' scores (`train.fuse_experts`; switch it off with
`scoring.expert_fusion: false`).

| CIC-IDS2017 P1, 3 seeds | ROC-AUC | recall (fixed) | MCC (fixed) | recall at an equal 1% FPR |
|---|---|---|---|---|
| E7 `ssl_mm_role_knn` | 0.945 | 0.12 | 0.18 | 0.22 |
| `iforest` | **0.953** | 0.09 | 0.14 | 0.02 |
| `ae_concat_knnrole` | 0.936 | 0.30 | 0.44 | 0.21 |
| **`ssl_mm_experts`** | 0.951 ± 0.007 | **0.43** | **0.54** | **0.37** |

It ties the best baseline on ranking, and at the operating point an analyst actually sees, it catches the most attacks.
On seed 42 the Suricata-OR-experts hybrid finds 95% of attack incidents. The costs are real, though:

- many more false alerts at the fixed threshold (about 644 per hour on seed 42, versus 58 for the E7 model),
- recall still depends on the seed (± 0.17),
- it is *worse* than the E7 model on CSE-CIC-IDS2018 (0.56) and UNSW-NB15 (0.87), where the "modalities" are just
  column groups of one flow record rather than separate sources.

My reading is that keeping separate experts helps when the sources really are separate. That is a hypothesis, and I
pre-registered its test as **E8, to run on Terma telemetry**. One warning from doing this: my first version averaged
z-scores and looked far better (0.98 AUC), but that was a numerical artifact. Most benign flows have identical TCP/HTTP
features, so those experts' spread is zero and every small deviation blew up. I discarded it. Reproduce the comparison
with `python scripts/explore_fusion.py` (output in `results_explore\`). The full run is in
`results_experts_cic2017_monday\`.

---

## 8. Results on the comparison datasets

### 8.1 Overview

ROC-AUC / PR-AUC / recall at the benign-validation threshold (~1% target FPR):

| dataset | `ssl_mm_role_knn` | `ae_concat_knnrole` | `ae_concat` | `iforest` | supervised RF | Suricata |
|---|---|---|---|---|---|---|
| **CIC-IDS2017 P1** (3 seeds) | 0.945 / 0.858 / 0.12 | 0.936 / **0.875 / 0.29** | 0.937 / 0.748 / 0.00 | **0.953** / 0.825 / 0.09 | n/a | 0.501 / 0.316 / 0.00 |
| UNSW-NB15 | 0.928 / 0.947 / 0.67 | 0.928 / 0.944 / 0.61 | 0.910 / 0.929 / 0.64 | 0.827 / 0.850 / 0.22 | **0.985 / 0.989 / 0.98** | – |
| CSE-CIC-IDS2018 3-day | 0.829 / 0.435 / 0.02 | 0.792 / 0.361 / 0.03 | 0.705 / 0.336 / 0.02 | 0.525 / 0.160 / 0.01 | **0.893 / 0.686** / 0.00 | – |
| CSE-CIC-IDS2018 2-day | **0.779 / 0.460** / 0.01 | 0.745 / 0.425 / 0.01 | 0.593 / 0.320 / 0.01 | 0.434 / 0.256 / 0.00 | 0.568 / 0.391 / 0.00 | – |

On the two comparison datasets the proposed model beats Isolation Forest and the autoencoder's reconstruction score
(by a wide margin on CSE-CIC-IDS2018, by less on UNSW-NB15), and it ties or narrowly beats the autoencoder once both use
the same scorer. The supervised RF wins on UNSW-NB15 and the CSE-CIC-IDS2018 3-day
split, but there it has seen the same attack types in training, so it isn't a zero-day setting. With its fixed
threshold it flags almost nothing on unseen attacks.

Keep in mind that **neither comparison dataset has separate telemetry sources.** Their "modalities" are four views of
one CICFlowMeter or Argus record, so the multi-modal claim (RQ2) rests on CIC-IDS2017.

How the scoring was chosen: I designed the latent-kNN scoring on CSE-CIC-IDS2018 (2-day) and UNSW-NB15, before
CIC-IDS2017 was used. A label-free hyperparameter search (`scripts/hparam_search.py`, 15 candidates scored on synthetic
anomalies) was flat within ~0.002 AUC, so I kept the defaults. The contrastive term not helping is not a tuning problem.

### 8.2 CSE-CIC-IDS2018: temporal context, label audit and experiments E1–E6

These were my development experiments. The full record is in `PREREGISTRATION.md`. The main points:

- **A label error in the dataset** (`docs/LABEL_AUDIT.md`, `scripts/label_audit.py`). On Wed-21, 358,623 flows
  labelled Benign are really the HOIC attack's connections recorded in the reverse direction. They were 99% of that
  day's "benign" test flows. The `*_clean` configs remove them, and the 2-day false-positive rate of the kNN methods
  drops from ~16% to 1.5–2%. Separately, 17.6% of Infiltration flows are feature-for-feature identical to benign flows,
  which caps Infiltration recall for any flow-level detector.
- **Temporal context and two-view fusion** (`config_context*.yaml`). Single flows can't show floods, scans or beacons,
  so I added 12 context features (flows per second to the same port, distinct ports per window, near-identical flows,
  time since the previous similar flow) as a separate view, fused with the per-flow view by min-p. On the 2-day
  protocol this took ROC-AUC from 0.49 to 0.94 and caught HOIC (0.995). On the held-out 3-day clean protocol (E4), though,
  the flow view alone ranked slightly higher, so "multiple views beat every single view" was **not** supported there.
  The SSL encoder did beat the autoencoder inside the two-view design (+0.021 [0.016, 0.026]).
- **E5, recall at a controlled false-alert rate.** Flow-level recall at 1% FPR is limited by how separable Bot and
  Infiltration are at all (oracle recall 2–26%). A window-level alert test cut false alerts from 48 to 0.26 per hour
  but kept only 16% of the recall, so it missed its pre-registered target.
- **E6, why the contrastive term doesn't help.** In a 256-flow batch, 82–97% of flows share their exact TCP / HTTP /
  session block with another flow (mostly all-zero blocks of absent protocols), so the contrastive task is at chance.
  Masking those false negatives makes it train, but detection still doesn't improve.
- **A late-fusion kNN variant** (`*_latefuse_knn`, one kNN per modality, maximum taken) was worse everywhere (e.g.
  CIC-IDS2017 0.862 vs 0.945) and is kept only for reproducibility.

### 8.3 UNSW-NB15

UNSW-NB15 uses its official train/test split, with models fit on the benign flows of the training part only. The data
has no timestamps and is sorted by class, so the adapter shuffles it with a fixed seed (the benign validation slice is a
random 15%). The test set has 82,332 flows, 55% of them attacks. The supervised RF reaches 0.985 AUC, but UNSW's train
and test sets contain the same attack types, so this is not a zero-day comparison.

### 8.4 Suricata and Zeek on a real CSE-CIC-IDS2018 capture

`docker_ids.sh` runs Suricata and Zeek on the Thu-22 victim capture, and `run.py compare` lines their alerts up with the
labelled attack flows (all 362 matched). With the 3-day models:

| attack | Suricata ET | Zeek | `ssl_mm_role_knn` | Suricata OR `ssl_mm_role_knn` |
|---|---|---|---|---|
| Brute Force -Web (249) | 0.016 | 0 | **0.418** | 0.426 |
| Brute Force -XSS (79) | **0.899** | 0 | 0.760 | **0.937** |
| SQL Injection (34) | 0.265 | 0 | 0.147 | 0.353 |

Same story as on CIC-IDS2017: signatures catch what has a rule (XSS), the anomaly model catches behaviour without one
(web brute force), and the two together do best. It's a single capture with three attack types, so I treat it as an
illustration.

---

## 9. Explanations and analyst reports

`python run.py explain [--config <cfg>] [--method <model>]` explains a sample of alerts (stratified over attack types,
plus some false alarms) with three methods: **native** (per-feature reconstruction error), **SHAP** (KernelExplainer on
the calibrated score, with a per-role benign background) and **LIME** (one explainer per role). It writes
`explanations*.md`, `explanation_quality*.csv` and an **analyst report** (`analyst_report*.md`), where each alert reads:

1. **Verdict and priority.** *CONFIRMED* if a Suricata signature and the anomaly model both fire, *ANOMALY ONLY*
   otherwise (possibly new activity, possibly a false alarm). Signatures are translated into what they mean.
2. **Why it looks abnormal.** The top SHAP features in plain units next to the normal range for that service role (e.g.
   "bytes sent by the server: 190 KB vs 242 B normal"). Only features that come up in two independent SHAP runs count
   as stable, and behaviour hints ("looks like a flood / scan / slow attack") are built only from stable evidence.
3. **Network context.** IPs and ports, HTTP URIs, DNS names and the TLS server name from the Suricata record.
4. **Next steps** and a confidence level. The ground-truth label comes last and is there for evaluation only.

Explanation quality is checked automatically:
- **deletion fidelity:** does the score drop when the top features are reset to normal, compared with random features?
- **stability:** do two SHAP or LIME runs agree on the top features?
- **cross-method agreement:** do the methods agree with each other?

Some highlights:

- I fixed two LIME problems along the way: one dataset-wide background, and too many features for its sample size.
  That turned its deletion fidelity on CSE-CIC-IDS2018 2-day from −0.03 to +0.25.
- **SHAP is faithful and improved on all three datasets** (deletion drop 0.23–0.40). LIME did well on CSE-CIC-IDS2018
  2-day but got worse on UNSW-NB15, and I report that rather than average it away. For the analyst-facing reports I rely
  on SHAP and native attribution, and keep LIME as a cross-check.
- For `ssl_mm_experts` on CIC-IDS2017 P1, the SHAP deletion drop is 0.32 against −0.12 for random features. Each alert
  also shows which source drove it, e.g. "http 90%" for a DDoS flow.

These checks are automatic only. Whether the explanations actually help an analyst still needs a human review with
the Terma supervisor.

---

## 10. Scoring service (production use)

On top of the research code there is a deployable layer: model bundle export, input validation, an HTTP API, a batch
CLI, tests, CI and Docker.

```bat
ids-detect export --config config_multiday.yaml --out models\prod        :: trained run -> pickle-free, checksummed bundle
set IDS_API_KEYS=...
ids-detect serve --bundle models\prod --host 0.0.0.0                     :: POST /v1/score, GET /v1/model, /healthz /readyz /metrics
ids-detect score --input flows.csv --bundle models\prod --output scored.csv
ids-detect recalibrate --benign site_benign.csv --bundle models\prod --out models\site   :: fixes threshold drift without retraining
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) and [docs/API.md](docs/API.md). Some honest caveats:

- The service hasn't been tested on customer data yet.
- Bundles from the `*context*` configs can't be served, because the service doesn't compute context features for
  single incoming flows.
- `ssl_mm_experts` can't be exported as a bundle yet.

---

## 11. Deviations from the proposal and known limits

- **Multi-modal telemetry is shown on CIC-IDS2017 only.** It is the only dataset with real, separate sources (Suricata
  flow, TCP, DNS, HTTP and session events). The two comparison datasets have one flow record per connection. The
  adapter interface (`ids_pipeline/adapters/`) is where Terma's Suricata or Zeek data would plug in.
- **The SSL model ties simpler unsupervised models on CIC-IDS2017** (H1 and H7 not supported), and its
  fixed-threshold recall depends strongly on the seed. The post-hoc `ssl_mm_experts` (section 7.4) is not a claim
  until E8 has been run.
- **CIC-IDS2017 labels are time-window labels** from CIC's schedule: everything between the scheduled attacker and
  victim inside the window counts as attack, failed attempts and replies included. Today's ET Open rules know these
  2017 attacks in hindsight, so the signature baseline is an optimistic upper bound for a 2017 signature IDS.
- **"Role" means the service role derived from the destination port** (web, DNS, remote admin, ...), because the
  public data has no asset inventory. On Terma data this would be the real asset role or network zone.
- The CSE-CIC-IDS2018 CSVs are cut at 1,048,576 rows (the Excel limit) and contain duplicates; ~20% of the Wed-14 rows
  are duplicates and are dropped.
- **Explanation usefulness (RQ3) is only measured automatically so far**, not rated by an analyst.
- **Nothing has been validated on Terma's own traffic yet.** All results are on public benchmarks. Testing on Terma
  telemetry (E8) needs a Terma adapter and, ideally, some labelled period such as a red-team exercise.

---

## 12. Troubleshooting

| symptom | cause and fix |
|---|---|
| `DLL load failed` when importing `pyarrow` | The pip pyarrow is installed. `python -m pip uninstall -y pyarrow`, then `conda install -y pyarrow`. |
| `Could not find/load shared object file 'llvmlite.dll'`, or `shap` fails to import | The pip numba is installed. `python -m pip uninstall -y numba llvmlite`, then `conda install -y numba`. |
| `Unable to find a usable engine; tried using: 'pyarrow'` | pyarrow is missing or not loading; see the first row. |
| `OMP: Error #15 ... libiomp5md.dll already initialized`, or `Fatal Python error: Aborted` | Two OpenMP libraries are loaded. Do the one-time step in section 2. |
| `import torchvision` fails with `operator torchvision::nms does not exist` | A leftover conda torchvision. `conda remove -y torchvision torchaudio cpuonly pytorch-mutex`. |
| `ModuleNotFoundError` right after installing a package | It went into the base environment. Use `python -m pip install ...` with `mlenv` active. |
| `python run.py all` fails: `suricata2017_rebuilt.parquet` not found | The CIC-IDS2017 flow table hasn't been built yet. Run the steps in section 4, or point `IDS_SURICATA_PARQUET` at the file. |
| UNSW run fails with file not found | The two CSVs must be in `dataset\UNSW_NB15\` (or `IDS_UNSW_DIR`) with their official names. |
| `error: ...` from `run.py` about a config or column | `ConfigError` / `DataError`: the message names the file or column. Check the paths in section 3. |
| Old results were overwritten | Set `IDS_RESULTS_DIR` / `IDS_WORK_DIR` before experimenting (section 4). |
| A 2018 or UNSW run is slow the first time | Its `work_*` cache was removed to save disk space and is being rebuilt. That's expected. |
| `failed to connect to the docker API ... dockerDesktopLinuxEngine` | Docker Desktop isn't running. Start it and wait until `docker info` answers. |
| Suricata on one day takes many hours instead of ~1 h | Windows went to sleep and Suricata paused with it. Run `logs/keep_awake.ps1` during long jobs. |
| A long run stops when the terminal, VS Code or the Claude session closes | Start long jobs through WMI (`Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=...}`). |
| `python` in Git Bash is Python 3.13 / packages missing | Git Bash finds the base Anaconda python. Use the `mlenv` interpreter explicitly (`export PY=.../envs/mlenv/python.exe`). |
| `explain --method ssl_mm_role_knn` fails with `FileNotFoundError ... ssl_mm_role_knn.pkl` | `explain` works on the trained network, not on a scoring variant. Use `--method ssl_mm_role` (the default) or `ssl_mm_experts`. |
