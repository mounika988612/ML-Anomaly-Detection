# Explainable self-supervised anomaly detection for network traffic

This repository is the code for my master thesis. It trains self-supervised, role-aware anomaly detectors on
network telemetry. The primary dataset is **CIC-IDS2017, rebuilt by running Suricata on the official pcaps** (real
multi-source telemetry: flow, TCP, DNS, HTTP and session events; section 8.8). CSE-CIC-IDS2018 and UNSW-NB15 are the two
comparison datasets. The models are compared with classic ML baselines and signature IDSs (Suricata, Zeek), and each
alert is explained in plain language for a security analyst.
The models learn only from benign traffic, so every attack in the test data is new to them. The evaluation is
therefore a zero-day setting.

Next to the research pipeline there is a small production layer: an exportable model bundle, an HTTP scoring API and
a command-line tool.

**Contents**
1. [Quick start](#1-quick-start)
2. [Setting up the `mlenv` conda environment](#2-setting-up-the-mlenv-conda-environment)
3. [Datasets](#3-datasets)
4. [Running the pipeline](#4-running-the-pipeline)
5. [Project structure](#5-project-structure)
6. [Methods and evaluation protocol](#6-methods-and-evaluation-protocol)
7. [Scoring service (production use)](#7-scoring-service-production-use)
8. [Results and findings](#8-results-and-findings)
9. [Deviations from the proposal and known limits](#9-deviations-from-the-proposal-and-known-limits)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Quick start

Open the **Anaconda Prompt** and run:

```bat
cd /d "D:\Thesis source code\anomaly_pipeline"
conda env create -f environment.yml      :: only the first time (then do the one-time step in section 2)
conda activate mlenv
pytest                                   :: 87 tests, about 2 minutes
python run.py all                        :: prepare -> train -> evaluate -> explain
```

The results end up in `results\`. Section 4 explains every stage and config.

---

## 2. Setting up the `mlenv` conda environment

All experiments run natively on Windows in an Anaconda environment called `mlenv` (Python 3.11).

### Option A: create it from `environment.yml` (recommended)

```bat
cd /d "D:\Thesis source code\anomaly_pipeline"
conda env create -f environment.yml
conda activate mlenv
```

This installs everything, including the pipeline itself as an editable package (`pip install -e .`). Changes to
the code under `ids_pipeline\` take effect immediately, and the `ids-detect` command becomes available. Then do the
one-time step below.

### Option B: install into an existing `mlenv` by hand

```bat
conda activate mlenv
conda install -y numpy pandas pyarrow numba scikit-learn matplotlib pyyaml
python -m pip install torch==2.13.0 --index-url https://download.pytorch.org/whl/cpu
python -m pip install lime shap
python -m pip install -e ".[research,dev]"
```

Then do the one-time step below.

### One-time step after installing torch: keep a single OpenMP library

numpy and scikit-learn from conda use Intel's OpenMP library (`libiomp5md.dll`), and the pip torch wheel ships its own
copy. With two copies loaded, Python aborts with `OMP: Error #15: Initializing libiomp5md.dll, but found
libiomp5md.dll already initialized`, depending on which package is imported first. The fix is to let torch use the
conda copy by renaming its own:

```bat
conda activate mlenv
ren "%CONDA_PREFIX%\Lib\site-packages\torch\lib\libiomp5md.dll" libiomp5md.dll.bak
```

Repeat this whenever torch is reinstalled or upgraded with pip. Do **not** use `KMP_DUPLICATE_LIB_OK=TRUE` instead;
Intel documents it as unsafe, and it can silently produce wrong results.

### Things to keep in mind

- **Use `python -m pip`, not plain `pip`.** On this machine `pip` can resolve to the *base* environment's pip even
  when `mlenv` is active, so packages silently land in the wrong environment.
- **Install `pyarrow` and `numba` with conda, not pip.** The conda versions of these two packages are the ones that
  work in this environment. `torch` is installed with pip from the PyTorch CPU index.
- **Have only one PyTorch in the environment.** Do not add conda's `pytorch`, `torchvision` or `torchaudio` on top of
  the pip torch. Two PyTorch installs in one environment overwrite each other's files.

### Check the installation

```bat
python -c "import torch, sklearn, pyarrow, numba, shap, lime, ids_pipeline; print('OK', torch.__version__)"
pytest
```

All 87 tests should pass. The working combination (checked 2026-09-30, and a full `python run.py all` reproduces the
2-day results, e.g. `ssl_mm_role_knn` ROC-AUC 0.7746): Python 3.11, torch 2.13 CPU, scikit-learn
1.9, numpy 2.4, pandas 3.0, pyarrow 23 (conda), numba 0.65 (conda), shap 0.51, lime 0.2.

In VS Code, select `mlenv` as the interpreter (`Ctrl+Shift+P` → *Python: Select Interpreter*). That way the editor,
the terminal and the test runner all use the same environment.

The dependency lists also exist as plain pip files: `requirements.txt` (research), `requirements-serve.txt` (scoring
service only) and `requirements-dev.txt` (everything plus pytest and ruff). CI and the Docker image use these.

---

## 3. Datasets

The data lives next to this folder, not inside it:

```
D:\Thesis source code\
├── anomaly_pipeline\          <- this repository
├── dataset\
│   ├── CICIDS2017\            <- official CIC-IDS2017 pcaps (primary dataset, ~52 GB)
│   │   ├── Monday-WorkingHours.pcap   (benign only: training day)
│   │   └── Tuesday-  Wednesday-  Thursday-  Friday-WorkingHours.pcap   (attack days)
│   ├── CICIDS2018\            <- CSE-CIC-IDS2018 CSVs, one per day
│   │   ├── Wednesday-14-02-2018.csv   Thursday-15-02-2018.csv   (training days)
│   │   └── Wednesday-21-02-2018.csv   Thursday-22-02-2018.csv   Thursday-01-03-2018.csv   Friday-02-03-2018.csv
│   └── UNSW_NB15\
│       ├── UNSW_NB15_training-set.csv   (175,341 flows)
│       └── UNSW_NB15_testing-set.csv    (82,332 flows)
└── external\
    ├── cic2017\               <- CIC-IDS2017 rebuilt by us (scripts/cic2017_suricata.sh + build_suricata2017.py)
    │   ├── rules\                       frozen ET Open rule file (sha256 + fetch date), shared by all days
    │   ├── <Day>\flows.parquet          one labelled row per Suricata flow, plus day_manifest.json and suri\ logs
    │   ├── suricata2017_rebuilt.parquet all five days (1,963,820 flows, 14 attack types)
    │   └── LABEL_AUDIT.md, manifest.json
    └── pcap\thu22\            <- Thu-22 victim capture + Suricata/Zeek output (signature comparison)
```

- **CIC-IDS2017 pcaps** come from https://www.unb.ca/cic/datasets/ids-2017.html (registration form). Only files with
  their final `*-WorkingHours.pcap` name count; `Unconfirmed *.crdownload` files are unfinished or duplicate browser
  downloads (~11 GB each) and can be deleted once the real file is there. Sections 4 (E7) and 8.7 describe how the pcaps
  become `suricata2017_rebuilt.parquet`. Each day's raw `eve.json` (1.5–2.5 GB) is deleted once its `flows.parquet` is built.
- **UNSW-NB15 file names:** use the official names `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` (as in
  `dataset\UNSW_NB15\`). The underscore spelling some mirrors use (`UNSW_NB15_training_set.csv`) also works. The Hugging
  Face mirror `Mireu-Lab/UNSW-NB15` ships the two files swapped as `test.csv`/`train.csv`, so check the row counts above.
- Paths in the configs are relative to the config file. You can point them elsewhere with environment variables:
  `IDS_DATA_DIR`, `IDS_UNSW_DIR`, `IDS_SURICATA_PARQUET`, `IDS_CAPTURE_DIR`, `IDS_WORK_DIR` and `IDS_RESULTS_DIR`.

---

## 4. Running the pipeline

### The four stages

Every experiment has the same four stages. `run.py` runs one or all of them:

```bat
python run.py prepare      :: clean the CSVs, chronological train/validation/test split, build the feature space
python run.py train        :: train all neural models and baselines, write anomaly scores
python run.py evaluate     :: metrics, per-attack recall, FPR/recall trade-off, time-to-detect, plots
python run.py explain      :: SHAP / LIME / native attributions + plain-language analyst report
python run.py all          :: all four in order
```

Timings on a normal laptop CPU for the default config: `prepare` takes a few minutes on the first run and about a
minute afterwards (it caches in `work\`). `train` takes the longest: roughly a minute per neural model, plus a few
minutes of latent-kNN scoring each.

### Choosing an experiment (config files)

Each config is a complete experiment with its own `work_*` and `results_*` folders. Pass it with `--config`:

| config | dataset / protocol | output folder |
|---|---|---|
| `config.yaml` (default) | CSE-CIC-IDS2018, 2-day protocol | `results\` |
| `config_multiday.yaml` | CSE-CIC-IDS2018, 3-day protocol | `results_multiday\` |
| `config_context.yaml` | 2-day + temporal-context modality (two-view model) | `results_context\` |
| `config_multiday_context.yaml` | 3-day + temporal context | `results_multiday_context\` |
| `config_context_clean.yaml` | 2-day + context, mislabelled HOIC flows removed | `results_context_clean\` |
| `config_multiday_context_clean.yaml` | 3-day + context, clean labels | `results_multiday_context_clean\` |
| **`config_cic2017_monday.yaml`** | **CIC-IDS2017 rebuilt, primary protocol P1: train Monday, test Tue–Fri (section 8.8)** | `results_cic2017_monday\` |
| `config_suricata2017_rebuilt.yaml` | CIC-IDS2017 rebuilt, protocol P2: train Mon+Tue, test Wed–Fri (with the supervised RF) | `results_suricata2017_rebuilt\` |
| `config_cic2017_3day.yaml`, `config_cic2017_3day_sup.yaml` | interim E7a run on Mon–Wed only (superseded by E7) | `results_cic2017_3day*\` |
| `config_unsw.yaml` | UNSW-NB15, official train/test split | `results_unsw\` |

Examples:

```bat
python run.py all --config config_multiday.yaml
python run.py train --config config_multiday.yaml --only ssl_mm_role ae_concat
python run.py explain --config config_multiday.yaml --method ae_concat
python run.py compare --capture-dir ..\external\pcap\thu22 --day Thursday-22-02-2018 --attacker 18.218.115.60
```

With `--only`, write the stage *before* the options (`train --only ...`).

**Keeping old results.** A new run overwrites its `results_*` folder. To keep the thesis numbers untouched while you
experiment, redirect the output first:

```bat
set IDS_WORK_DIR=work_test
set IDS_RESULTS_DIR=results_test
python run.py all
```

### What you get

`work*\` holds cached data, the feature space, trained models and raw scores (`scores\*.npz`). You can delete it at
any time; it is rebuilt. `results*\` holds the outputs you read:

- `metrics_overall.csv` / `metrics_overall_adapted.csv`: ROC-AUC, PR-AUC, precision, recall, FPR, MCC and F1 per method,
  at the fixed validation threshold and after per-day recalibration
- `per_attack_recall*.csv`, `fpr_recall_tradeoff*.csv`, time-to-detect tables and plots
- `explanations.md`, `explanation_quality*.csv`: attributions and their automatic quality checks
- `analyst_report*.md`: one plain-language report per alert (see section 8)

### Experiment scripts

The experiment runs in the thesis (E1–E6) are recorded as bash scripts in `logs\run_*.sh`, next to their log files.
They call `python`, so run them from Git Bash *after* activating `mlenv` in the same shell:

```bash
conda activate mlenv
bash logs/run_E4.sh
```

The older `run_all.sh`, `run_knn.sh`, `run_unsw.sh` and `run_compare.sh` in the root folder reproduce the first rounds
of results. `docker_ids.sh` runs Suricata and Zeek on a pcap and needs Docker Desktop.

**E7 (CIC-IDS2017 primary dataset)** is driven by `logs/run_E7.sh` and needs Docker Desktop for the sensor step. Set
`PY` to the `mlenv` interpreter first (in Git Bash, `python` may be the base environment):

```bash
export PY=/d/SoftwareTools/Users/maida/anaconda3/envs/mlenv/python.exe
for d in Monday Tuesday Wednesday Thursday Friday; do
  bash logs/run_E7.sh sensors $d ../dataset/CICIDS2017/$d-WorkingHours.pcap   # Suricata (~1 h/day), flows.parquet, eve.json deleted
done
bash logs/run_E7.sh parquet                      # suricata2017_rebuilt.parquet + LABEL_AUDIT.md: read the audit before training
bash logs/run_E7.sh train config_cic2017_monday.yaml config_suricata2017_rebuilt.yaml   # 3 seeds each + bootstrap CIs (~5 h)
$PY scripts/e7_report.py --p1 config_cic2017_monday.yaml --p2 config_suricata2017_rebuilt.yaml --tag 5day
```

(Wednesday's file is named `Wednesday-workingHours.pcap` with a lower-case `w`.) Runs of several hours need two
precautions on this laptop: start them so they do not die with the terminal or Claude session (e.g. through WMI,
`Invoke-CimMethod -ClassName Win32_Process -MethodName Create`), and keep Windows awake with `logs/keep_awake.ps1`
(it stops after `-Hours` or when `logs/keep_awake.stop` exists). See section 10.

---

## 5. Project structure

```
anomaly_pipeline\
├── run.py                     entry point of the research pipeline (prepare / train / evaluate / explain / compare)
├── config*.yaml               one file per experiment (section 4)
├── environment.yml            conda environment "mlenv"
├── requirements*.txt          pip dependency lists (research / serving / dev)
├── pyproject.toml             package definition; installs the `ids-detect` command
│
├── ids_pipeline\              the actual code
│   ├── data.py                loading, cleaning and chronological splitting of CSE-CIC-IDS2018
│   ├── adapters\              the same interface for the other datasets (unsw.py, suricata2017.py)
│   ├── features.py            multi-modal feature space, service-role assignment, temporal-context features
│   ├── models.py              multi-modal SSL network and the plain autoencoder baseline
│   ├── baselines.py           Isolation Forest, PCA reconstruction, supervised Random Forest
│   ├── scoring.py             score calibration (per role) and latent-kNN scoring
│   ├── train.py               trains every method and writes validation/test scores
│   ├── evaluate.py            metrics, per-attack recall, trade-off curves, latency, plots, two-view fusion
│   ├── explain.py             SHAP, LIME and native attributions + their quality metrics
│   ├── analyst_report.py      turns alerts + attributions + signatures into readable reports
│   ├── signature_compare.py   aligns Suricata/Zeek output with the labelled flows
│   ├── schema.py              input contract for incoming flow records
│   ├── bundle.py, service.py  deployable model bundle and inference engine
│   ├── api.py, cli.py         HTTP API (FastAPI) and the `ids-detect` command
│   └── utils.py               config loading (with ${ENV:-default} paths), logging, seeding
│
├── scripts\                   one-off analyses on saved scores (no need to retrain)
│   ├── label_audit.py             finds the mislabelled HOIC flows (docs/LABEL_AUDIT.md)
│   ├── hparam_search.py           label-free hyperparameter search
│   ├── multiseed.py               retrain with other seeds, mean ± std
│   ├── clean_eval.py              E4/E6: seed-averaged metrics with bootstrap confidence intervals
│   ├── knn_reference.py           E5: size/deduplication of the kNN reference set
│   ├── window_alerts.py           E5: window-level alerting at a controlled false-alert rate
│   ├── contrastive_diagnostics.py E6: why the contrastive loss term does not help
│   ├── operating_point_analysis.py, alert_aggregation.py, compare_proposed_vs_baselines.py
│   ├── cic2017_suricata.sh, build_suricata2017.py   CIC-IDS2017 pcaps -> Suricata -> labelled flow table (+ --out for a subset of days)
│   ├── e7_report.py               E7: hypotheses H1-H7, CIC-IDS2017 tables/figures, cross-dataset comparison
│   ├── eda.py                     basic dataset statistics
│   └── loadtest.py                load test for a running scoring service
│
├── tests\                     pytest suite (87 tests)
├── docs\                      API.md, DEPLOYMENT.md, LABEL_AUDIT.md, SURICATA2017_PROVENANCE.md
├── logs\                      experiment scripts (run_*.sh) and their logs      [not in git]
├── models\prod\               exported model bundle for the scoring service    [not in git]
├── work*\                     caches, trained models, raw scores               [not in git]
├── results*\                  metrics, plots, explanations, analyst reports    [not in git]
├── results_comparison\        PREREGISTRATION.md and outcome tables of E4–E6
├── Dockerfile, docker-compose.yml, .github\workflows\ci.yml   container and CI for the scoring service
└── docker_ids.sh              runs Suricata + Zeek on a pcap (Docker)
```

How a run flows through the code:

```
CSV / parquet ──> data.py / adapters ──> features.py ──> train.py ──> scores (work\scores)
                                           (modalities,     (models.py,       │
                                            roles)          baselines.py,     ├──> evaluate.py  ──> metrics, plots
                                                            scoring.py)       └──> explain.py   ──> analyst_report.py
```

---

## 6. Methods and evaluation protocol

### Methods

| name | what it is |
|---|---|
| `ssl_mm_role` | **proposed**: one encoder per modality (volume_timing, packet_size, protocol_flags, bulk_subflow), masked-feature reconstruction + modality dropout + cross-modal InfoNCE, role embedding, per-role score calibration |
| `ssl_mm_role_knn` | the same network scored by latent-space kNN distance to benign flows of the same service role (the final proposed scoring, section 8) |
| `ssl_mm_global` | the same without any role information (objective 4 ablation) |
| `ssl_no_contrastive` | without the cross-modal contrastive term (SSL ablation) |
| `ssl_only_<modality>` | single-modality models (RQ2) |
| `ssl_mm_twoview_knn` | **two-view** model (only with `data.context_features`): `ssl_mm_flow_knn` (4 per-flow modalities) and `ssl_only_temporal_context_knn` (5th modality: traffic context) fused by min-p on tail probabilities |
| `ae_concat`, `iforest`, `pca_recon` | unsupervised baselines (`*_knn`, `*_knnrole` = the autoencoder with the same kNN scorer) |
| `rf_supervised` | supervised baseline |
| `suricata_signature` | rule-based baseline: the flow raised at least one Suricata ET Open alert (Suricata datasets only; no training) |
| `hybrid_sig_or_<method>` | Suricata alert OR the anomaly model's alert, e.g. `hybrid_sig_or_ssl_mm_role_knn` |

### Protocol

- Models train on **benign traffic only** (self-supervised, no attack labels). The latest 15% of the benign traffic
  of *each* training day is held out as validation. Its 99th percentile score is the alert threshold (1% target
  false-positive rate).
- Testing uses only later days. No attack type in the test set appears in training.
- The supervised Random Forest does see the labelled attacks of the training period. It is there to show the zero-day
  gap (RQ1).

| | config | train (benign only) | test |
|---|---|---|---|
| 2-day | `config.yaml` | Wed-14, Thu-15 | Wed-21 (DDoS), Thu-22 (web attacks), Thu-01 (infiltration), Fri-02 (bot) |
| 3-day | `config_multiday.yaml` | Wed-14, Thu-15, Wed-21 | Thu-22, Thu-01, Fri-02 |
| **CIC-IDS2017 P1** | `config_cic2017_monday.yaml` | Monday | Tuesday, Wednesday, Thursday, Friday (all 14 attack types) |
| CIC-IDS2017 P2 | `config_suricata2017_rebuilt.yaml` | Monday, Tuesday | Wednesday, Thursday, Friday |

`evaluate` writes every table twice. The first version uses the fixed threshold from the benign validation data.
The second (`*_adapted`) uses per-day recalibration: the first 30 minutes of each test day serve as an unlabeled
reference window to re-centre and re-scale the scores and to derive a new threshold. That window is then left out
of the metrics. The supervised RF is not recalibrated.

The per-role score scale is floored at 0.5× the global scale (`min_scale_ratio`). Without this floor, roles with
near-identical benign flows got a vanishing scale and the role-aware model dropped below 0.5 AUC.

---

## 7. Scoring service (production use)

The research pipeline has a deployable layer on top: model bundle export, input validation, an HTTP API, a batch
CLI, tests, CI and Docker.

```bat
ids-detect export --config config_multiday.yaml --out models\prod        :: trained run -> pickle-free, checksummed bundle
set IDS_API_KEYS=...
ids-detect serve --bundle models\prod --host 0.0.0.0                     :: POST /v1/score, GET /v1/model, /healthz /readyz /metrics
ids-detect score --input flows.csv --bundle models\prod --output scored.csv
ids-detect recalibrate --benign site_benign.csv --bundle models\prod --out models\site   :: fixes threshold drift without retraining
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (operations, drift, known limits) and [docs/API.md](docs/API.md)
(the API contract). The service has not been validated on customer data yet. Bundles exported from the `*context*`
configs cannot be served yet, because the service does not compute context features for single incoming flows.

---

## 8. Results and findings

The numbers below come from the `results*\metrics_overall*.csv` files. Read them in this order: the latent-kNN
scoring (8.1) is the current proposed method; the later sections add the temporal-context view, the label audit and
the pre-registered follow-up experiments. **The final results on the primary dataset (CIC-IDS2017 rebuilt from the
official pcaps) are in section 8.8.** Results obtained earlier on a third-party (Hugging Face) Suricata version of
CIC-IDS2017 were withdrawn and removed (section 8.7); they remain only as historical entries in
`results_comparison/PREREGISTRATION.md`.

### 8.1 Latent-space scoring: the improved SSL method (`ssl_*_knn`)

**What changed.** The original SSL score was the mean reconstruction error. That dilutes anomalies and ignores the
learned embedding (objective 6). The new score is the mean distance of a flow's fused latent embedding to its k=5
nearest benign training embeddings (`scoring.LatentKNN`, 10k reference flows). `ssl_mm_role_knn` only searches among
benign flows of the **same service role** (objective 4); `ssl_mm_global_knn` searches globally. Calibration is pooled
on benign validation data (1% target FPR), and nothing uses attack labels. `ae_concat_knn` (global) and
`ae_concat_knnrole` (role-aware) give the plain autoencoder the identical scorer, so the gains are not just the
scoring trick.

**How the design was selected.** The scoring design was chosen on CSE-CIC-IDS2018 (2-day) and UNSW-NB15. Training
hyperparameters (contrastive weight, epochs, dropout, mask ratio, size) were checked with a label-free pseudo-anomaly
test (swapped modality blocks and extreme feature values on benign validation flows). The test was flat across all
variants, so the defaults were kept. The pooled calibration was chosen after a first run on the withdrawn third-party
Suricata version of CIC-IDS2017 gave a far too conservative threshold (the role was normalised twice), so CIC-IDS2017 is
**not** a fully clean held-out set for that one choice.

A more thorough re-check (`scripts/hparam_search.py`, `results_multiday/hparam_search_*.csv`) searched a label-free
grid of 15 candidates on the 3-day config: `contrastive_weight` (0–0.4), `mask_ratio` (0.15–0.35), `epochs` (10/20),
`latent_dim` (32/64) and `modality_dropout` (0/0.15/0.25). Each candidate was scored by the ROC-AUC of real benign
validation flows against two synthetic-anomaly sets, without touching attack labels. Again all candidates were within
~0.002 AUC of each other. The mildly best one (`contrastive_weight=0.05`, `mask_ratio=0.35`) was retrained and
evaluated once on the labelled test set as a check, not as further tuning: `ssl_mm_role_knn` reached 0.824 against 0.829
for the shipped defaults, and `ssl_no_contrastive_knn` still led at 0.841. **So the 3-day gap (the contrastive
role-aware model not beating its own no-contrastive ablation) is not a tuning problem** under this architecture and
selection criterion. It is reported as a negative result. `modality_dropout=0.15` (the default) *was* confirmed best
among 0/0.15/0.25, so forcing cross-modal learning during training still makes sense. Only the contrastive loss term
does not contribute to the final score.

ROC-AUC / PR-AUC / recall at the benign-validation threshold (fixed threshold, ~1% target FPR):

| dataset | `ssl_mm_role_knn` | `ae_concat_knnrole` | `ae_concat` (old score) | `iforest` | `ssl_mm_role` (old score) | supervised RF | Suricata signatures |
|---|---|---|---|---|---|---|---|
| CIC-IDS2017 (P1, 3 seeds, 8.8) | 0.945 / 0.858 / 0.12 | 0.936 / **0.875 / 0.29** | 0.937 / 0.748 / 0.00 | **0.953** / 0.825 / 0.09 | 0.937 / 0.752 / 0.00 | n/a (no labels in training) | 0.501 / 0.316 / 0.00 |
| UNSW-NB15 | 0.928 / 0.947 / 0.67 | 0.928 / 0.944 / 0.61 | 0.910 / 0.929 / 0.64 | 0.827 / 0.850 / 0.22 | 0.892 / 0.888 / 0.10 | **0.985 / 0.989 / 0.98** | - |
| CIC-2018 3-day | 0.829 / 0.435 / 0.02 | 0.792 / 0.361 / 0.03 | 0.705 / 0.336 / 0.02 | 0.525 / 0.160 / 0.01 | 0.614 / 0.207 / 0.09 | **0.893 / 0.686** / 0.00 | - |
| CIC-2018 2-day | **0.779 / 0.460** / 0.01 | 0.745 / 0.425 / 0.01 | 0.593 / 0.320 / 0.01 | 0.434 / 0.256 / 0.00 | 0.485 / 0.276 / 0.02 | 0.568 / 0.391 / 0.00 | - |

(The best 3-day SSL variant is `ssl_no_contrastive_knn` with 0.842 / 0.479.)

**What this supports.**
1. The SSL model's ranking improved on all four settings (+0.01 to +0.29 AUC over its own old score). It beats
   `iforest`, PCA and the autoencoder's old score on UNSW-NB15 and CSE-CIC-IDS2018; on CIC-IDS2017 they are
   statistically tied with it (section 8.8).
2. The role-aware search is what makes the role idea work: on CIC-IDS2017, `ssl_mm_global_knn` reaches 0.792 AUC
   against 0.945 for the role-aware version (+0.153 [0.007, 0.329]).

**What it does not support (to be stated in the thesis).**
- On UNSW it ties the autoencoder once both use the same scorer. On the CIC-2018 3-day run the variant without the
  contrastive term is slightly better (0.842 vs 0.829), so the cross-modal contrastive objective is not shown to help.
  `ae_concat_knnrole` is close behind on most sets.
- The supervised RF has a higher AUC on UNSW and CIC-2018 3-day. There it sees the same attack types in training, so
  it is not a zero-day setting, and its fixed 0.5 threshold flags almost nothing on unseen attacks.
- CIC-2018 recall at the fixed threshold stays at 1–4%. On the 2-day protocol the FPR at the validation threshold is
  16.5%, which turned out to be mostly a label error rather than drift (section 8.5). The good ranking therefore does
  not turn into a usable operating point, and per-day recalibration (`*_adapted`) does not fix it.

**Earlier results with the reconstruction-error score** (superseded, kept for reference). Pooled ROC-AUC on the 2-day
protocol was 0.39–0.59 for all unsupervised methods (`ssl_mm_role` 0.49), and the Wed-21 HOIC flood was never detected.
On the 3-day protocol the ranking was `ae_concat` 0.70 > `ssl_mm_global` 0.61 > `ssl_mm_role` 0.58 > iforest/PCA ~0.52,
with recall at 1% FPR of 1–7%. `rf_supervised` (3-day) reached AUC 0.90 / PR-AUC 0.78, but its 0.5 threshold flagged
almost nothing on unseen attacks. Per-day recalibration brought the FPR back to ~1% but did not improve ranking.

**Negative result: late-fusion latent-kNN (`*_latefuse_knn`).** The hypothesis was that the fused embedding dilutes a
signal that is strong in one modality. The late-fusion variant (`train.py:_train_latefuse_knn`,
`models.py:embed_modalities`) uses one role-aware `LatentKNN` per modality on the same encoder, calibrates each
modality and takes the maximum. Pooled ROC-AUC of fused `ssl_mm_role_knn` vs `ssl_mm_role_latefuse_knn`: CIC-2018 2-day
0.779 vs 0.706, CIC-2018 3-day 0.829 vs 0.769, CIC-IDS2017 0.945 vs 0.862 (seed mean; UNSW not run). **It does not help**, because
the maximum over noisy modalities inflates false alarms, and it is kept only for reproducibility.

The earlier impression that single-modality models beat the full model turned out to be a threshold artefact. At
matched target FPR on the 3-day protocol (`results_multiday/fpr_recall_tradeoff.csv`), fused `ssl_mm_role_knn` and
`ssl_only_packet_size_knn` reach recall 0.009/0.016/0.024/0.097/0.479 and 0.006/0.022/0.394/0.398/0.420 at
0.1/0.5/1/2/5% FPR. The single-modality F1 of 0.52 comes from the 1% threshold landing just below a large cluster of
attack scores; at 5% FPR the fused model is higher. Other threshold strategies (pooled validation thresholds at the
99/99.5/99.9th percentile, per-role thresholds) all give recall 0.01–0.04 (MCC ≤ 0.044). Even a label-using best-MCC
threshold, which is an upper bound and not deployable, needs ~16–25% FPR to reach recall ~0.83. **Low recall at 1% FPR
is a separability limit of the flow features for Infiltration and Bot, not a threshold-selection problem.**

### 8.2 Temporal-context modality and two-view fusion (`config_context.yaml`)

**Problem.** On the 2-day protocol every method missed DDoS-HOIC (668,461 flows, 64% of all attack flows), Bot and most
Infiltration. The per-flow modalities cannot see these attacks: a single HOIC request looks like ordinary web traffic,
and floods, beacons and scans only become visible in aggregate. The CSVs have no IPs, so per-host behaviour is not
available either.

**Change 1: a fifth modality, `temporal_context`** (`features.CONTEXT_MODALITY`, `add_context_features`, switched on by
`data.context_features: true`). These are 12 features per flow, computed from the timestamp, destination port and flow
"shape" (dst port, protocol, fwd/bwd packet and byte counts):

- flows in the same second and in the trailing 60 s, overall and to the same port, and that port's share of the load
- distinct destination ports per 1 s / 10 s (scanning)
- near-identical flows per 1 s / 60 s and their share of the port's traffic (floods, bots)
- seconds since the previous identical flow and since the previous flow to this port (beaconing)

They are computed over each full cleaned day **before** the split and any sampling, with attacks included, as a
deployed sensor would see them. Labels are not used. Timestamps have 1 s resolution, so "same second" includes flows
later in that second. A brute-force check in `tests/test_features_scoring.py` confirms the counts. The default configs
are unchanged; the baselines get the same 81 features.

**Change 2: two-view fusion** (`evaluate.TWO_VIEW`, `min_p`). Putting all five modalities into one embedding does not
work: the four per-flow modalities drown the context signal, and HOIC is still ranked *below* benign traffic on its
day (within-day ROC-AUC 0.004). Instead, `ssl_mm_flow` (four per-flow modalities) and `ssl_only_temporal_context` are
trained separately, each with its own latent-kNN score. Each score becomes its empirical upper-tail probability among
its own benign reference scores. The fused score is the smallest tail probability (max of −log p), and the threshold is
the (1 − FPR) quantile of the fused reference score. A plain maximum of the two calibrated scores fails, because the
context score has a much heavier benign tail and hides the web attacks (XSS 0%).

Results, 2-day protocol, `metrics_overall_adapted.csv` (1% target FPR):

| method | ROC-AUC | PR-AUC | precision | recall | FPR | MCC | F1 |
|---|---|---|---|---|---|---|---|
| `ssl_mm_twoview_knn` | **0.937** | **0.889** | 0.976 | 0.653 | 0.74% | **0.735** | 0.783 |
| `ssl_only_temporal_context_knn` | 0.874 | 0.866 | 0.982 | 0.661 | 0.57% | 0.744 | 0.790 |
| `ssl_mm_flow_knn` (= `ssl_mm_role_knn` in `results/`) | 0.487 | 0.361 | 0.412 | 0.009 | 0.62% | 0.017 | 0.018 |
| `ssl_mm_role_knn` (5 modalities, one embedding) | 0.572 | 0.360 | 0.587 | 0.028 | 0.92% | 0.072 | 0.054 |
| `rf_supervised` | 0.878 | 0.825 | 0.290 | 0.000 | 0.00% | 0.000 | 0.000 |
| `ae_concat_knnrole` | 0.586 | 0.367 | 0.438 | 0.015 | 0.87% | 0.027 | 0.028 |

Recall per attack (adapted), flow view / context view / **two-view**: HOIC 0 / 0.995 / **0.995**; LOIC-UDP 1.0 / 0.806 /
**1.0**; XSS 0.506 / 0 / **0.468**; web brute force 0.285 / 0 / **0.273**; SQL injection 0.059 / 0 / 0.029; Infiltration
0.032 / 0.238 / 0.100; Bot 0.018 / 0.006 / 0.022. The two views complement each other: context catches floods and
scans, flow catches web attacks. A second seed points the same way (two-view 0.855 vs 0.796 for the role-only model).
`ssl_mm_flow_knn` reproduces the original `ssl_mm_role_knn` exactly (ROC-AUC 0.7746, fixed threshold), so old and new
results are directly comparable.

**Limits.**
- It depends on per-day recalibration. With the fixed validation threshold, the DDoS day's benign traffic is still
  flagged almost entirely (pooled FPR ~16%). This is mostly the label error described in 8.5.
- The operating point is sensitive: at 0.1% / 0.5% target FPR two-view recall collapses to 0.4% / 0.6%, while from 1% to
  5% it is stable at 0.65–0.72 (`fpr_recall_tradeoff_adapted.csv`).
- Bot (2%) and Infiltration (10%) remain mostly missed. Bot beaconing is probably slower than the 1 s / 60 s windows.
- It is not a clean held-out result: the context features were designed after seeing which attacks were missed, and
  min-p was chosen over max, mean, smooth max and Fisher fusion on the labelled test days (`logs/fusion_offline*.py`).
  Section 8.5 re-evaluates it properly.
- The context view is still derived from CICFlowMeter records, not a separate telemetry source.

Reproduce with `bash logs/run_context.sh`, or by hand: `python run.py prepare --config config_context.yaml`, then
`python run.py train --config config_context.yaml --only ssl_mm_flow ssl_only_temporal_context ssl_mm_role ssl_mm_global
ssl_no_contrastive ae_concat iforest pca_recon rf_supervised`, then `python run.py evaluate --config config_context.yaml`.

### 8.3 Comparison with signature IDSs (Suricata + Zeek on a real pcap)

`docker_ids.sh` runs Suricata (Emerging Threats Open rules) and Zeek offline on the Thu-22 victim capture
(172.31.69.28). `python run.py compare --capture-dir ..\external\pcap\thu22 --day Thursday-22-02-2018 --attacker
18.218.115.60` aligns the labelled attack flows with the attacker's connections and writes
`signature_comparison_*.csv` and `signature_background_alerts_*.txt`. For Suricata only "ET ..." signatures count
(engine and decode events are ignored); for Zeek, any non-CaptureLoss notice on the attacker counts. All 362 attack
flows matched to 131 attacker connections.

Share of attack flows detected with the 3-day latent-kNN models (`results_multiday/signature_comparison_*.csv`):

| attack | Suricata ET | Zeek | `ssl_mm_role_knn` | `ae_concat_knnrole` | Suricata OR `ssl_mm_role_knn` |
|---|---|---|---|---|---|
| Brute Force -Web (249) | 0.016 | 0 | **0.418** | **0.426** | 0.426 |
| Brute Force -XSS (79) | **0.899** | 0 | 0.760 | 0.468 | **0.937** |
| SQL Injection (34) | 0.265 | 0 | 0.147 | 0.353 | 0.353 |

Signatures catch attacks that have a rule (XSS). The SSL model catches behaviour without a rule (web brute force).
The combination is the best of the three on XSS. With the older reconstruction-error score the SSL models added nothing
on top of Suricata. Zeek raised no notice on the attacker; its only notice was an SSH password-guessing alert about an
unrelated host. Suricata also raised 78 ET alerts on non-attacker sources (8.8 per hour), mostly SIP and port scans from
the internet. This is a single capture with three attack types: an illustration, not a general claim.

### 8.4 Explanations and analyst reports

**Analyst reports** (`ids_pipeline/analyst_report.py`). `python run.py explain --config <cfg> [--method <model>]` also
writes `analyst_report[_<model>].md` and `analyst_report_summary[_<model>].csv`. Each alert states, in this order:

1. **Verdict and priority.** *CONFIRMED* means a Suricata ET signature and the anomaly model both flag the flow (HIGH
   if the signature severity is ≤ 2). *ANOMALY ONLY* means there is no signature: possibly new activity, possibly a
   false alarm. Signatures are translated into what they mean.
2. **Why it looks abnormal.** The top SHAP features in words and units, compared with the median / 95th percentile of
   benign training flows of the same service role (e.g. "bytes sent by the server: 190 KB vs 242 B normal"). A feature
   is marked *stable* only if it is in the top-k of two independent SHAP runs. Behaviour hypotheses ("consistent with a
   flood / scan / upload / slow attack / web probing") are built only from stable evidence and rank below a signature.
3. **Network context.** IPs and ports, HTTP URIs, DNS names and the TLS server name (from the Suricata record or Zeek
   http.log).
4. **Next steps** and a confidence level. The ground-truth label is printed last, for evaluation only.

For the CIC-IDS2017 configs the signature context comes from the Suricata fields stored per flow. For the CIC-2018
configs it comes from the Suricata eve.json and Zeek logs of the Thu-22 pcap (the `report:` block), matched by start
time and destination port because the CSV has no IPs. Examples: `results_multiday/analyst_report_ae_concat.md`, where 5
of 29 alerts are confirmed by `ET WEB_SERVER Script tag in URI ...` and show the actual `<script>` request, and
`results_cic2017_monday/analyst_report.md` for CIC-IDS2017. On CSE-CIC-IDS2018 and UNSW-NB15 most flows have no signature source, so most alerts are ANOMALY ONLY.

**Fixing LIME** (`explain.py`). LIME originally did worse than random feature removal and barely agreed with SHAP. Two
causes were found and fixed:

1. LIME was fit on one dataset-wide background sample, while SHAP already used a per-role background. LIME's local
   surrogate was therefore fit against the wrong idea of "normal" for many roles. **Fix:** one `LimeTabularExplainer`
   per role, using that role's benign training flows (falling back to the pooled sample for small roles).
2. `num_features=d` forced LIME to fit a coefficient for every one of the ~70–90 features from ~1,000 samples, which
   is underdetermined and noisy. **Fix:** `num_features=30`; only the top 5–10 are used downstream anyway.

SHAP's budget was also raised (background 20→40, `nsamples` 500→1200, costing ~0.05–0.17 s per alert) to reduce its
variance across seeds. Raising `lime_samples` from 1000 to 4000 made LIME *more stable* (0.574→0.741 on 3-day) but *less
faithful* (deletion drop −0.060→−0.106): more samples converge more confidently on a linear surrogate that is
systematically misaligned with the non-linear latent-distance score. `lime_samples` stays at 1000.

Before → after (`explanation_quality*.csv`, same trained models, only the attribution methods changed):

| dataset | SHAP deletion drop | SHAP stability | LIME deletion drop | LIME stability | SHAP–LIME agreement |
|---|---|---|---|---|---|
| CIC-2018 2-day | 0.169 → 0.227 | 0.362 → 0.517 | **−0.032 → +0.252** | 0.484 → 0.778 | 0.096 → 0.276 |
| CIC-2018 3-day | 0.161 → 0.293 | 0.376 → 0.499 | −0.075 → −0.060 | 0.483 → 0.574 | 0.062 → 0.179 |
| UNSW-NB15 | 0.391 → 0.403 | 0.401 → 0.576 | +0.037 → **−0.096** | 0.365 → 0.516 | 0.192 → 0.197 |

SHAP improved on all three datasets. LIME improved on both CIC-2018 settings (sharply on 2-day) but **regressed on UNSW-NB15**, and
this should be reported, not averaged away. For RQ3 this means SHAP and native attribution are the methods to trust
for analyst-facing explanations. LIME is informative on CSE-CIC-IDS2018 but should remain a secondary
cross-check until the UNSW regression is understood (a likely cause is the different scale and sparsity of UNSW's
features per modality). On the 3-day set, only Bot, Infiltration and SQL-injection alerts fired, so DDoS and
brute-force alerts are not explained.

### 8.5 Label audit and pre-registered experiments E4–E6 (2026-09-25/26)

These experiments were pre-registered in `results_comparison/PREREGISTRATION.md`, which also has the full outcome
tables. They use 3 seeds and 95% block-bootstrap confidence intervals of paired differences (`scripts/clean_eval.py`).
The held-out setting reported here is CIC 3-day clean; CIC 2-day clean is the development set. Their second held-out
setting, the withdrawn third-party Suricata2017 data, appears only in `PREREGISTRATION.md`.

**A label error in CSE-CIC-IDS2018** (`docs/LABEL_AUDIT.md`, `scripts/label_audit.py`). On Wed-21, 358,623 flows labelled
Benign are in fact the HOIC connections recorded in the reverse direction. All of them fall inside the 22-minute HOIC
window, share one flow shape and use ephemeral destination ports, and no other attack window shows this pattern. They
made up 99% of Wed-21's "benign" test flows (2-day protocol) and part of the benign training data (3-day protocol).
`config_context_clean.yaml` and `config_multiday_context_clean.yaml` exclude them (`data.label_exclusions`); the older
configs and results are unchanged. With clean labels, the 2-day fixed-threshold FPR of the kNN methods drops from ~16% to
1.5–2%, and `rf_supervised` on the 3-day protocol drops from 0.842 to 0.714 ROC-AUC. In addition, 17.6% of Infiltration
flows are feature-for-feature identical to benign flows, which caps Infiltration recall for any flow-level detector.

**E4: clean re-evaluation of two-view fusion.** A fair new baseline, `ae_twoview_knnrole`, runs the plain autoencoder on
the same two views with the same min-p fusion. ROC-AUC, seed mean:

| setting | two-view SSL | two-view AE | flow view | context view | best single embedding |
|---|---|---|---|---|---|
| 3-day clean (held-out), adapted | 0.820 | 0.799 | **0.835** | 0.677 | 0.805 |
| 3-day clean (held-out), fixed | **0.858** | 0.836 | 0.841 | 0.714 | 0.826 |
| 2-day clean (dev), adapted | **0.928** | 0.922 | 0.524 | 0.878 | 0.720 |

- **Not supported: "multiple views beat every single view".** On the 3-day adapted protocol the flow view ranks higher
  (−0.015 [−0.031, −0.001]) and the context view has higher recall at 1% FPR. The earlier 2-day result (8.2) was on
  the design set with mislabelled flows.
- **Supported: the SSL encoder helps inside the two-view design.** Two-view SSL beats two-view AE on the 3-day protocol
  in both modes (+0.021 [0.016, 0.026] adapted).
- Two-view SSL's adapted operating point is fragile on the 2-day protocol (MCC 0.49 ± 0.40 over seeds), because the
  Wed-21 threshold rests on only 155 flows.

**E5: recall at a controlled false-alert rate.**
- A larger or deduplicated kNN reference set (`scripts/knn_reference.py`) was rejected on the dev set.
- Flow-level recall at 1% FPR is limited by separability: oracle recall is 2–6% for Bot and 5–26% for Infiltration for
  every view.
- The binomial window test (`scripts/window_alerts.py`) flags a (role, 5-minute) window when it has more flagged flows
  than benign traffic explains. For two-view SSL on the 3-day protocol it cuts false alerts from 48/h to 0.26/h but
  keeps only 16% of the attack-window recall, so the pre-registered criterion (FPR ≤ 1.5% and ≥ 50% recall kept) is
  **not met**.
- For RQ4: at a usable alert rate these detectors surface sustained or volumetric attacks. Low-volume web attacks, SQL
  injection and Bot are lost and are better left to signatures (section 8.3).

**E6: why the contrastive term does not help** (`scripts/contrastive_diagnostics.py`).
- In a 256-flow InfoNCE batch, 82–97% of flows share their exact TCP / HTTP / session block with another flow, mostly
  all-zero blocks of absent protocols. These in-batch false negatives cannot be told apart from the positive, so the
  shipped term stays at chance (InfoNCE 5.20 ± 0.002 vs 5.55) and leaves the embedding unchanged. That is why it ties
  the ablation.
- The fix `ssl_mm_role_fnmask` (false negatives masked) makes the term train (masked InfoNCE 1.25 vs 2.35), but
  detection does not improve. By the pre-registered seed rule there is no measurable effect; the bootstrap CIs put it
  slightly below `ssl_no_contrastive` on CIC (−0.012 to −0.024 ROC-AUC).
- Conclusion: the latent-kNN score does not benefit from cross-modal alignment, even when the alignment is learned.

### 8.6 UNSW-NB15 (`config_unsw.yaml`)

UNSW-NB15 uses its official train/test partition, and the models are fit on the benign flows of the training partition
only. UNSW has no timestamps and its files are sorted by class, so the adapter uses a seeded random order (the benign
validation slice is a random 15%). Pooled test set: 82,332 flows, 55% attacks. See 8.1 for the latent-kNN numbers.
With the original score, ROC-AUC / recall at ~1–2% FPR was: `ae_concat` 0.91 / 0.64, `ssl_no_contrastive` 0.90 / 0.62,
`ssl_mm_global` 0.90 / 0.14, `ssl_mm_role` 0.89 / 0.10, iforest 0.83, pca_recon 0.84; the best single modality was
`ssl_only_context` 0.85 (recall 0.50). `rf_supervised` reaches 0.985 AUC with recall 0.98 at 19% FPR, but UNSW's train
and test sets contain the same attack types, so this is **not** a zero-day setting.

### 8.7 CIC-IDS2017 rebuilt from the official pcaps (`docs/SURICATA2017_PROVENANCE.md`)

An earlier third-party Suricata version of CIC-IDS2017 (Hugging Face) had undocumented provenance and labels that
disagreed with CIC's documentation. It was withdrawn and deleted on 2026-10-03 and replaced by this rebuild; its results
remain only as historical entries in `results_comparison/PREREGISTRATION.md`.

`scripts/cic2017_suricata.sh` runs a pinned Suricata 8.0.7 with frozen ET Open
rules (and optionally Zeek 9.0.0) on each official day pcap. `scripts/build_suricata2017.py` then produces one row per
Suricata flow with the same schema, labelled only from CIC's attack schedule (`docs/cic2017_attack_schedule.csv`) by
attacker IP, victim IP and time window. Every build writes `LABEL_AUDIT.md` and `manifest.json`.

**Status (2026-10-03): rebuilt and used.** All five official pcaps were processed (Suricata 8.0.7, image pinned by
digest, one ET Open rule file for all days, `HOME_NET` = 192.168.10.0/24). Zeek was skipped for disk space; it was optional.

| day | Suricata flows | benign | attack flows (labelled from the schedule only) | excluded |
|---|---|---|---|---|
| Monday | 343,005 | 343,005 | none (benign-only day) | 0 |
| Tuesday | 294,902 | 287,910 | FTP-Patator 4,010; SSH-Patator 2,551 | 431 |
| Wednesday | 471,217 | 292,083 | DoS Hulk 161,096; GoldenEye 7,530; Slowhttptest 4,222; Slowloris 3,895; Heartbleed 1 | 2,390 |
| Thursday | 334,452 | 265,761 | Infiltration-Portscan 66,514; Web Brute Force 1,362; XSS 679; Infiltration 14; SQL Injection 12 | 110 |
| Friday | 524,643 | 264,355 | Portscan 161,264; DDoS 96,813; Botnet 743 | 1,468 |

What `LABEL_AUDIT.md` showed (full notes in `results_comparison/PREREGISTRATION.md`, E7):
- **No lost state on any day** (flow/stream memcap and alert-queue counters 0; every packet decoded), and the same rules sha256 on all days.
- **Every attack window is dominated by the scheduled attacker** with the expected ports (FTP 21, SSH 22, web/DoS/DDoS 80,
  Heartbleed 444, Botnet 8080).
- **Excluded, not relabelled** (`outside_window = drop`): SSH-Patator continues ~20 min past its published end (428
  flows); the Heartbleed victim's ordinary HTTPS to the firewall address all day (2,248 flows); the five bots keep
  beaconing to the C&C (205.174.165.73:8080) from 11:02 to 17:00 after the published Botnet window (1,456 flows).
  Excluded flows are neither benign nor attack, so no method gains from them.
- Infiltration-Portscan includes ~3,000 DNS flows of the infected host (time-window label). Heartbleed (1 flow) and
  Infiltration (14) are too small to interpret per class.
- **Suricata ET alerts on 0.71% of benign flows** (2.10% on Monday). This is the honest false-positive rate of the
  signature baseline.
- Suricata flows are bidirectional connections, so there are fewer of them than CICFlowMeter rows (e.g. Monday 343k vs ~530k).

The rebuilt data is evaluated in section 8.8.

### 8.8 CIC-IDS2017 as the primary dataset: pre-registered experiment E7 (2026-10-02/03)

E7 was pre-registered in `results_comparison/PREREGISTRATION.md` (hypotheses H1–H7) before any Tuesday–Friday pcap was
processed. It uses the shipped hyper-parameters (no tuning on this dataset), seeds 42, 1 and 2, and 95% block-bootstrap
confidence intervals of paired differences (`scripts/clean_eval.py`). Tables and figures: `results_comparison/E7_5day_tables.md`,
`table_E7_5day_*.csv` and `figE7_5day_{scorecard,recall_per_attack,cross_dataset_auc}.png`, made by `scripts/e7_report.py`.

| protocol | config | train (benign only) | test |
|---|---|---|---|
| **P1 (primary)** | `config_cic2017_monday.yaml` | Monday (291,539 flows; last 15% = threshold) | Tue–Fri: 1,620,815 flows, 510,706 attacks, all 14 types unseen |
| P2 | `config_suricata2017_rebuilt.yaml` | Monday + Tuesday (RF also sees Tuesday's labelled Patator flows) | Wed–Fri: 1,326,344 flows, 504,145 attacks |

The supervised RF has no place in P1, because Monday contains no attack labels to learn from; P2 exists to measure it.

**P1 results, fixed threshold (1% target FPR on Monday's validation slice), mean of 3 seeds:**

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

P2 (Wed–Fri, fixed): proposed 0.951 ROC-AUC / recall 0.070; `ae_concat_knnrole` 0.961 / 0.262; `iforest` 0.957 / 0.050;
Suricata 0.499 / 0.001; **`rf_supervised` 0.612 / 0.004** (FPR 0%).

**Pre-registered hypotheses:**

| H | claim | outcome | evidence (P1; paired ROC-AUC difference, 95% CI) |
|---|---|---|---|
| H1 (RQ1) | SSL detects unseen attacks: AUC ≥ 0.90 and beats AE / iForest / PCA | **not supported** | AUC 0.945, but vs AE +0.008 [−0.019, 0.034], vs iForest −0.009 [−0.043, 0.017], vs PCA +0.021 [−0.004, 0.043] |
| H2 (RQ1/RQ4) | beats the rule-based IDS at a controlled false-alert rate | supported | recall 0.115 vs 0.004 at FPR 0.50% |
| H3 | signatures + anomaly model together | supported | incident recall 0.91 vs 0.70 / 0.73 |
| H4 (RQ2) | multiple telemetry sources beat every single source | supported | flow +0.013 [0.005, 0.020], tcp +0.19, http +0.14, session +0.49, dns +0.74 (all CIs > 0) |
| H5 (obj. 4) | role-aware beats global | supported | +0.153 [0.007, 0.329] |
| H6 (RQ1) | supervised learning fails on unseen attacks | supported | P2: RF recall 0.004 vs 0.070 |
| H7 | the gain is not only the kNN scorer | **not supported** | vs `ae_concat_knnrole` +0.009 [−0.025, 0.044] |

**Recall per attack (P1, fixed, seed mean).** Suricata catches what has a rule: FTP-Patator 0.49, SQL injection 0.67,
Infiltration 0.21, Heartbleed (1 flow). It catches nothing of Botnet, DoS, DDoS, Portscan or Web Brute Force. The
proposed model adds Botnet 0.27, Portscan 0.28, FTP-Patator 0.33, Slowloris 0.19 and Infiltration-Portscan 0.14, but
hardly any DoS Hulk (0.005) or DDoS (0.005). `ae_concat_knnrole` catches DDoS 0.98 and Slowloris 0.57; `iforest` is the
only method with some DoS Hulk (0.25) and GoldenEye (0.38). Web XSS, SQL injection and SSH-Patator stay close to 0 for
every anomaly model.

**What this supports.**
1. Trained only on benign traffic, the proposed model ranks unseen attacks well (ROC-AUC 0.945 P1, 0.951 P2) and far
   better than the signature IDS, whose ranking is at chance (0.50) because it alerts on so few attack flows.
2. The supervised RF collapses on attack types it has not seen (0.61 AUC, recall 0.004), which is the zero-day gap the
   proposal argues from.
3. The multi-modal and role-aware design choices both hold up with confidence intervals on real Suricata telemetry.
4. Signatures and the anomaly model are complementary: together they find 91% of attack incidents.

**What it does not support (to be stated in the thesis).**
- The SSL encoder is not shown to be better than simpler unsupervised models: Isolation Forest, PCA and especially the
  autoencoder with the same role-aware kNN scorer are statistically tied with it in ROC-AUC, and the AE+kNN has higher
  recall and MCC. The contrastive term again has no effect (vs `ssl_no_contrastive_knn` +0.001 [−0.001, 0.003]).
- **The operating point is unstable across seeds.** Proposed recall at the fixed threshold is 0.005 / 0.007 / 0.334
  (seeds 42 / 1 / 2) at a stable ROC-AUC (0.938–0.950): the Monday-calibrated threshold lands just above or just below
  the large DoS Hulk/DDoS score cluster. `iforest` and `ssl_no_contrastive_knn` show the same pattern. Per-day
  recalibration raises the proposed recall to 0.38 (FPR 1.9%) but does not remove this sensitivity.
- Post hoc, not a claim: the single-modality reconstruction score `ssl_only_tcp` had the best seed-42 result (ROC-AUC
  0.974, recall 0.86, MCC 0.86). It was not pre-registered and needs its own pre-registered test before it is used.

**Interim run E7a.** Before Thursday and Friday were available, P1 was started on Monday–Wednesday only
(`config_cic2017_3day*.yaml`, `results_cic2017_3day\`, seed 42 only). It is reported as a single-seed interim result:
proposed ROC-AUC 0.919, recall ≈ 0; `iforest` 0.979; Suricata recall 0.011. It is superseded by E7.

### 8.9 Exploratory: late fusion of modality experts (`ssl_mm_experts`, post hoc, 2026-10-03)

**Not pre-registered: proposed after the E7 test labels were seen** (`results_comparison/PREREGISTRATION.md`, X1). `ssl_mm_experts`
fuses the single-modality SSL experts (`ssl_only_<modality>`, one per telemetry source) by min-p, like the two-view detector: each
expert is ranked against its own benign validation scores and the most extreme one decides. `train` builds it from the experts'
score files (`train.fuse_experts`; `scoring.expert_fusion: false` turns it off); `explain --method ssl_mm_experts` explains its alerts.

On CIC-IDS2017 P1 (3 seeds) it ties the best baselines in ROC-AUC (0.951 vs iForest 0.953) and has the highest recall and MCC at the
1% operating point (fixed threshold: recall 0.43, MCC 0.54 vs 0.12 / 0.18 for the E7 model and 0.30 / 0.44 for AE+kNN; at an equal
1% FPR: recall 0.37 vs 0.22 / 0.21). Its fixed-threshold recall is still seed-dependent (std 0.17), and on CSE-CIC-IDS2018 (0.56)
and UNSW-NB15 (0.87) it is worse than the E7 model. It is a hypothesis about real multi-source telemetry, pre-registered as E8 for
Terma data, not a thesis claim. A first z-score variant that looked far stronger was a numerical artifact and was discarded (X1).
Recompute: `python scripts/explore_fusion.py` (output in `results_explore\`). Model bundles (`ids-detect export`) do not support it yet.

---

## 9. Deviations from the proposal and known limits

- **Where the multi-modal telemetry claim is actually shown.** CSE-CIC-IDS2018 and UNSW-NB15 have no DNS/TLS/HTTP logs,
  only CICFlowMeter flow features. Their "modalities" are four views of one flow record (`features.MODALITIES`). Real
  multi-source telemetry (flow, TCP, DNS, HTTP and session events from Suricata's `eve.json`) exists only for
  **CIC-IDS2017 rebuilt from the official pcaps** (`adapters/suricata2017.py`, section 8.8). The multi-modal claim (RQ2)
  is therefore demonstrated on that dataset, while CSE-CIC-IDS2018 and UNSW-NB15 serve as comparison datasets for scale
  and the zero-day protocol. The adapter interface is the extension point for real Zeek/Suricata sources on Terma data.
- **CIC-IDS2017 labels are time-window labels** from CIC's published schedule: all traffic between the scheduled
  attacker and victim inside the window counts as attack, including failed attempts and replies (the same unit CIC
  used). Traffic the schedule cannot explain is excluded, not guessed (section 8.7). ET Open rules from 2026 know these
  2017 attacks in hindsight, so the signature baseline is an optimistic upper bound for a signature IDS of that time.
- **The proposed SSL model ties simpler unsupervised models on CIC-IDS2017** (H1 and H7 not supported, section 8.8),
  and its fixed-threshold recall depends strongly on the seed.
- **Role = service role derived from the destination port** (web, remote_admin, ...), because the datasets have no IPs.
  On Terma data this would be the asset role or network zone.
- The CSE-CIC-IDS2018 CSVs are truncated at 1,048,576 rows (the Excel limit) and contain duplicates; ~20% of the
  Wed-14 rows are duplicates and are dropped.
- `explain` uses `shap.KernelExplainer`. If `shap` cannot be imported, `explain.py` falls back to a built-in
  permutation-Shapley estimator.
- **Explanation usefulness (RQ3) is only measured automatically so far** (deletion fidelity, cross-seed stability,
  cross-method agreement), not rated by a human analyst. A review of the `analyst_report*.md` alerts with the Terma
  supervisor is planned before submission.
- **No validation on Terma's own traffic.** All results are on public benchmarks. The serving layer is
  production-shaped (bundle export, auth, drift monitoring, recalibration, Docker) but untested against live
  telemetry, a SIEM or an asset-role inventory. See "Known limits" in `docs/DEPLOYMENT.md`.

---

## 10. Troubleshooting

| symptom | cause and fix |
|---|---|
| `DLL load failed` when importing `pyarrow` | The pip version of pyarrow is installed. Replace it with the conda version: `python -m pip uninstall -y pyarrow`, then `conda install -y pyarrow`. |
| `Could not find/load shared object file 'llvmlite.dll'`, or `shap` fails to import | The pip version of numba is installed. Replace it with the conda version: `python -m pip uninstall -y numba llvmlite`, then `conda install -y numba`. |
| `Unable to find a usable engine; tried using: 'pyarrow'` | pyarrow is missing or not loading; see the first row. |
| `OMP: Error #15: Initializing libiomp5md.dll, but found libiomp5md.dll already initialized`, or `Fatal Python error: Aborted` | Two OpenMP libraries are loaded (torch's and conda's). Do the one-time step in section 2 (rename `torch\lib\libiomp5md.dll`). |
| `import torchvision` fails with `operator torchvision::nms does not exist` | A conda torchvision/torchaudio is left over from an older PyTorch. Remove them: `conda remove -y torchvision torchaudio cpuonly pytorch-mutex`. |
| `ModuleNotFoundError` right after installing a package | It went into the base environment. Use `python -m pip install ...` with `mlenv` active. |
| UNSW run fails with file not found | The two CSVs must be in `dataset\UNSW_NB15\` (or the folder in `IDS_UNSW_DIR`), named `UNSW_NB15_training-set.csv` / `UNSW_NB15_testing-set.csv` (underscores also work). |
| `error: ...` from `run.py` about a config or column | `ConfigError` / `DataError`: the message names the file or column. Check the paths in section 3. |
| Old results were overwritten | Set `IDS_RESULTS_DIR` / `IDS_WORK_DIR` before experimenting (section 4). |
| `failed to connect to the docker API ... dockerDesktopLinuxEngine` | Docker Desktop is not running. Start it and wait until `docker info` answers before `run_E7.sh sensors`. |
| Suricata on one day takes many hours instead of ~1 h | Windows went to sleep (this laptop sleeps after 5 min idle, also on mains power), and Suricata pauses with it. Run `logs/keep_awake.ps1` during long jobs. |
| A long run stops when the terminal, VS Code or the Claude session closes | Child processes of the session are stopped with it. Start long jobs through WMI (`Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=...}`). A Windows scheduled task does not work with Git Bash (exit `0xC000013A`). |
| `python` in Git Bash is Python 3.13 / packages missing | Git Bash finds the base Anaconda python. Use the `mlenv` interpreter explicitly (`export PY=.../envs/mlenv/python.exe`, as `run_E7.sh` expects). |
| `explain --method ssl_mm_role_knn` fails with `FileNotFoundError ... ssl_mm_role_knn.pkl` | `explain` works on the trained network, not on a scoring variant. Use the base name (`--method ssl_mm_role`, the default). |
