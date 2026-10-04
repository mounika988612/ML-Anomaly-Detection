# Explainable self-supervised anomaly detection for network traffic

This repository holds the code for my master thesis at DTU Compute, written in collaboration with Terma A/S. The
question behind it is whether a model can learn what normal network traffic looks like from unlabelled telemetry,
raise an alert when something doesn't fit, and then explain that alert in a way a SOC analyst can actually use.

I work with three public datasets: CIC-IDS2017, CSE-CIC-IDS2018 and UNSW-NB15. For CIC-IDS2017 I skipped the usual
CSV release and ran Suricata myself on the five official pcap files. That way the models get the kind of data a real
SOC has: flow records together with TCP, DNS, HTTP and TLS/SSH/FTP session events.

The models are trained on benign traffic only, so every attack in the test data is new to them. That is the zero-day
setting the thesis is about. I compare against three kinds of baseline: a rule-based IDS (Suricata with the Emerging
Threats Open rules, plus Zeek in one capture study), unsupervised ML (Isolation Forest, PCA reconstruction and a plain
autoencoder), and supervised ML (a Random Forest trained on labelled attacks).

Besides the research code there is a small production layer: a model bundle you can export, an HTTP scoring API and
a command-line tool.

Contents:

- [Quick start](#quick-start)
- [Setting up the environment](#setting-up-the-environment)
- [Datasets](#datasets)
- [Running the pipeline](#running-the-pipeline)
- [Project structure](#project-structure)
- [Method and evaluation protocol](#method-and-evaluation-protocol)
- [Results on CIC-IDS2017](#results-on-cic-ids2017)
- [Results on CSE-CIC-IDS2018 and UNSW-NB15](#results-on-cse-cic-ids2018-and-unsw-nb15)
- [Explanations and analyst reports](#explanations-and-analyst-reports)
- [Scoring service](#scoring-service)
- [Deviations from the proposal and known limitations](#deviations-from-the-proposal-and-known-limitations)
- [Troubleshooting](#troubleshooting)

---

## Quick start

From the Anaconda Prompt:

```bat
cd /d "D:\Thesis source code\anomaly_pipeline"
conda env create -f environment.yml      :: first time only, followed by the OpenMP fix described below
conda activate mlenv
pytest                                   :: 87 tests, roughly 2 minutes
python run.py all                        :: CIC-IDS2017: prepare -> train -> evaluate -> explain
```

If you don't pass `--config`, `run.py` uses `config_cic2017_monday.yaml`, which trains on Monday and tests on Tuesday
to Friday. It reads the Suricata flow table at `..\external\cic2017\suricata2017_rebuilt.parquet`, so if you haven't
built that yet, do that first (see "Building CIC-IDS2017 from the pcaps" further down). The output goes to
`results_cic2017_monday\`.

---

## Setting up the environment

Everything runs natively on Windows in a conda environment called `mlenv` with Python 3.11.

The easiest way is to create it from `environment.yml`:

```bat
cd /d "D:\Thesis source code\anomaly_pipeline"
conda env create -f environment.yml
conda activate mlenv
```

This also installs the pipeline as an editable package (`pip install -e .`), so edits under `ids_pipeline\` are picked
up immediately and the `ids-detect` command becomes available.

If you already have an `mlenv` and want to install into it by hand:

```bat
conda activate mlenv
conda install -y numpy pandas pyarrow numba scikit-learn matplotlib pyyaml
python -m pip install torch==2.13.0 --index-url https://download.pytorch.org/whl/cpu
python -m pip install lime shap
python -m pip install -e ".[research,dev]"
```

### The OpenMP fix (once, after installing torch)

The conda builds of numpy and scikit-learn use Intel's OpenMP library (`libiomp5md.dll`), and the pip torch wheel
ships its own copy. When both get loaded, Python aborts with `OMP: Error #15 ... libiomp5md.dll already initialized`.
I solved it by renaming torch's copy so it falls back to the conda one:

```bat
conda activate mlenv
ren "%CONDA_PREFIX%\Lib\site-packages\torch\lib\libiomp5md.dll" libiomp5md.dll.bak
```

You have to repeat this every time torch is reinstalled. I'd advise against setting `KMP_DUPLICATE_LIB_OK=TRUE`
instead. Intel documents it as unsafe, and it can give wrong results without any warning.

A few other things that cost me time on this machine. Plain `pip` sometimes points to the base environment even with
`mlenv` active, so always use `python -m pip`. `pyarrow` and `numba` only worked when installed from conda, while torch
comes from pip (the CPU index). And there should only be one PyTorch: don't install conda's `pytorch`, `torchvision` or
`torchaudio` on top of the pip version.

To check that everything works:

```bat
python -c "import torch, sklearn, pyarrow, numba, shap, lime, ids_pipeline; print('OK', torch.__version__)"
pytest
```

All 87 tests should pass. The versions I use (last checked 2026-09-30) are Python 3.11, torch 2.13 CPU,
scikit-learn 1.9, numpy 2.4, pandas 3.0, pyarrow 23 (conda), numba 0.65 (conda), shap 0.51 and lime 0.2.

In VS Code, select `mlenv` as the interpreter (`Ctrl+Shift+P`, then *Python: Select Interpreter*) so the editor,
terminal and test runner all use the same environment. The dependencies are also listed as plain pip files, which is
what CI and the Docker image use: `requirements.txt` for research, `requirements-serve.txt` for the scoring service
alone, and `requirements-dev.txt` for everything plus pytest and ruff.

---

## Datasets

The data lives next to this folder rather than inside it, and it isn't tracked by git:

```
D:\Thesis source code\
├── anomaly_pipeline\          <- this repository
├── dataset\
│   ├── CICIDS2017\            <- the five official CIC-IDS2017 pcaps (~52 GB)
│   │   ├── Monday-WorkingHours.pcap        benign only, used for training
│   │   └── Tuesday- Wednesday- Thursday- Friday-WorkingHours.pcap   attack days
│   ├── CICIDS2018\            <- CSE-CIC-IDS2018 CSVs, one per day
│   └── UNSW_NB15\             <- UNSW_NB15_training-set.csv (175,341) and UNSW_NB15_testing-set.csv (82,332)
└── external\
    ├── cic2017\               <- my Suricata build of CIC-IDS2017
    │   ├── rules\                       the frozen ET Open rule file (sha256 + fetch date), same for every day
    │   ├── <Day>\flows.parquet          one labelled row per Suricata flow, plus day_manifest.json and Suricata logs
    │   ├── suricata2017_rebuilt.parquet all five days together (1,963,820 flows, 14 attack types)
    │   └── LABEL_AUDIT.md, manifest.json
    └── pcap\                  <- CSE-CIC-IDS2018 victim captures for the Suricata/Zeek comparison (thu22 is the one used)
```

CIC-IDS2017 is available from https://www.unb.ca/cic/datasets/ids-2017.html after filling in a registration form.
Only the files with their final `*-WorkingHours.pcap` name matter; anything called `Unconfirmed *.crdownload` is an
unfinished browser download and can go. Note that Wednesday's file is spelled `Wednesday-workingHours.pcap`, with a
lower-case `w`.

For CSE-CIC-IDS2018 I use the CICFlowMeter CSVs for Wed-14, Thu-15, Wed-21, Thu-22, Thu-01 and Fri-02.

For UNSW-NB15 the official file names work, and so does the underscore spelling some mirrors use. Be careful with the
Hugging Face mirror `Mireu-Lab/UNSW-NB15`, though: it has the two files swapped (`test.csv` is really the training set
and vice versa), so compare the row counts with the ones above.

Paths in the config files are relative to the config file itself. They can be overridden with the environment
variables `IDS_DATA_DIR`, `IDS_UNSW_DIR`, `IDS_SURICATA_PARQUET`, `IDS_CAPTURE_DIR`, `IDS_WORK_DIR` and
`IDS_RESULTS_DIR`.

---

## Running the pipeline

### Stages

Each experiment goes through the same four stages. `run.py` can run them one at a time or all together:

```bat
python run.py prepare      :: load the data, chronological train/validation/test split, build the feature space
python run.py train        :: train all models and baselines, write anomaly scores
python run.py evaluate     :: metrics, per-attack recall, FPR/recall trade-off, time-to-detect, plots
python run.py explain      :: SHAP / LIME / native attributions + a plain-language analyst report
python run.py all          :: all four in order
```

`prepare` caches its output in the experiment's `work_*` folder, so it is much quicker the second time. `train` is the
slow part: around a minute per neural model, plus a few minutes of latent-kNN scoring for each.

### Experiments

Every config file describes one complete experiment and has its own `work_*` and `results_*` folder.

| config | dataset / protocol | output folder |
|---|---|---|
| `config_cic2017_monday.yaml` (default) | CIC-IDS2017, protocol P1: train Monday, test Tue–Fri. This is the main result. | `results_cic2017_monday\` |
| `config_suricata2017_rebuilt.yaml` | CIC-IDS2017, protocol P2: train Mon+Tue, test Wed–Fri (includes the supervised RF) | `results_suricata2017_rebuilt\` |
| `config_cic2017_3day.yaml`, `config_cic2017_3day_sup.yaml` | an earlier run on Mon–Wed only, now superseded | `results_cic2017_3day*\` |
| `config_cic2018.yaml` | CSE-CIC-IDS2018, 2-day protocol | `results\` |
| `config_multiday.yaml` | CSE-CIC-IDS2018, 3-day protocol | `results_multiday\` |
| `config_context*.yaml`, `config_multiday_context*.yaml` | CSE-CIC-IDS2018 with the temporal-context view; `_clean` means the mislabelled flows are removed | `results_context*\`, `results_multiday_context*\` |
| `config_unsw.yaml` | UNSW-NB15, official train/test split | `results_unsw\` |

A few examples:

```bat
python run.py all --config config_suricata2017_rebuilt.yaml
python run.py train --config config_cic2017_monday.yaml --only ssl_mm_role ae_concat
python run.py explain --config config_cic2017_monday.yaml --method ssl_mm_experts
python run.py compare --config config_cic2018.yaml --capture-dir ..\external\pcap\thu22 --day Thursday-22-02-2018 --attacker 18.218.115.60
```

When you use `--only`, the stage name has to come first (`train --only ...`).

A new run overwrites its `results_*` folder, including the numbers reported in the thesis. If you just want to try
something out, point the output somewhere else first:

```bat
set IDS_WORK_DIR=work_test
set IDS_RESULTS_DIR=results_test
python run.py all
```

### Output

`work_*\` contains caches, the feature space and the trained models. It's safe to delete and gets rebuilt on the next
run. The only one I keep is `work_cic2017_monday\`, because `explain` needs it for the default CIC-IDS2017 models.

In `results_*\` you'll find:

- `scores\*.npz` with the raw validation and test scores of every method
- `metrics_overall.csv` and `metrics_overall_adapted.csv` with ROC-AUC, PR-AUC, precision, recall, FPR, MCC and F1 per
  method, first at the fixed validation threshold and then after per-day recalibration
- `recall_per_attack*.csv`, `fpr_recall_tradeoff*.csv`, `incidents*.csv`, `time_to_detection*.csv` and the plots
- `explanations*.md`, `explanation_quality*.csv` and `analyst_report*.md` (described under
  [Explanations](#explanations-and-analyst-reports))

### Building CIC-IDS2017 from the pcaps (experiment E7)

This is the only step that needs Docker Desktop, since Suricata runs in a pinned container. In Git Bash, plain
`python` may resolve to the base environment, so set `PY` to the `mlenv` interpreter first:

```bash
export PY=/d/SoftwareTools/Users/maida/anaconda3/envs/mlenv/python.exe
for d in Monday Tuesday Wednesday Thursday Friday; do
  bash logs/run_E7.sh sensors $d ../dataset/CICIDS2017/$d-WorkingHours.pcap   # Suricata, ~1 h per day
done
bash logs/run_E7.sh parquet          # suricata2017_rebuilt.parquet + LABEL_AUDIT.md (read the audit before training)
bash logs/run_E7.sh train config_cic2017_monday.yaml config_suricata2017_rebuilt.yaml   # 3 seeds each + bootstrap CIs (~5 h)
$PY scripts/e7_report.py --p1 config_cic2017_monday.yaml --p2 config_suricata2017_rebuilt.yaml --tag 5day
```

The raw `eve.json` for each day (1.5–2.5 GB) is deleted as soon as its `flows.parquet` has been written. On my laptop,
long runs only finished reliably once I started them in a way that survives closing the terminal (through WMI, with
`Invoke-CimMethod -ClassName Win32_Process -MethodName Create`) and kept Windows from sleeping with
`logs/keep_awake.ps1`.

### Older experiment scripts

The earlier experiments E1–E6 on CSE-CIC-IDS2018 are kept as bash scripts in `logs\run_*.sh`, next to their logs. Run
them from Git Bash with `mlenv` activated. `run_all.sh`, `run_knn.sh`, `run_unsw.sh` and `run_compare.sh` reproduce
the first rounds of results, and `docker_ids.sh` runs Suricata and Zeek on any pcap.

---

## Project structure

```
anomaly_pipeline\
├── run.py                     entry point (prepare / train / evaluate / explain / compare)
├── config*.yaml               one file per experiment
├── environment.yml, requirements*.txt, pyproject.toml
│
├── ids_pipeline\              the actual code
│   ├── adapters\suricata2017.py   CIC-IDS2017: Suricata events -> five telemetry modalities (flow, tcp, dns, http, session)
│   ├── adapters\unsw.py           UNSW-NB15
│   ├── data.py                loading, chronological splitting (and the CSE-CIC-IDS2018 CSV loader)
│   ├── features.py            feature spaces, service-role assignment, temporal-context features
│   ├── models.py              the multi-modal SSL network and the plain autoencoder
│   ├── baselines.py           Isolation Forest, PCA reconstruction, supervised Random Forest
│   ├── scoring.py             per-role calibration, latent-kNN scoring, min-p fusion, the E9 ensemble (TailEnsemble)
│   ├── train.py               trains every method, writes scores, builds ssl_mm_experts and ssl_mm_ensemble
│   ├── evaluate.py            metrics, per-attack recall, trade-off curves, incidents, plots, hybrids
│   ├── explain.py             SHAP, LIME and native attributions + their quality checks
│   ├── analyst_report.py      turns alerts + attributions + Suricata context into readable reports
│   ├── signature_compare.py   lines up Suricata/Zeek output with labelled flows
│   ├── schema.py, bundle.py, service.py, api.py, cli.py   the production layer
│   └── utils.py               config loading (with ${ENV:-default} paths), logging, seeding
│
├── scripts\                   analyses that work on saved scores (no retraining)
│   ├── cic2017_suricata.sh, build_suricata2017.py   CIC-IDS2017 pcaps -> Suricata -> labelled flow table
│   ├── e7_report.py               E7 hypotheses, CIC-IDS2017 tables and figures
│   ├── clean_eval.py, multiseed.py  seed-averaged metrics and bootstrap confidence intervals
│   ├── explore_fusion.py          the post-hoc modality-expert analysis
│   ├── e9_devtest.py              E9: choose on Tuesday, test once on Wednesday-Friday
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

Roughly, a run flows through the code like this:

```
pcap -> Suricata -> parquet ─┐
CSV (2018) / CSV (UNSW) ─────┴─> data.py / adapters ─> features.py ─> train.py ─> scores ─┬─> evaluate.py ─> metrics, plots
                                                      (modalities,   (models.py,          └─> explain.py  ─> analyst_report.py
                                                       roles)         baselines.py, scoring.py)
```

---

## Method and evaluation protocol

### The model

The network has a small encoder for each telemetry modality. On CIC-IDS2017 these follow Suricata's event types:
flow, tcp, dns, http and session (the last one covers TLS, SSH, FTP and anomaly events). Training is purely
self-supervised. A quarter of the input features are masked and the model has to reconstruct them. Every so often a
whole modality is dropped, which forces the model to lean on the remaining ones. There is also a cross-modal
contrastive (InfoNCE) term, although in the end it made no difference. Finally, each flow carries a role embedding, so
that a web server and a DNS server can each have their own notion of normal.

The anomaly score I use (`ssl_mm_role_knn`) is the distance from a flow's latent embedding to its 5 nearest benign
training embeddings that share the same service role. Attack labels are not used anywhere in training or scoring.

### Methods compared

| name | description |
|---|---|
| `ssl_mm_role_knn` | the proposed model with role-aware latent-kNN scoring (pre-registered in E7) |
| `ssl_mm_role` | the same network, scored by reconstruction error (the original score) |
| `ssl_mm_global_knn` | ablation without any role information |
| `ssl_no_contrastive_knn` | ablation without the contrastive term |
| `ssl_only_<modality>` | ablation: a model that only sees one telemetry source |
| `ssl_mm_ensemble` | the improved model from E9: a 3-seed ensemble of min-p(`ssl_mm_role_knn`, `ssl_mm_experts`) |
| `ssl_mm_experts` | post-hoc variant that fuses the single-source models by min-p |
| `ae_concat`, `ae_concat_knnrole` | plain autoencoder, scored by reconstruction error and by the same role-aware kNN scorer |
| `iforest`, `pca_recon` | unsupervised ML baselines |
| `rf_supervised` | supervised baseline, trained on the labelled attacks of the training period |
| `suricata_signature` | rule-based baseline: a flow counts as detected if it raised at least one ET Open alert |
| `hybrid_sig_or_<method>` | Suricata alert OR anomaly alert, as if both ran side by side |
| `ssl_mm_twoview_knn` | CSE-CIC-IDS2018 only: flow view and temporal-context view fused by min-p |

### Protocol

All models are trained on benign traffic only. The last 15% of each training day's benign traffic is held out for
validation, and the 99th percentile of the validation scores becomes the alert threshold, which targets a 1%
false-positive rate. Testing uses only later days, so none of the test attacks were seen during training. The one
deliberate exception is the supervised Random Forest. It gets to see the attacks of the training period, which is what
lets me show how it does on attacks it has never seen.

| protocol | config | train (benign only) | test |
|---|---|---|---|
| CIC-IDS2017 P1 (default) | `config_cic2017_monday.yaml` | Monday | Tuesday–Friday, all 14 attack types |
| CIC-IDS2017 P2 | `config_suricata2017_rebuilt.yaml` | Monday, Tuesday | Wednesday–Friday |
| CSE-CIC-IDS2018 2-day | `config_cic2018.yaml` | Wed-14, Thu-15 | Wed-21, Thu-22, Thu-01, Fri-02 |
| CSE-CIC-IDS2018 3-day | `config_multiday.yaml` | Wed-14, Thu-15, Wed-21 | Thu-22, Thu-01, Fri-02 |
| UNSW-NB15 | `config_unsw.yaml` | benign part of the official training set | official test set |

`evaluate` writes each table in two versions. The main one uses the fixed threshold from the benign validation data.
The `*_adapted` version recalibrates per day, using the first 30 minutes of each test day as an unlabelled reference
window; those 30 minutes are then excluded from the metrics.

---

## Results on CIC-IDS2017

### How I built the dataset

The public CIC-IDS2017 CSVs contain CICFlowMeter features. That is a single source, and its labels have known
problems. I wanted real multi-source telemetry, so `scripts/cic2017_suricata.sh` runs a pinned Suricata 8.0.7 with one
frozen ET Open rule file over each official pcap, and `scripts/build_suricata2017.py` turns the output into one row per
Suricata flow. The labels come only from CIC's published attack schedule (`docs/cic2017_attack_schedule.csv`, which
gives attacker IP, victim IP and time window). Suricata's own alerts are never used for labelling.

| day | Suricata flows | benign | attack flows | excluded |
|---|---|---|---|---|
| Monday | 343,005 | 343,005 | none (training day) | 0 |
| Tuesday | 294,902 | 287,910 | FTP-Patator 4,010; SSH-Patator 2,551 | 431 |
| Wednesday | 471,217 | 292,083 | DoS Hulk 161,096; GoldenEye 7,530; Slowhttptest 4,222; Slowloris 3,895; Heartbleed 1 | 2,390 |
| Thursday | 334,452 | 265,761 | Infiltration-Portscan 66,514; Web Brute Force 1,362; XSS 679; Infiltration 14; SQL Injection 12 | 110 |
| Friday | 524,643 | 264,355 | Portscan 161,264; DDoS 96,813; Botnet 743 | 1,468 |

Each build writes a `LABEL_AUDIT.md`, and I went through it before training anything. Suricata didn't lose state on
any day, and all five days were processed with the same rule file (identical sha256). In every attack window the
traffic is dominated by the scheduled attacker on the expected ports. Where the schedule can't explain some traffic, I
excluded it instead of guessing a label. This covers SSH-Patator continuing about 20 minutes past its published end,
the Heartbleed victim's normal HTTPS traffic to the firewall, and the bots that kept beaconing to their C&C server
after the Botnet window closed. Excluded flows count as neither benign nor attack. Suricata alerts on 0.71% of benign
flows (2.10% on Monday), and that is the real false-positive rate of the rule-based baseline.

Before this, I used a third-party Suricata version of CIC-IDS2017 from Hugging Face. Its provenance wasn't documented
and its labels disagreed with CIC's own documentation, so I withdrew it and deleted it on 2026-10-03. It only remains
as part of the history in `PREREGISTRATION.md`, and `docs/SURICATA2017_PROVENANCE.md` has the details.

### Main result: the pre-registered experiment E7

I wrote down the hypotheses in `results_comparison/PREREGISTRATION.md` before touching any of the Tuesday–Friday
pcaps. E7 uses the hyperparameters as shipped (nothing was tuned on this dataset), seeds 42, 1 and 2, and 95%
block-bootstrap confidence intervals on paired differences (`scripts/clean_eval.py`). The full tables are in
`results_comparison/E7_5day_tables.md` and the figures in `figE7_5day_*.png`.

P1 (train Monday, test Tue–Fri; 1,620,815 flows of which 510,706 are attacks), fixed threshold, mean over 3 seeds:

| method | ROC-AUC | PR-AUC | recall | realised FPR | MCC | incident recall | false alerts/h |
|---|---|---|---|---|---|---|---|
| Suricata ET signatures (rule-based) | 0.501 | 0.316 | 0.004 | 0.28% | 0.01 | 0.73 | 93 |
| Proposed `ssl_mm_role_knn` | 0.945 ± 0.006 | 0.858 | 0.115 ± 0.189 | 0.50% | 0.18 | 0.70 | 169 |
| Hybrid: Suricata OR proposed | 0.942 | 0.844 | 0.118 | 0.77% | 0.18 | 0.91 | 261 |
| `ae_concat_knnrole` (AE + same scorer) | 0.936 | 0.875 | 0.295 | 0.96% | 0.44 | 0.88 | 327 |
| `ae_concat` (reconstruction error) | 0.937 | 0.748 | 0.000 | 0.15% | −0.02 | 0.06 | 53 |
| `iforest` | 0.953 | 0.825 | 0.086 | 1.26% | 0.14 | 0.59 | 427 |
| `pca_recon` | 0.923 | 0.704 | 0.000 | 0.17% | −0.02 | 0.09 | 57 |
| `ssl_mm_global_knn` (no roles) | 0.792 | 0.689 | 0.085 | 0.70% | 0.17 | 0.83 | 237 |
| `ssl_no_contrastive_knn` | 0.944 | 0.856 | 0.156 | 0.47% | 0.26 | 0.62 | 160 |

On P2 (train Mon+Tue, test Wed–Fri, fixed threshold) the ROC-AUC / recall figures are 0.951 / 0.070 for the proposed
model, 0.961 / 0.262 for `ae_concat_knnrole`, 0.957 / 0.050 for `iforest`, 0.499 / 0.001 for Suricata and 0.612 /
0.004 for the supervised `rf_supervised`. P1 has no supervised baseline, because Monday has no attacks to learn from.

Here is how the hypotheses turned out:

| H | claim | outcome | evidence (P1; paired ROC-AUC difference, 95% CI) |
|---|---|---|---|
| H1 (RQ1) | SSL detects unseen attacks: AUC ≥ 0.90 and beats AE / iForest / PCA | not supported | AUC 0.945, but vs AE +0.008 [−0.019, 0.034], vs iForest −0.009 [−0.043, 0.017], vs PCA +0.021 [−0.004, 0.043] |
| H2 (RQ1/RQ4) | beats the rule-based IDS at a controlled false-alert rate | supported | recall 0.115 vs 0.004 at FPR 0.50% |
| H3 | signatures and the anomaly model work better together | supported | incident recall 0.91 vs 0.70 / 0.73 |
| H4 (RQ2) | multiple telemetry sources beat every single source | supported | flow +0.013 [0.005, 0.020], tcp +0.19, http +0.14, session +0.49, dns +0.74 (all CIs > 0) |
| H5 (obj. 4) | role-aware beats global | supported | +0.153 [0.007, 0.329] |
| H6 (RQ1) | supervised learning fails on unseen attacks | supported | P2: RF recall 0.004 vs 0.070 |
| H7 | the gain is not just the kNN scorer | not supported | vs `ae_concat_knnrole` +0.009 [−0.025, 0.044] |

Looking at individual attack types (P1, fixed threshold, seed mean), Suricata catches the attacks it has rules for:
FTP-Patator 0.49, SQL injection 0.67, Infiltration 0.21 and the single Heartbleed flow. It finds nothing at all of
Botnet, DoS, DDoS, Portscan or Web Brute Force. The proposed model adds Botnet 0.27, Portscan 0.28, FTP-Patator 0.33,
Slowloris 0.19 and Infiltration-Portscan 0.14, but it hardly touches DoS Hulk or DDoS (0.005). `ae_concat_knnrole`
gets DDoS 0.98 and Slowloris 0.57, and `iforest` is the only method that catches some DoS Hulk (0.25) and GoldenEye
(0.38). Web XSS, SQL injection and SSH-Patator stay close to zero for every anomaly model.

### Interpretation

I think the results support four things. First, the model ranks unseen attacks well after training only on benign
traffic (ROC-AUC 0.945 on P1 and 0.951 on P2), far better than the signature IDS, which sits at chance (0.50) because
it alerts on so few attack flows. Second, the supervised Random Forest falls apart on attack types it hasn't seen
(0.61 AUC, recall 0.004), which is exactly the zero-day gap the project started from. Third, both main design choices
hold up on real Suricata telemetry with confidence intervals: several sources beat any single one, and role-aware
baselines beat a single global one. Fourth, signatures and the anomaly model complement each other, and together they
find 91% of the attack incidents.

There are also two things the results don't support, and the thesis says so. The SSL encoder is not shown to be better
than simpler unsupervised models. Isolation Forest, PCA and especially the autoencoder with the same role-aware kNN
scorer are statistically tied with it on ROC-AUC, and the AE+kNN actually has better recall and MCC. The contrastive
term has no measurable effect either (vs `ssl_no_contrastive_knn`: +0.001 [−0.001, 0.003]). The other problem is that
the operating point isn't stable across seeds. Recall at the fixed threshold is 0.005, 0.007 and 0.334 for seeds 42, 1
and 2, while ROC-AUC hardly moves (0.938–0.950). What happens is that the Monday threshold ends up just above or just
below the large cluster of DoS Hulk and DDoS scores. Per-day recalibration raises recall to 0.38 (at 1.9% FPR), but the
sensitivity to the seed is still there.

An earlier single-seed run on Monday–Wednesday only (`config_cic2017_3day*.yaml`) gave ROC-AUC 0.919 for the proposed
model and 0.979 for `iforest`. E7 replaces it.

### Exploratory follow-up: fusing the single-source experts

This part is post hoc. I tried it after I had already seen the E7 test labels, so it isn't a claim in the thesis; it
is logged as X1 in `PREREGISTRATION.md`. E7 suggested that a single source often carries the signal by itself (the
TCP-only model did surprisingly well). So `ssl_mm_experts` keeps the five single-source models separate, ranks each
one against its own benign validation scores, and lets the most extreme one decide. This is the same min-p fusion I
had already used for the two-view model on CSE-CIC-IDS2018. `train` builds it automatically from the experts' scores
(`train.fuse_experts`), and you can turn it off with `scoring.expert_fusion: false`.

| CIC-IDS2017 P1, 3 seeds | ROC-AUC | recall (fixed) | MCC (fixed) | recall at an equal 1% FPR |
|---|---|---|---|---|
| E7 `ssl_mm_role_knn` | 0.945 | 0.12 | 0.18 | 0.22 |
| `iforest` | 0.953 | 0.09 | 0.14 | 0.02 |
| `ae_concat_knnrole` | 0.936 | 0.30 | 0.44 | 0.21 |
| `ssl_mm_experts` | 0.951 ± 0.007 | 0.43 | 0.54 | 0.37 |

On ranking it ties the best baseline, and at the operating point an analyst would actually work with, it catches more
attacks than anything else. With seed 42, the Suricata-OR-experts hybrid finds 95% of attack incidents. It isn't
free, though. At the fixed threshold it produces far more false alerts (about 644 per hour on seed 42, compared with
58 for the E7 model), its recall still varies with the seed (± 0.17), and it does worse than the E7 model on
CSE-CIC-IDS2018 (0.56) and UNSW-NB15 (0.87). On those two datasets the "modalities" are just column groups from one
flow record, not separate sources.

My guess is that separate experts help when the sources are genuinely separate. That's still a hypothesis, and I have
pre-registered a test of it as E8, to be run on Terma telemetry.

One lesson from this: my first version averaged z-scores and looked much better (0.98 AUC), but that turned out to be
a numerical artifact. Most benign flows have identical TCP/HTTP features, so the spread of those experts was zero and
any small deviation exploded. I threw that version away. The comparison can be reproduced with
`python scripts/explore_fusion.py` (output in `results_explore\`), and the full run is in
`results_experts_cic2017_monday\`.

### Fixing the operating point: dev/test experiment E9

After E7 there were two open problems: the tie on ranking, and an alert threshold that swings with the seed. E9 went
after the second one without retraining anything, using a clean dev/test split. All candidates were trained on Monday
only. I used Tuesday to choose between them, wrote the choice down (`PREREGISTRATION.md`, E9; `scripts/e9_devtest.py`),
and only then tested once on Wednesday–Friday. The labels for those days had already been seen during E7, so this is
weaker evidence than E7 itself.

The candidate with the best PR-AUC on Tuesday was a 3-seed ensemble of min-p(E7 kNN score, modality experts). It
averages over three encoders, and inside each one the latent-kNN score and the five single-source experts back each
other up. To keep the comparison fair, I ensembled the baselines in the same way.

| Wed–Fri test, fixed threshold | ROC-AUC | PR-AUC | recall | FPR | MCC |
|---|---|---|---|---|---|
| SSL ensemble (E9 selection) | 0.954 | 0.928 | 0.631 | 1.8% | 0.686 |
| E7 `ssl_mm_role_knn` (seed mean) | 0.945 | 0.886 | 0.114 | 0.5% | 0.172 |
| `iforest` (3-seed ensemble) | 0.955 | 0.862 | 0.074 | 1.3% | 0.160 |
| `ae_concat_knnrole` (3-seed ensemble) | 0.941 | 0.907 | 0.210 | 1.0% | 0.347 |
| `pca_recon` | 0.922 | 0.751 | 0.000 | 0.2% | −0.02 |
| Suricata signatures | 0.499 | 0.380 | 0.001 | 0.3% | −0.02 |

At the operating point, the ensemble beats every baseline with confidence intervals above zero. Its MCC is higher than
Isolation Forest (+0.53 [0.12, 0.94]), the autoencoder with the same scorer (+0.34 [0.07, 0.67]), PCA (+0.71
[0.42, 0.94]) and Suricata (+0.71 [0.42, 0.94]). It finds 63% of attack flows at a 1.8% false-positive rate, where the
best baseline finds 21%. It is also a clear improvement over the E7 model (MCC +0.51 [0.32, 0.70]). On ranking,
however, it still ties the unsupervised baselines (ROC-AUC vs iForest −0.002 [−0.05, 0.04]), so H9.1 is not
supported. In other words, the gain comes from ensembling and from combining different kinds of evidence when scoring,
not from a better encoder.

`ssl_mm_ensemble` runs like any other method in the pipeline, but it needs trained models for all three seeds. Train
the extra seeds first, then let `train` assemble the ensemble from the saved scores (no retraining), and finally
evaluate and explain it:

```bat
python run.py all
python scripts\multiseed.py --config config_cic2017_monday.yaml --seeds 1 2
python run.py train --only ssl_mm_ensemble
python run.py evaluate
python run.py explain --method ssl_mm_ensemble
```

The seeds are taken from `scoring.ensemble_seeds` (default `[1, 2]`) plus the config's own seed. Built this way, it
reproduces the E9 numbers exactly. To explain its alerts, `explain` reloads each seed's network and its five experts,
and refits that seed's kNN reference the same way as during training.

---

## Results on CSE-CIC-IDS2018 and UNSW-NB15

### Overview

ROC-AUC / PR-AUC / recall at the benign-validation threshold (about 1% target FPR):

| dataset | `ssl_mm_role_knn` | `ae_concat_knnrole` | `ae_concat` | `iforest` | supervised RF | Suricata |
|---|---|---|---|---|---|---|
| CIC-IDS2017 P1 (3 seeds) | 0.945 / 0.858 / 0.12 | 0.936 / 0.875 / 0.29 | 0.937 / 0.748 / 0.00 | 0.953 / 0.825 / 0.09 | n/a | 0.501 / 0.316 / 0.00 |
| UNSW-NB15 | 0.928 / 0.947 / 0.67 | 0.928 / 0.944 / 0.61 | 0.910 / 0.929 / 0.64 | 0.827 / 0.850 / 0.22 | 0.985 / 0.989 / 0.98 | – |
| CSE-CIC-IDS2018 3-day | 0.829 / 0.435 / 0.02 | 0.792 / 0.361 / 0.03 | 0.705 / 0.336 / 0.02 | 0.525 / 0.160 / 0.01 | 0.893 / 0.686 / 0.00 | – |
| CSE-CIC-IDS2018 2-day | 0.779 / 0.460 / 0.01 | 0.745 / 0.425 / 0.01 | 0.593 / 0.320 / 0.01 | 0.434 / 0.256 / 0.00 | 0.568 / 0.391 / 0.00 | – |

On these two datasets the proposed model beats Isolation Forest and the autoencoder's reconstruction score, by a wide
margin on CSE-CIC-IDS2018 and by less on UNSW-NB15. Once the autoencoder uses the same scorer, the two are tied or the
SSL model is slightly ahead. The supervised RF wins on UNSW-NB15 and on the CSE-CIC-IDS2018 3-day split, but in those
cases it has seen the same attack types during training, so that isn't a zero-day situation. On unseen attacks it flags
almost nothing at its fixed threshold.

It's worth remembering that neither CSE-CIC-IDS2018 nor UNSW-NB15 has separate telemetry sources. Their "modalities"
are four views of the same CICFlowMeter or Argus record, so the multi-modal claim (RQ2) depends on CIC-IDS2017 alone.

The latent-kNN scoring was designed on CSE-CIC-IDS2018 (2-day) and UNSW-NB15, before I used CIC-IDS2017 at all. A
label-free hyperparameter search (`scripts/hparam_search.py`, 15 candidates evaluated on synthetic anomalies) came out
flat to within about 0.002 AUC, so I kept the defaults. The contrastive term not helping is therefore not a matter of
tuning.

### CSE-CIC-IDS2018: temporal context, label audit and experiments E1–E6

These were my development experiments. `PREREGISTRATION.md` has the full record; the main findings are below.

The dataset has a labelling error (`docs/LABEL_AUDIT.md`, `scripts/label_audit.py`). On Wed-21, 358,623 flows marked
Benign are actually the HOIC attack's connections recorded in the opposite direction, and they make up 99% of that
day's "benign" test flows. The `*_clean` configs remove them, which brings the 2-day false-positive rate of the kNN
methods down from about 16% to 1.5–2%. Separately, 17.6% of the Infiltration flows are identical to benign flows,
feature for feature, which puts a ceiling on Infiltration recall for any flow-level detector.

Single flows can't reveal floods, scans or beaconing, so I added 12 temporal-context features (flows per second to the
same port, distinct ports per window, near-identical flows, time since the previous similar flow) as a separate view
and fused it with the per-flow view by min-p (`config_context*.yaml`). On the 2-day protocol this raised ROC-AUC from
0.49 to 0.94 and caught HOIC (0.995). On the held-out 3-day clean protocol (E4), however, the flow view alone ranked
slightly higher, so the claim that multiple views beat every single view was not supported there. Within the two-view
design, the SSL encoder did beat the autoencoder (+0.021 [0.016, 0.026]).

E5 looked at recall at a controlled false-alert rate. At 1% FPR, flow-level recall is limited by how separable Bot and
Infiltration are in the first place (oracle recall 2–26%). A window-level alerting test cut false alerts from 48 to
0.26 per hour, but kept only 16% of the recall, so it missed its pre-registered target.

E6 asked why the contrastive term doesn't help. In a batch of 256 flows, 82–97% share their exact TCP / HTTP / session
block with another flow in the batch, mostly because absent protocols produce all-zero blocks. That leaves the
contrastive task at chance level. Masking out those false negatives lets it train, but detection still doesn't improve.

I also tried a late-fusion kNN variant (`*_latefuse_knn`, one kNN per modality, maximum taken). It was worse
everywhere, for example 0.862 vs 0.945 on CIC-IDS2017, and I only keep it for reproducibility.

### UNSW-NB15

UNSW-NB15 uses its official train/test split, and the models are fitted on the benign flows of the training part
only. The data has no timestamps and is sorted by class, so the adapter shuffles it with a fixed seed and takes a
random 15% as the benign validation slice. The test set has 82,332 flows, 55% of which are attacks. The supervised RF
reaches 0.985 AUC, but because UNSW's train and test sets contain the same attack types, that isn't a zero-day
comparison.

### Suricata and Zeek on a real CSE-CIC-IDS2018 capture

`docker_ids.sh` runs Suricata and Zeek on the Thu-22 victim capture, and `run.py compare` matches their alerts against
the labelled attack flows (all 362 were matched). Using the 3-day models:

| attack | Suricata ET | Zeek | `ssl_mm_role_knn` | Suricata OR `ssl_mm_role_knn` |
|---|---|---|---|---|
| Brute Force -Web (249) | 0.016 | 0 | 0.418 | 0.426 |
| Brute Force -XSS (79) | 0.899 | 0 | 0.760 | 0.937 |
| SQL Injection (34) | 0.265 | 0 | 0.147 | 0.353 |

The pattern is the same as on CIC-IDS2017. Signatures catch what they have a rule for (XSS), the anomaly model catches
behaviour without a rule (web brute force), and combining the two works best. This is one capture with three attack
types, so I only treat it as an illustration.

---

## Explanations and analyst reports

`python run.py explain [--config <cfg>] [--method <model>]` explains a sample of alerts, stratified over attack types
and including some false alarms. It uses three methods: native attribution (per-feature reconstruction error), SHAP
(KernelExplainer on the calibrated score, with a benign background per role) and LIME (one explainer per role). The
output is `explanations*.md`, `explanation_quality*.csv` and an analyst report, `analyst_report*.md`.

Each alert in the analyst report has four parts. It starts with a verdict and a priority: CONFIRMED when both a
Suricata signature and the anomaly model fire, otherwise ANOMALY ONLY, meaning it could be new activity or a false
alarm. Signature names are translated into what they mean. Next comes the reason the flow looks abnormal: the top SHAP
features in readable units, next to the normal range for that service role (for example "bytes sent by the server:
190 KB vs 242 B normal"). A feature only counts as stable if it shows up in two independent SHAP runs, and the
behaviour hints ("looks like a flood / scan / slow attack") are only built from stable features. Then there is the
network context from the Suricata record: IPs and ports, HTTP URIs, DNS names and the TLS server name. Finally the
report suggests next steps and gives a confidence level. The ground-truth label is shown last and is only there for
evaluation.

The quality of the explanations is checked automatically in three ways. Deletion fidelity asks whether the score drops
when the top features are reset to normal values, compared with resetting random features. Stability asks whether two
SHAP or LIME runs agree on the top features. Cross-method agreement asks whether the methods agree with each other.

Some results from these checks:

- LIME had two problems that I fixed along the way: it used one background for the whole dataset, and it had too many
  features for its sample size. After the fix, its deletion fidelity on CSE-CIC-IDS2018 2-day went from −0.03 to
  +0.25.
- SHAP is faithful and improved on all three datasets (deletion drop 0.23–0.40). LIME did well on CSE-CIC-IDS2018
  2-day but got worse on UNSW-NB15. I report that as it is rather than averaging it away. For the analyst reports I
  rely on SHAP and native attribution, and keep LIME as a cross-check.
- For `ssl_mm_experts` on CIC-IDS2017 P1, the SHAP deletion drop is 0.32, against −0.12 for random features. Each
  alert also says which source drove it, for example "http 90%" for a DDoS flow.

The E9 ensemble (`ssl_mm_ensemble`) needed extra work before it could be explained. Its score is rank-based and
saturates at about 10.85 for strong alerts, where no single feature can move it. Explained directly, SHAP failed the
deletion test (−0.15 vs −0.22 for random features). So `explain` works on an unsaturated version of the same score
(`TailEnsemble.transform(extrapolate=True)`). Above each level's benign 99th percentile, the empirical tail is replaced
by an exponential tail fitted to the top scores. Below that point it is identical to the detector's score, so the set
of alerts doesn't change. With this, SHAP passes (deletion drop +0.10 vs −0.12 random; stability 0.63), and I had set
that criterion before the run. Native attribution and LIME still fail (−0.23 vs −0.21 and −0.18 vs −0.20). Resetting
features to the benign median makes the ensemble more suspicious even when the features are random, because a mix of
median values is itself an unusual flow for some of its 15 member models. For the ensemble, the analyst reports should
therefore use SHAP only. Its explanations are weaker than those of `ssl_mm_experts` (SHAP +0.32); that's the cost of
the better detection.

All of these checks are automatic. Whether the explanations actually help an analyst still has to be judged by a person,
which I plan to do with my supervisor at Terma.

---

## Scoring service

On top of the research code there is a layer meant for deployment: model bundle export, input validation, an HTTP API,
a batch CLI, tests, CI and a Docker image.

```bat
ids-detect export --config config_multiday.yaml --out models\prod        :: trained run -> pickle-free, checksummed bundle
set IDS_API_KEYS=...
ids-detect serve --bundle models\prod --host 0.0.0.0                     :: POST /v1/score, GET /v1/model, /healthz /readyz /metrics
ids-detect score --input flows.csv --bundle models\prod --output scored.csv
ids-detect recalibrate --benign site_benign.csv --bundle models\prod --out models\site   :: fixes threshold drift without retraining
```

[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) and [docs/API.md](docs/API.md) describe it in more detail. A few limitations
to be aware of: the service has not been tried on customer data yet. Bundles from the `*context*` configs can't be
served, because the service doesn't compute context features for individual incoming flows. And none of the
CIC-IDS2017 models can be served yet, `ssl_mm_ensemble` included, because the service expects CICFlowMeter-style flow
columns while those models take Suricata event features. Adding Suricata (eve.json) input to the service is the same
job as writing the Terma adapter.

---

## Deviations from the proposal and known limitations

- Multi-modal telemetry is only demonstrated on CIC-IDS2017, since it is the only dataset with real, separate sources
  (Suricata flow, TCP, DNS, HTTP and session events). CSE-CIC-IDS2018 and UNSW-NB15 have a single flow record per
  connection. Terma's Suricata or Zeek data would plug in through the adapter interface in `ids_pipeline/adapters/`.
- On CIC-IDS2017 the SSL model ties simpler unsupervised models (H1 and H7 are not supported), and its recall at the
  fixed threshold depends heavily on the seed. The post-hoc `ssl_mm_experts` is not a claim until E8 has been run.
- The CIC-IDS2017 labels are time-window labels taken from CIC's schedule. Everything between the scheduled attacker
  and victim inside the window counts as attack, failed attempts and replies included. Today's ET Open rules know these
  2017 attacks with hindsight, so the signature baseline should be read as an optimistic upper bound for a signature
  IDS in 2017.
- "Role" means a service role derived from the destination port (web, DNS, remote admin and so on), because the public
  datasets have no asset inventory. On Terma data it would be the actual asset role or network zone.
- The CSE-CIC-IDS2018 CSVs are cut off at 1,048,576 rows (the Excel limit) and contain duplicates. About 20% of the
  Wed-14 rows are duplicates and are dropped.
- So far, the usefulness of the explanations (RQ3) has only been measured automatically, not rated by an analyst.
- Nothing has been validated on Terma's own traffic yet; every result here comes from public benchmarks. Testing on
  Terma telemetry (E8) needs a Terma adapter and, ideally, a labelled period such as a red-team exercise.

---

## Troubleshooting

| problem | cause and fix |
|---|---|
| `DLL load failed` when importing `pyarrow` | The pip version of pyarrow is installed. Run `python -m pip uninstall -y pyarrow`, then `conda install -y pyarrow`. |
| `Could not find/load shared object file 'llvmlite.dll'`, or `shap` won't import | The pip version of numba is installed. Run `python -m pip uninstall -y numba llvmlite`, then `conda install -y numba`. |
| `Unable to find a usable engine; tried using: 'pyarrow'` | pyarrow is missing or fails to load; see the first row. |
| `OMP: Error #15 ... libiomp5md.dll already initialized`, or `Fatal Python error: Aborted` | Two OpenMP libraries are loaded. Apply the OpenMP fix from the setup section. |
| `import torchvision` fails with `operator torchvision::nms does not exist` | A leftover conda torchvision. Run `conda remove -y torchvision torchaudio cpuonly pytorch-mutex`. |
| `ModuleNotFoundError` right after installing a package | It was installed into the base environment. Use `python -m pip install ...` with `mlenv` active. |
| `python run.py all` can't find `suricata2017_rebuilt.parquet` | The CIC-IDS2017 flow table hasn't been built. Follow "Building CIC-IDS2017 from the pcaps", or set `IDS_SURICATA_PARQUET` to the file. |
| UNSW run fails with file not found | Both CSVs need to be in `dataset\UNSW_NB15\` (or `IDS_UNSW_DIR`) under their official names. |
| `error: ...` from `run.py` about a config or a column | This is a `ConfigError` or `DataError`, and the message names the file or column. Check the paths described under Datasets. |
| Old results got overwritten | Set `IDS_RESULTS_DIR` and `IDS_WORK_DIR` before experimenting. |
| A 2018 or UNSW run is slow the first time | Its `work_*` cache was deleted to save disk space and is being rebuilt. This is expected. |
| `failed to connect to the docker API ... dockerDesktopLinuxEngine` | Docker Desktop isn't running. Start it and wait until `docker info` responds. |
| Suricata takes many hours for one day instead of about one | Windows went to sleep and paused Suricata. Run `logs/keep_awake.ps1` during long jobs. |
| A long run stops when the terminal or VS Code is closed | Start long jobs through WMI (`Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=...}`). |
| `python` in Git Bash is Python 3.13, or packages are missing | Git Bash is picking up the base Anaconda python. Point to the `mlenv` interpreter explicitly (`export PY=.../envs/mlenv/python.exe`). |
| `explain --method ssl_mm_role_knn` fails with `FileNotFoundError ... ssl_mm_role_knn.pkl` | `explain` needs a trained network, not a scoring variant. Use `--method ssl_mm_role` (the default), `ssl_mm_experts` or `ssl_mm_ensemble`. |
| `[ssl_mm_ensemble] skipped: missing ...` | The other seeds haven't been trained yet. Run `scripts\multiseed.py --config config_cic2017_monday.yaml --seeds 1 2` first. |
