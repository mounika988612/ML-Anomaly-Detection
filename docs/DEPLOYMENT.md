# Deployment guide

## Architecture
```
 training site (research pipeline)                    production
 run.py prepare/train ──► work/models ──► ids-detect export ──► bundle/ ──► ids-detect serve (HTTP)  /  ids-detect score (batch CSV)
                                                       manifest.json + weights.pt + reference.npz
```
A **bundle** is self-contained and pickle-free: `weights.pt` (loaded with `weights_only=True`), `reference.npz`, and a
`manifest.json` holding the feature space, calibration, alert threshold and SHA-256 of both files. A modified or truncated bundle
is refused at start-up. The service never reads training data or the research config.

## 1. Build a bundle
```bash
pip install -e ".[research]"                       # training environment
python run.py --config config_multiday.yaml all    # or prepare + train
ids-detect export --config config_multiday.yaml --out models/prod
```
Dataset location is configured by environment, not by editing YAML: `IDS_DATA_DIR`, `IDS_WORK_DIR`, `IDS_RESULTS_DIR`
(defaults are relative to the config file). The same command works on Windows, Linux and WSL.

**For a customer, train on that customer's benign traffic** (same CICFlowMeter columns) and export from that run. A model trained on
CSE-CIC-IDS2018 carries that lab's notion of "normal".

## 2. Run
Docker (recommended):
```bash
docker build -t ids-detect .
IDS_API_KEYS=$(openssl rand -hex 24) docker compose up -d      # mounts ./models/prod read-only
curl localhost:8080/readyz
```
Without Docker: `pip install -e ".[serve]" && IDS_API_KEYS=... ids-detect serve --bundle models/prod --host 0.0.0.0`.
Batch: `ids-detect validate --input flows.csv --bundle models/prod` then `ids-detect score --input flows.csv --bundle models/prod --output scored.csv`
(rejected rows go to `scored.rejected.csv`; exit code 2 = bad input, 1 = internal failure).

| Variable | Meaning | Default |
|---|---|---|
| `IDS_BUNDLE_DIR` | bundle path | – (required) |
| `IDS_API_KEYS` | accepted keys, comma-separated | – (**service refuses to start without**) |
| `IDS_ALLOW_ANONYMOUS` | `1` disables auth, development only | off |
| `IDS_MAX_BATCH` / `IDS_MAX_BODY_MB` | request limits | 5000 / 20 |
| `IDS_LOG_LEVEL` | research pipeline log level | INFO |

Use TLS: either terminate at a reverse proxy/ingress, or pass `--ssl-certfile/--ssl-keyfile` to `ids-detect serve`. The API key is a bearer secret.
Set `IDS_LOG_FORMAT=json` for log shippers (one JSON object per line, with request id, path, status, latency).
Container runs as non-root, read-only root filesystem, no capabilities. Scale by adding replicas (the model is stateless);
`--workers N` multiplies memory by N. Measured on a laptop CPU: ~68k flows/s in-process on the 3-day model (1.04M flows, batch scoring).

## 3. Operate
* **Probes**: liveness `/healthz`, readiness `/readyz`. **Metrics**: `/metrics`.
* **Drift**: the threshold encodes a benign-validation FPR (default 1%). On CSE-CIC-IDS2018 the fixed-threshold FPR reached 16.5% on
  later days in the 2-day protocol, so expect drift. `ids_drift` / `GET /v1/model` → `drift` flag it (recent alert rate > 3× target).
  Fix without retraining: `ids-detect recalibrate --benign recent_benign.csv --bundle models/prod --out models/site` refits the score
  centre/scale and the threshold on benign flows of *your* network (≥2,000; you vouch they contain no attacks; weights and reference set stay
  identical, the old bundle stays for rollback). Check on the real 3-day model (Thu-22, calibrate on the first half of benign, evaluate on the
  second): FPR 1.30% → 1.07% (target 1%), attack recall 46.7% → 42.8%. This model barely drifted on that day, so the gain shown is small;
  it has not been demonstrated on the 2-day model that drifted to 16.5%. A threshold cannot fix a model whose ranking degraded: then retrain.
* **Other exporters / asset roles**: `--column-map` / `IDS_COLUMN_MAP` map foreign column names; `--role-column` (CLI) and `role` (API) supply asset roles.
* **Model updates**: export to a new directory, run `ids-detect validate/score` on a sample, swap the mount, restart (checksum verified on load).
  Keep the previous bundle for rollback.
* **Security**: rotate API keys by listing old+new, migrating clients, dropping old. Don't expose the port without TLS.

## 4. Quality gates
`pytest` (67 tests: config, schema/cleaning, feature space, bundle integrity, scoring, recalibration, drift, API auth/limits/contract, CLI) and `ruff` run in
GitHub Actions on Python 3.10 and 3.12, plus a Docker build. Locally: `pip install -r requirements-dev.txt && pytest`.
Numerical parity with the research pipeline was checked on the real 3-day model (Thu-22, 1.04M flows): identical threshold and pooled
ROC-AUC (0.9009), 1 of 1,039,684 alert decisions differs (float noise on near-duplicate flows).

## 5. Known limits (read before a customer pilot)
* **Input schema is CICFlowMeter's.** Renamed columns can be mapped, but a different exporter (Zeek conn.log, NetFlow/IPFIX) produces
  *different features*, so a name mapping is not enough: that needs retraining on that telemetry. A mismatch fails loudly, not silently.
* **Roles default to the destination port** (the dataset has no IPs). Supply asset roles per flow if you have an inventory; note the model was
  trained with port-derived roles, so inventory roles are only meaningful if they map onto the same nine categories.
* **Detection quality is what the thesis measured, not a guarantee**: ranking is good (AUC 0.83 pooled 3-day, 0.98 on Suricata2017) but recall at a
  1% FPR threshold on drifting real traffic is low (1-4% on CIC-2018). Treat it as a triage/prioritisation signal next to signature IDS,
  not a standalone blocker. It is untested on Terma's traffic and has not been evaluated with analysts.
* Explanations in the API are per-feature reconstruction error; the SHAP/LIME analyst reports remain research tooling (`run.py explain`).
* No training-as-a-service, model registry, or automatic retraining (recalibration is manual). The Docker image and compose file are untested:
  the Docker daemon was not running where this was developed, so only CI (or your first `docker build`) verifies them.
* No rate limiting or per-client quotas in the service; do that at the gateway. Single API-key tier, no per-key roles.
