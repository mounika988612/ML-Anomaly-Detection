# API contract (v1)

The machine-readable contract is the OpenAPI document served at `GET /openapi.json` (Swagger UI at `/docs`).
Breaking changes will move to `/v2`; additive fields may appear in `/v1` responses, so clients must ignore unknown fields.

Authentication: header `X-API-Key: <key>` on everything except `/healthz` and `/readyz`.
Keys are configured with `IDS_API_KEYS` (comma-separated, allows rotation: add the new key, migrate clients, remove the old one).

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | liveness (process is up) |
| GET | `/readyz` | readiness (model bundle loaded and verified) |
| GET | `/v1/model` | model metadata, threshold, **required input columns**, limits |
| POST | `/v1/score` | score a batch of flows |
| GET | `/metrics` | Prometheus text metrics |

## Input: one flow = CICFlowMeter columns by name
`GET /v1/model` → `required_columns` lists exactly what the loaded model needs (names as in the CSE-CIC-IDS2018 CSVs,
e.g. `Flow Duration`, `Tot Fwd Pkts`, `Dst Port`, `Protocol`). Extra columns are ignored. Values may be numbers or numeric strings. Padded names and the common CICFlowMeter-2017 spellings
(`Total Fwd Packets`, `Destination Port`, ...) are mapped automatically; for any other exporter set `IDS_COLUMN_MAP` to a JSON file `{"their_name": "canonical name"}`.
Optional per-flow `role` (one of `roles` from `/v1/model`, e.g. from your asset inventory) overrides the destination-port heuristic; unknown roles are rejected.

```json
POST /v1/score
{
  "top_k": 3,
  "flows": [
    {"id": "conn-8f2a", "features": {"Dst Port": 443, "Protocol": 6, "Flow Duration": 120394, "Tot Fwd Pkts": 12, "...": 0}}
  ]
}
```

## Output
```json
{
  "model": "ssl_mm_role_knn",
  "threshold": 2.32,
  "n_alerts": 1,
  "results": [
    {"id": "conn-8f2a", "score": 4.81, "threshold": 2.32, "alert": true, "role": "web",
     "top_features": [{"feature": "Fwd Pkt Len Max", "error": 31.2}]}
  ],
  "rejected": [{"index": 4, "id": "conn-19bc", "reason": "non-numeric, missing or infinite value in 'Flow Duration'"}]
}
```
* `score` — calibrated robust z-score; **higher = more anomalous**. `alert` is `score > threshold`. The threshold is fixed at the
  benign-validation quantile chosen at export time (`target_fpr`), *for the network the model was trained on*.
* `top_features` — only for alerts; features with the largest reconstruction error (native attribution, standardised units).
  It says where the flow deviates, not why it is malicious.
* `results` keep the request order; `rejected[].index` is the position in the request. A bad row never fails the batch.

## Errors
All errors are `{"error": "<code>", "detail": "<text>"}`.

| Status | `error` | Meaning |
|---|---|---|
| 401 | – | missing/invalid API key |
| 413 | `batch_too_large` / `payload_too_large` | more than `IDS_MAX_BATCH` flows / body over `IDS_MAX_BODY_MB` |
| 422 | `invalid_input` | a required column is absent from the batch (schema problem) |
| 422 | (validation) | malformed JSON body: unknown fields, empty `flows`, `top_k` outside 0-10 |
| 503 | `model_error` / – | model not loaded or bundle invalid |

Per-row problems (non-numeric, NaN/inf, negative duration, port outside 0-65535) are **not** errors: those rows come back under `rejected`.

## Metrics
`ids_requests_total`, `ids_flows_scored_total`, `ids_flows_rejected_total`, `ids_alerts_total`, `ids_scoring_seconds_total`,
`ids_alert_ratio` (since start), `ids_recent_alert_ratio` (last 10,000 flows), `ids_target_alert_ratio` (design FPR) and `ids_drift`
(1 when the recent alert rate exceeds 3× the target after at least 1,000 flows). **Alert on `ids_drift == 1`**, then run `ids-detect recalibrate`
(DEPLOYMENT.md). The same status is in `GET /v1/model` → `drift`.

Every response carries `X-Request-ID` (echoed if the client sends one). With `IDS_LOG_FORMAT=json` each request is logged as one JSON line.
