import json

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from ids_pipeline.api import create_app
from ids_pipeline.cli import main as cli_main

KEY = {"X-API-Key": "s3cret"}


def flow(df, i, fid=None):
    row = {k: (None if pd.isna(v) else float(v)) for k, v in df.iloc[i].items()}
    return {"id": fid or f"f{i}", "features": row}


@pytest.fixture(scope="module")
def client(bundle_dir):
    with TestClient(create_app(bundle_dir, api_keys=["s3cret", "other"], max_batch=50)) as c:
        yield c


def test_health_is_open_and_ready(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json()["status"] == "ready"


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "wrong"}])
def test_auth_required(client, headers):
    assert client.get("/v1/model", headers=headers).status_code == 401
    assert client.post("/v1/score", json={"flows": []}, headers=headers).status_code == 401
    assert client.get("/metrics", headers=headers).status_code == 401


def test_model_contract(client):
    r = client.get("/v1/model", headers=KEY).json()
    assert r["api_version"] == "v1" and "Dst Port" in r["required_columns"] and r["max_batch"] == 50


def test_score_roundtrip(client, benign, attacks, detector):
    scores = [r["score"] for r in detector.score_frame(attacks, top_k=0).rows]
    worst = int(max(range(len(scores)), key=scores.__getitem__))
    quiet = int(min(range(3200, 4000), key=lambda i: detector.score_frame(benign.iloc[[i]], top_k=0).rows[0]["score"]))
    body = {"flows": [flow(benign, quiet, "ben"), flow(attacks, worst, "att")], "top_k": 2}
    r = client.post("/v1/score", json=body, headers=KEY)
    assert r.status_code == 200
    out = r.json()
    by_id = {x["id"]: x for x in out["results"]}
    assert not by_id["ben"]["alert"] and by_id["att"]["alert"]
    assert len(by_id["att"]["top_features"]) == 2 and out["n_alerts"] == 1 and out["rejected"] == []


def test_bad_flow_is_reported_not_fatal(client, benign):
    bad = flow(benign, 0, "bad")
    bad["features"]["Flow Duration"] = "not-a-number"
    r = client.post("/v1/score", json={"flows": [bad, flow(benign, 1, "ok")]}, headers=KEY).json()
    assert [x["id"] for x in r["results"]] == ["ok"]
    assert r["rejected"] == [{"index": 0, "id": "bad", "reason": "non-numeric, missing or infinite value in 'Flow Duration'"}]


def test_missing_column_is_422(client, benign):
    f = flow(benign, 0)
    del f["features"]["Flow Duration"]
    r = client.post("/v1/score", json={"flows": [f]}, headers=KEY)
    assert r.status_code == 422 and r.json()["error"] == "invalid_input" and "Flow Duration" in r.json()["detail"]


@pytest.mark.parametrize("body", [{}, {"flows": []}, {"flows": [{"features": {}, "bogus": 1}]}, {"flows": [{"features": {}}], "top_k": 99}])
def test_malformed_requests_are_422(client, body):
    assert client.post("/v1/score", json=body, headers=KEY).status_code == 422


def test_batch_limit(client, benign):
    r = client.post("/v1/score", json={"flows": [flow(benign, i) for i in range(51)]}, headers=KEY)
    assert r.status_code == 413 and r.json()["error"] == "batch_too_large"


def test_metrics(client):
    text = client.get("/metrics", headers=KEY).text
    assert "ids_flows_scored_total" in text and "ids_alert_ratio" in text


def test_openapi_exposes_contract(client):
    spec = client.get("/openapi.json").json()
    assert "/v1/score" in spec["paths"] and "ScoreResponse" in spec["components"]["schemas"]


def test_refuses_to_start_unsafely(bundle_dir, monkeypatch):
    monkeypatch.delenv("IDS_API_KEYS", raising=False)
    monkeypatch.delenv("IDS_ALLOW_ANONYMOUS", raising=False)
    with pytest.raises(RuntimeError, match="API keys"):
        create_app(bundle_dir)
    with pytest.raises(RuntimeError, match="bundle"):
        create_app(None, api_keys=["k"])


def test_anonymous_mode_is_explicit(bundle_dir):
    with TestClient(create_app(bundle_dir, allow_anonymous=True)) as c:
        assert c.get("/v1/model").status_code == 200


def test_bad_bundle_fails_at_startup(tmp_path):
    with pytest.raises(Exception, match="manifest"):
        with TestClient(create_app(tmp_path, api_keys=["k"])):
            pass


# ---------------------------------------------------------------- CLI

def test_cli_score_and_rejects(bundle_dir, benign, tmp_path, capsys):
    df = benign.head(30).copy()
    df.loc[4, "Tot Fwd Pkts"] = float("nan")
    df.columns = [f" {c}" if i % 2 else c for i, c in enumerate(df.columns)]      # padded names as in CIC-IDS2017 files
    src, out = tmp_path / "in.csv", tmp_path / "out" / "scored.csv"
    df.to_csv(src, index=False)
    assert cli_main(["score", "--input", str(src), "--bundle", str(bundle_dir), "--output", str(out), "--chunksize", "10"]) == 0
    scored = pd.read_csv(out)
    assert len(scored) == 29 and 4 not in set(scored["row"]) and scored["row"].is_monotonic_increasing
    assert pd.read_csv(out.with_suffix(".rejected.csv")).to_dict("records") == [
        {"row": 4, "reason": "non-numeric, missing or infinite value in 'Tot Fwd Pkts'"}]


def test_cli_validate_exit_codes(bundle_dir, benign, tmp_path):
    good, bad = tmp_path / "g.csv", tmp_path / "b.csv"
    benign.head(20).to_csv(good, index=False)
    benign.head(20).assign(**{"Dst Port": -5}).to_csv(bad, index=False)
    assert cli_main(["validate", "--input", str(good), "--bundle", str(bundle_dir)]) == 0
    assert cli_main(["validate", "--input", str(bad), "--bundle", str(bundle_dir)]) == 2


def test_cli_errors_are_exit_2_not_tracebacks(bundle_dir, tmp_path, capsys):
    assert cli_main(["score", "--input", str(tmp_path / "x.csv"), "--bundle", str(bundle_dir), "--output", str(tmp_path / "o.csv")]) == 2
    assert "not found" in capsys.readouterr().err
    assert cli_main(["score", "--input", "x", "--bundle", str(tmp_path), "--output", "o"]) == 2
    assert cli_main(["export", "--config", str(tmp_path / "missing.yaml"), "--out", str(tmp_path / "b")]) == 2


def test_cli_score_missing_column(bundle_dir, benign, tmp_path, capsys):
    src = tmp_path / "in.csv"
    benign.head(5).drop(columns=["Flow Duration"]).to_csv(src, index=False)
    assert cli_main(["score", "--input", str(src), "--bundle", str(bundle_dir), "--output", str(tmp_path / "o.csv")]) == 2
    assert "Flow Duration" in capsys.readouterr().err


def test_manifest_is_json_serialisable(bundle_dir):
    json.loads((bundle_dir / "manifest.json").read_text())


def test_api_role_drift_and_request_id(client, benign):
    f = flow(benign, 0, "r")
    f["role"] = "database"
    good = client.post("/v1/score", json={"flows": [f]}, headers={**KEY, "X-Request-ID": "abc123"})
    assert good.status_code == 200 and good.json()["results"][0]["role"] == "database" and good.headers["X-Request-ID"] == "abc123"
    f["role"] = "bogus"
    bad = client.post("/v1/score", json={"flows": [f]}, headers=KEY).json()
    assert bad["results"] == [] and "unknown role" in bad["rejected"][0]["reason"]
    assert client.get("/healthz").headers["X-Request-ID"]
    assert client.get("/v1/model", headers=KEY).json()["drift"]["status"] in {"ok", "drifting", "insufficient_data"}
    assert "ids_drift" in client.get("/metrics", headers=KEY).text


def test_json_log_formatter():
    import logging

    from ids_pipeline.api import JsonFormatter
    rec = logging.LogRecord("ids.api", logging.INFO, "f", 1, "request", None, None)
    rec.status = 200
    out = json.loads(JsonFormatter().format(rec))
    assert out["msg"] == "request" and out["status"] == 200 and out["level"] == "INFO"
