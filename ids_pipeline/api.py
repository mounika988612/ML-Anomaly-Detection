"""HTTP service (FastAPI). Contract version: /v1. See docs/API.md.

    IDS_BUNDLE_DIR        model bundle directory (required)
    IDS_API_KEYS          comma-separated accepted API keys, sent as `X-API-Key`
    IDS_ALLOW_ANONYMOUS   "1" disables authentication (development only; the service refuses to start without keys otherwise)
    IDS_MAX_BATCH         maximum flows per request (default 5000)
    IDS_MAX_BODY_MB       maximum request body (default 20)
    IDS_RATE_LIMIT_PER_MIN  requests per minute per API key (default 600; 0 disables), answered with 429 + Retry-After
    IDS_COLUMN_MAP        optional JSON file {their_column: canonical_column} for other flow exporters
    IDS_LOG_FORMAT        "json" for one JSON object per log line (default: text)
"""
import hashlib
import hmac
import json
import logging
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Optional, Union

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .bundle import BundleError
from .schema import ROLE_COLUMN, DataError
from .service import Detector

log = logging.getLogger("ids.api")
API_VERSION = "v1"


class FlowIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: Optional[str] = Field(None, max_length=128, description="caller's flow identifier, echoed back in the response")
    role: Optional[str] = Field(None, description="asset role (see GET /v1/model -> roles); overrides the destination-port heuristic")
    features: dict[str, Union[float, int, str, None]] = Field(
        description="CICFlowMeter columns by name (see GET /v1/model -> required_columns); extra columns are ignored")


class ScoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    flows: list[FlowIn] = Field(min_length=1)
    top_k: int = Field(3, ge=0, le=10, description="explain each alert with its top-k features (0 disables)")


class FeatureError(BaseModel):
    feature: str
    error: float = Field(description="squared reconstruction error in standardised units")


class ScoreItem(BaseModel):
    id: Optional[str]
    score: float = Field(description="calibrated anomaly score (robust z-score); higher = more anomalous")
    threshold: float
    alert: bool = Field(description="score > threshold")
    role: str = Field(description="role used for the neighbour search: the flow's supplied role, else derived from the destination port")
    top_features: list[FeatureError]


class Rejected(BaseModel):
    index: int = Field(description="position in the request's flows array")
    id: Optional[str]
    reason: str


class ScoreResponse(BaseModel):
    model: str
    threshold: float
    results: list[ScoreItem]
    rejected: list[Rejected]
    n_alerts: int


class ErrorBody(BaseModel):
    error: str
    detail: Optional[str] = None


class JsonFormatter(logging.Formatter):
    _SKIP = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}

    def format(self, record):
        d = dict(ts=self.formatTime(record, "%Y-%m-%dT%H:%M:%S"), level=record.levelname, logger=record.name, msg=record.getMessage())
        d.update({k: v for k, v in record.__dict__.items() if k not in self._SKIP})
        if record.exc_info:
            d["exc"] = self.formatException(record.exc_info)
        return json.dumps(d, default=str)


def configure_logging():
    """`ids.*` loggers: JSON lines if IDS_LOG_FORMAT=json (for log shippers), plain text otherwise."""
    lg = logging.getLogger("ids")
    if lg.handlers:
        return
    h = logging.StreamHandler()
    h.setFormatter(JsonFormatter() if os.environ.get("IDS_LOG_FORMAT") == "json"
                   else logging.Formatter("%(asctime)s %(levelname)s %(name)s | %(message)s"))
    lg.addHandler(h)
    lg.setLevel(logging.INFO)
    lg.propagate = False


def _keys_from_env():
    return [k.strip() for k in os.environ.get("IDS_API_KEYS", "").split(",") if k.strip()]


class RateLimiter:
    """sliding-window limit of requests per identity (hashed API key, or client address in anonymous mode)."""

    def __init__(self, per_minute, window=60.0):
        self.limit, self.window = per_minute, window
        self._hits, self._lock = defaultdict(deque), threading.Lock()

    def check(self, who):
        """returns 0 if allowed, else seconds until the next request would be allowed."""
        if self.limit <= 0:
            return 0
        now = time.monotonic()
        with self._lock:
            q = self._hits[who]
            while q and now - q[0] >= self.window:
                q.popleft()
            if len(q) >= self.limit:
                return max(1, int(self.window - (now - q[0])) + 1)
            q.append(now)
            return 0


def create_app(bundle_dir=None, api_keys=None, max_batch=None, allow_anonymous=None, rate_limit=None):
    bundle_dir = bundle_dir or os.environ.get("IDS_BUNDLE_DIR")
    keys = _keys_from_env() if api_keys is None else list(api_keys)
    if allow_anonymous is None:
        allow_anonymous = os.environ.get("IDS_ALLOW_ANONYMOUS") == "1"
    max_batch = int(max_batch or os.environ.get("IDS_MAX_BATCH", 5000))
    max_body = int(float(os.environ.get("IDS_MAX_BODY_MB", 20)) * 1024 * 1024)
    limiter = RateLimiter(int(os.environ.get("IDS_RATE_LIMIT_PER_MIN", 600) if rate_limit is None else rate_limit))
    if not keys and not allow_anonymous:
        raise RuntimeError("no API keys configured: set IDS_API_KEYS (or IDS_ALLOW_ANONYMOUS=1 for development)")
    if not bundle_dir:
        raise RuntimeError("no model bundle configured: set IDS_BUNDLE_DIR")

    state = {}

    @asynccontextmanager
    async def lifespan(app):
        configure_logging()
        state["detector"] = Detector(bundle_dir)                  # fail fast on a missing/corrupt bundle
        log.info("model %s loaded, threshold %.3f", state["detector"].manifest["method"], state["detector"].threshold)
        yield
        state.clear()

    app = FastAPI(title="Flow anomaly detection service", version=__version__, lifespan=lifespan,
                  description="Scores network flow records (CICFlowMeter columns) with a self-supervised, role-aware anomaly detector.")
    header = APIKeyHeader(name="X-API-Key", auto_error=False)

    def auth(request: Request, key: Optional[str] = Security(header)):
        if allow_anonymous and not keys:
            who = "anon:" + (request.client.host if request.client else "?")
        elif key and any(hmac.compare_digest(key.encode(), k.encode()) for k in keys):
            who = "key:" + hashlib.sha256(key.encode()).hexdigest()[:12]
        else:
            raise HTTPException(401, "missing or invalid API key")
        wait = limiter.check(who)
        if wait:
            raise HTTPException(429, f"rate limit of {limiter.limit} requests/minute exceeded", headers={"Retry-After": str(wait)})

    def detector() -> Detector:
        d = state.get("detector")
        if d is None:
            raise HTTPException(503, "model not loaded")
        return d

    @app.middleware("http")
    async def limit_body(request: Request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        t0 = time.perf_counter()
        n = request.headers.get("content-length")
        if n and n.isdigit() and int(n) > max_body:
            resp = JSONResponse(ErrorBody(error="payload_too_large", detail=f"body exceeds {max_body} bytes").model_dump(), 413)
        else:
            resp = await call_next(request)
        resp.headers["X-Request-ID"] = rid
        log.info("request", extra=dict(request_id=rid, method=request.method, path=request.url.path, status=resp.status_code,
                                       ms=round((time.perf_counter() - t0) * 1000, 1)))
        return resp

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_, e):
        names = {401: "unauthorized", 404: "not_found", 405: "method_not_allowed", 429: "rate_limited", 503: "unavailable"}
        code = names.get(e.status_code, "http_error")
        return JSONResponse(ErrorBody(error=code, detail=str(e.detail)).model_dump(), e.status_code, headers=getattr(e, "headers", None))

    @app.exception_handler(DataError)
    async def _data_error(_, e):
        return JSONResponse(ErrorBody(error="invalid_input", detail=str(e)).model_dump(), 422)

    @app.exception_handler(BundleError)
    async def _bundle_error(_, e):
        return JSONResponse(ErrorBody(error="model_error", detail=str(e)).model_dump(), 503)

    @app.get("/healthz", tags=["ops"], summary="liveness")
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz", tags=["ops"], summary="readiness (model loaded)")
    def readyz():
        if "detector" not in state:
            return JSONResponse({"status": "not_ready"}, 503)
        return {"status": "ready", "model": state["detector"].manifest["method"]}

    @app.get(f"/{API_VERSION}/model", tags=["model"], dependencies=[Depends(auth)], summary="model metadata and input contract")
    def model_info(d: Detector = Depends(detector)):
        return {**d.info, "api_version": API_VERSION, "max_batch": max_batch}

    @app.post(f"/{API_VERSION}/score", tags=["scoring"], dependencies=[Depends(auth)], response_model=ScoreResponse,
              responses={401: {"model": ErrorBody}, 413: {"model": ErrorBody}, 422: {"model": ErrorBody}},
              summary="score a batch of flows")
    def score(req: ScoreRequest, d: Detector = Depends(detector)):
        if len(req.flows) > max_batch:
            return JSONResponse(ErrorBody(error="batch_too_large", detail=f"at most {max_batch} flows per request").model_dump(), 413)
        records = [{**f.features, **({ROLE_COLUMN: f.role} if f.role else {})} for f in req.flows]
        res = d.score_records(records, req.top_k)
        results = [ScoreItem(id=req.flows[r["index"]].id, score=r["score"], threshold=r["threshold"], alert=r["alert"],
                             role=r["role"], top_features=r["top_features"]) for r in res.rows]
        rejected = [Rejected(index=i, id=req.flows[i].id, reason=why) for i, why in sorted(res.rejected.items())]
        return ScoreResponse(model=d.manifest["method"], threshold=d.threshold, results=results, rejected=rejected,
                             n_alerts=sum(r.alert for r in results))

    @app.get("/metrics", tags=["ops"], dependencies=[Depends(auth)], response_class=PlainTextResponse, summary="Prometheus metrics")
    def metrics(d: Detector = Depends(detector)):
        c = d.counters
        scored = max(c["flows_scored"], 1)
        dr = d.drift()
        lines = [
            ("ids_requests_total", "counter", c["requests"]),
            ("ids_flows_scored_total", "counter", c["flows_scored"]),
            ("ids_flows_rejected_total", "counter", c["flows_rejected"]),
            ("ids_alerts_total", "counter", c["alerts"]),
            ("ids_scoring_seconds_total", "counter", round(c["seconds"], 6)),
            ("ids_alert_ratio", "gauge", c["alerts"] / scored),
            ("ids_target_alert_ratio", "gauge", d.manifest["target_fpr"]),
            ("ids_recent_alert_ratio", "gauge", dr["recent_alert_rate"]),
            ("ids_drift", "gauge", int(dr["status"] == "drifting")),
        ]
        return "".join(f"# TYPE {n} {t}\n{n} {v}\n" for n, t, v in lines)

    return app


def app_factory():
    """uvicorn --factory ids_pipeline.api:app_factory"""
    return create_app()
