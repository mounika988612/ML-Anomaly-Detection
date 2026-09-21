"""Load test for a running scoring service (stdlib only).

    python scripts/loadtest.py --url http://localhost:8080 --key KEY --csv flows.csv --batch 200 --clients 4 --seconds 30

Sends /v1/score requests built from real rows of a CICFlowMeter CSV from `--clients` parallel threads and reports throughput
and latency percentiles. Point it at a service started with IDS_RATE_LIMIT_PER_MIN=0, otherwise you measure the limiter.
"""
import argparse
import csv
import json
import statistics
import threading
import time
import urllib.error
import urllib.request


def load_rows(path, n):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            r = {k.strip(): v for k, v in r.items() if k.strip() not in ("Timestamp", "Label")}
            if all(v not in ("", None) for v in r.values()):
                rows.append({"features": r})
            if len(rows) >= n:
                break
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8080")
    ap.add_argument("--key", required=True)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--batch", type=int, default=200)
    ap.add_argument("--clients", type=int, default=4)
    ap.add_argument("--seconds", type=float, default=30)
    a = ap.parse_args()
    body = json.dumps({"flows": load_rows(a.csv, a.batch), "top_k": 0}).encode()
    hdr = {"X-API-Key": a.key, "Content-Type": "application/json"}
    lat, errors, lock = [], {}, threading.Lock()
    stop = time.monotonic() + a.seconds

    def worker():
        while time.monotonic() < stop:
            t0 = time.perf_counter()
            try:
                with urllib.request.urlopen(urllib.request.Request(a.url + "/v1/score", body, hdr), timeout=60) as r:
                    r.read()
                    code = r.status
            except urllib.error.HTTPError as e:
                code = e.code
            except Exception as e:                       # connection reset, timeout, ...
                code = type(e).__name__
            dt = time.perf_counter() - t0
            with lock:
                if code == 200:
                    lat.append(dt)
                else:
                    errors[code] = errors.get(code, 0) + 1

    ts = [threading.Thread(target=worker) for _ in range(a.clients)]
    t0 = time.perf_counter()
    [t.start() for t in ts]
    [t.join() for t in ts]
    wall = time.perf_counter() - t0
    n = len(lat)
    print(f"clients={a.clients} batch={a.batch} duration={wall:.1f}s")
    if n:
        q = statistics.quantiles(lat, n=100) if n >= 2 else [lat[0]] * 99
        print(f"requests ok={n} errors={errors or 0}  {n / wall:.1f} req/s  {n * a.batch / wall:,.0f} flows/s")
        print(f"latency ms  p50={q[49] * 1e3:.0f}  p95={q[94] * 1e3:.0f}  p99={q[98] * 1e3:.0f}  max={max(lat) * 1e3:.0f}")
    else:
        print(f"no successful requests, errors={errors}")
    raise SystemExit(0 if n and not errors else 1)


if __name__ == "__main__":
    main()
