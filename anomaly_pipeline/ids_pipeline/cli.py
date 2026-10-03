"""Operations CLI (`ids-detect` / `python -m ids_pipeline`).

    ids-detect export   --config config_multiday.yaml --out models/prod      # trained work dir -> deployable bundle
    ids-detect validate --input flows.csv --bundle models/prod               # check a CSV against the input contract
    ids-detect score    --input flows.csv --bundle models/prod --output scored.csv
    ids-detect recalibrate --benign site_benign.csv --bundle models/prod --out models/site   # fix threshold drift, no retraining
    ids-detect serve    --bundle models/prod --port 8080                     # HTTP API (needs IDS_API_KEYS)

Exit codes: 0 ok, 1 unexpected failure, 2 bad input/config/bundle.
"""
import argparse
import json
import logging
import sys
from pathlib import Path

import pandas as pd

from .bundle import BundleError, export_from_workdir, read_manifest
from .schema import ROLE_COLUMN, DataError, validate_flows
from .service import load_column_map
from .utils import ConfigError, load_config

log = logging.getLogger("ids.cli")


def _read_chunks(path, chunksize, role_column=None):
    if not Path(path).is_file():
        raise DataError(f"input file not found: {path}")
    try:
        for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False):
            chunk.columns = [str(c).strip() for c in chunk.columns]        # CICFlowMeter 2017 files pad names with spaces
            if role_column:
                if role_column not in chunk.columns:
                    raise DataError(f"role column '{role_column}' not in input")
                chunk = chunk.rename(columns={role_column: ROLE_COLUMN})
            yield chunk
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError) as e:
        raise DataError(f"{path}: unreadable CSV: {e}") from e


def cmd_export(a):
    cfg = load_config(a.config)
    m = export_from_workdir(cfg, a.out, a.method)
    print(json.dumps({k: m[k] for k in ("method", "threshold", "target_fpr", "created_utc", "metrics")}, indent=2))
    print(f"bundle written to {a.out}")


def cmd_validate(a):
    m = read_manifest(a.bundle)
    names = m["feature_space"]["names"]
    n = bad = 0
    reasons = {}
    cmap = load_column_map(a.column_map)
    for chunk in _read_chunks(a.input, a.chunksize, a.role_column):
        _, rejected = validate_flows(chunk, names, cmap)
        n, bad = n + len(chunk), bad + len(rejected)
        for r in rejected.values():
            reasons[r] = reasons.get(r, 0) + 1
    print(f"{n} rows, {bad} invalid ({bad / max(n, 1):.2%})")
    for r, c in sorted(reasons.items(), key=lambda kv: -kv[1])[:10]:
        print(f"  {c:>8}  {r}")
    return 0 if bad == 0 else 2


def cmd_score(a):
    from .service import Detector
    det = Detector(a.bundle, load_column_map(a.column_map))
    out, rej_path = Path(a.output), Path(a.output).with_suffix(".rejected.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    offset = n_ok = n_rej = n_alert = 0
    first_out = first_rej = True
    for chunk in _read_chunks(a.input, a.chunksize, a.role_column):
        res = det.score_frame(chunk, top_k=a.top_k)
        rows = pd.DataFrame(res.rows)
        if len(rows):
            rows["row"] = rows.pop("index") + offset
            rows["top_features"] = rows["top_features"].map(lambda t: ";".join(f"{x['feature']}={x['error']}" for x in t))
            rows[["row", "score", "threshold", "alert", "role", "top_features"]].to_csv(
                out, mode="w" if first_out else "a", header=first_out, index=False)
            first_out, n_ok, n_alert = False, n_ok + len(rows), n_alert + int(rows["alert"].sum())
        if res.rejected:
            pd.DataFrame([dict(row=i + offset, reason=r) for i, r in sorted(res.rejected.items())]).to_csv(
                rej_path, mode="w" if first_rej else "a", header=first_rej, index=False)
            first_rej, n_rej = False, n_rej + len(res.rejected)
        offset += len(chunk)
    print(f"scored {n_ok} flows, {n_alert} alerts (threshold {det.threshold:.3f}), {n_rej} rejected -> {out}"
          + (f" (rejected rows: {rej_path})" if n_rej else ""))


def cmd_recalibrate(a):
    from .service import recalibrate_bundle
    m = recalibrate_bundle(a.bundle, a.out, _read_chunks(a.benign, a.chunksize, a.role_column), a.target_fpr, load_column_map(a.column_map))
    r = m["recalibrated"]
    print(f"recalibrated on {r['n_flows']} benign flows ({r['rejected_rows']} rejected): "
          f"threshold {r['previous_threshold']:.3f} -> {m['threshold']:.3f}, target FPR {m['target_fpr']} -> {a.out}")


def cmd_serve(a):
    import os

    import uvicorn
    if bool(a.ssl_certfile) != bool(a.ssl_keyfile):
        raise ConfigError("--ssl-certfile and --ssl-keyfile must be given together")
    os.environ["IDS_BUNDLE_DIR"] = str(a.bundle)
    if a.column_map:
        os.environ["IDS_COLUMN_MAP"] = str(a.column_map)
    uvicorn.run("ids_pipeline.api:app_factory", factory=True, host=a.host, port=a.port, workers=a.workers,
                log_level=a.log_level, proxy_headers=True, ssl_certfile=a.ssl_certfile, ssl_keyfile=a.ssl_keyfile)


def _input_opts(s):
    s.add_argument("--column-map", help="JSON file {their_column: canonical_column} for other flow exporters")
    s.add_argument("--role-column", help="CSV column with the asset role (web, remote_admin, ...) instead of the port heuristic")


def build_parser():
    p = argparse.ArgumentParser(prog="ids-detect", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("export", help="build a deployable bundle from a finished training run")
    s.add_argument("--config", default=None)
    s.add_argument("--out", required=True)
    s.add_argument("--method", default="ssl_mm_role_knn")
    s.set_defaults(fn=cmd_export)
    s = sub.add_parser("validate", help="check a CSV against the bundle's input contract")
    s.add_argument("--input", required=True)
    s.add_argument("--bundle", required=True)
    s.add_argument("--chunksize", type=int, default=200_000)
    _input_opts(s)
    s.set_defaults(fn=cmd_validate)
    s = sub.add_parser("score", help="score a CSV of flows")
    s.add_argument("--input", required=True)
    s.add_argument("--bundle", required=True)
    s.add_argument("--output", required=True)
    s.add_argument("--top-k", type=int, default=3)
    s.add_argument("--chunksize", type=int, default=100_000)
    _input_opts(s)
    s.set_defaults(fn=cmd_score)
    s = sub.add_parser("recalibrate", help="refit calibration and alert threshold on benign flows of the deployment network")
    s.add_argument("--benign", required=True, help="CSV of benign flows (you vouch that it contains no attacks)")
    s.add_argument("--bundle", required=True)
    s.add_argument("--out", required=True, help="new bundle directory (the old one stays for rollback)")
    s.add_argument("--target-fpr", type=float, default=None, help="default: the bundle's current target")
    s.add_argument("--chunksize", type=int, default=200_000)
    _input_opts(s)
    s.set_defaults(fn=cmd_recalibrate)
    s = sub.add_parser("serve", help="run the HTTP API")
    s.add_argument("--bundle", required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--workers", type=int, default=1)
    s.add_argument("--log-level", default="info")
    s.add_argument("--ssl-certfile")
    s.add_argument("--ssl-keyfile")
    s.add_argument("--column-map", help="JSON file {their_column: canonical_column}")
    s.set_defaults(fn=cmd_serve)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s | %(message)s")
    try:
        return args.fn(args) or 0
    except (ConfigError, DataError, BundleError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Exception:
        log.exception("unexpected failure")
        return 1


if __name__ == "__main__":
    sys.exit(main())
