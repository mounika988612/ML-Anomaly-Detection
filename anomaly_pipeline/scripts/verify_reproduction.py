"""Snapshot and verification for `make reproduce-final` (scripts/reproduce_final.sh).

    python scripts/verify_reproduction.py snapshot <run-dir> <step>     # copy the files <step> will regenerate into <run-dir>/before/
    python scripts/verify_reproduction.py verify <run-dir>              # compare regenerated files with the snapshot

CSV files are compared numerically (absolute difference <= 1e-6; text columns must be equal); columns that measure wall-clock time
are ignored. NPZ files are compared array by array; Markdown files byte by byte. Figures (PNG) are regenerated but not compared,
because their bytes carry rendering metadata. Writes <run-dir>/verification.csv and exits 1 if any compared file differs.
"""
import shutil
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
TIMING_COLUMNS = {"seconds", "lat_ms_per_1k", "latency_ms_per_1k_flows", "train_s", "sec_attr"}
TOL = 1e-6

# files each step of reproduce_final.sh regenerates (globs relative to anomaly_pipeline/)
OUTPUTS = {
    "eda": ["../dataset/EDA/*/*.csv"],
    "e7": ["results_cic2017_monday/clean_eval_*__e7.csv", "results_suricata2017_rebuilt/clean_eval_*__e7.csv",
           "results_comparison/E7_5day_tables.md", "results_comparison/table_E7_5day_*.csv"],
    "e9": ["results_comparison/E9_dev.csv", "results_comparison/E9_test.csv"],
    "e10": ["results_cic2017_monday/xai_eval/*.csv", "results_cic2017_monday/xai_eval/*.npz"],
    "crossdata": ["results_multiday_context_clean/clean_eval_fixed.csv", "results_multiday_context_clean/clean_eval_adapted.csv"],
    "x2": ["results_comparison/leakage_audit/*.csv"],
    "e11": ["results_e11_*/clean_eval_fixed_e11.csv", "results_multiday_context_clean/clean_eval_fixed_e11default.csv"],
    "e12": ["results_comparison/E12/*.csv"],
    "e13": ["results_comparison/E13/*.csv"],
    "x3": ["results_comparison/representation/*.csv"],
    "x4": ["results_comparison/error_analysis/*.csv"],
}


def files_of(step):
    out = []
    for g in OUTPUTS[step]:
        base = ROOT
        while g.startswith("../"):
            base, g = base.parent, g[3:]
        out += sorted(base.glob(g))
    return out


def key(p):
    """stable name of a file inside the snapshot (relative to the repository root)."""
    return p.resolve().relative_to(ROOT.parent).as_posix()


def snapshot(run, step):
    before = run / "before"
    listed = run / f"{step}.files"
    saved = listed.read_text(encoding="utf-8").split("\n") if listed.exists() else []
    for f in files_of(step):
        dst = before / key(f)
        if dst.exists():               # never replace an earlier snapshot (retrain_final.sh snapshots before retraining)
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, dst)
        saved.append(key(f))
    saved = [k for k in dict.fromkeys(saved) if k]
    listed.write_text("\n".join(saved), encoding="utf-8")
    n = len(saved)
    with open(run / "steps.txt", "a", encoding="utf-8") as fh:
        fh.write(f"{step}\n")
    print(f"[snapshot] {step}: {n} files saved")


def compare_csv(a, b):
    x, y = pd.read_csv(a), pd.read_csv(b)
    if list(x.columns) != list(y.columns) or len(x) != len(y):
        return False, f"shape/columns differ {x.shape} vs {y.shape}"
    worst = 0.0
    for c in x.columns:
        if c in TIMING_COLUMNS:
            continue
        xa, ya = (pd.to_numeric(s, errors="coerce").astype(float) for s in (x[c], y[c]))   # float: bool columns cannot be subtracted
        if xa.notna().any() or ya.notna().any():
            both_nan = xa.isna() & ya.isna()
            if ((xa.isna() != ya.isna()) & ~both_nan).any():
                return False, f"column {c}: missing values differ"
            d = (xa - ya).abs()[~both_nan]
            worst = max(worst, float(d.max()) if len(d) else 0.0)
            if (d > TOL).any():
                return False, f"column {c}: max |diff| {float(d.max()):.3g}"
        elif not (x[c].fillna("").astype(str) == y[c].fillna("").astype(str)).all():   # pandas str dtype keeps NaN, and NaN != NaN
            return False, f"column {c}: text differs"
    return True, f"max |diff| {worst:.1g}"


def compare_npz(a, b):
    x, y = np.load(a, allow_pickle=True), np.load(b, allow_pickle=True)   # score files hold object arrays (labels); both are our own outputs
    if sorted(x.files) != sorted(y.files):
        return False, "different arrays"
    for k in x.files:
        u, v = x[k], y[k]
        if u.shape != v.shape:
            return False, f"{k}: shape differs"
        if np.issubdtype(u.dtype, np.number):
            if not np.allclose(u, v, atol=TOL, rtol=0, equal_nan=True):
                return False, f"{k}: max |diff| {float(np.nanmax(np.abs(u.astype(float) - v.astype(float)))):.3g}"
        elif not np.array_equal(u, v):
            return False, f"{k}: differs"
    return True, "arrays equal"


def verify(run):
    before = run / "before"
    steps = (run / "steps.txt").read_text(encoding="utf-8").split()
    rows = []
    for step in dict.fromkeys(steps):
        new = {key(f): f for f in files_of(step)}
        old = {k: before / k for k in new if (before / k).is_file()}
        for k, f in new.items():
            if k not in old:
                rows.append(dict(step=step, file=k, status="NEW", detail="no earlier version to compare"))
                continue
            if f.suffix == ".csv":
                ok, detail = compare_csv(old[k], f)
            elif f.suffix == ".npz":
                ok, detail = compare_npz(old[k], f)
            else:
                ok = old[k].read_bytes() == f.read_bytes()
                detail = "identical" if ok else "text differs"
            rows.append(dict(step=step, file=k, status="SAME" if ok else "DIFFERENT", detail=detail))
        listed = run / f"{step}.files"
        for k in (listed.read_text(encoding="utf-8").split("\n") if listed.exists() else []):
            if k and k not in new:
                rows.append(dict(step=step, file=k, status="MISSING", detail="existed before, not regenerated"))
    t = pd.DataFrame(rows)
    t.to_csv(run / "verification.csv", index=False)
    pd.set_option("display.width", 250)
    pd.set_option("display.max_colwidth", 90)
    print(t.to_string(index=False))
    count = (lambda s: int((t.status == s).sum())) if len(t) else (lambda s: 0)
    print(f"\n{len(t)} files checked: {count('SAME')} same, {count('DIFFERENT')} different, {count('MISSING')} missing, "
          f"{count('NEW')} new.  Report: {run / 'verification.csv'}")
    return 1 if count("DIFFERENT") or count("MISSING") else 0


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("snapshot", "verify"):
        sys.exit(__doc__)
    run = Path(sys.argv[2])
    run.mkdir(parents=True, exist_ok=True)
    if sys.argv[1] == "snapshot":
        snapshot(run, sys.argv[3])
    else:
        sys.exit(verify(run))


if __name__ == "__main__":
    main()
