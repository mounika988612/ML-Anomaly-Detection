"""Analyst study for RQ3 (docs/analyst_study/PROTOCOL.md): blinded alert cards and scoring of the answers.

    python scripts/analyst_study_pack.py build              # alert cards (2 counterbalanced forms) + answer key
    python scripts/analyst_study_pack.py score responses.csv

build: 20 alerts of the explained model (default `ssl_mm_ensemble`, the E9 selection) on CIC-IDS2017 P1: one random alert per
attack type (Heartbleed and Infiltration excluded, as in E10) and false alarms to make 20, in random order. Each card is
rendered by analyst_report.build_report and then blinded: the ground-truth line and the day name are removed (the CIC day
schedule would reveal the attack). Condition A (score only) keeps the verdict, the detectors and the network context;
condition B (explained) also keeps the evidence table, the behaviour hypothesis, the next steps and the explanation
confidence. Form 1 shows odd alerts as A and even alerts as B, form 2 the reverse, so every alert is seen in both conditions.
The answer key (docs/analyst_study/facilitator/answer_key.csv) must not be given to participants.
score: joins the filled responses (docs/analyst_study/RESPONSES_TEMPLATE.csv) with the key and reports accuracy, category
accuracy, confidence, time and ratings per condition, per participant and overall (Wilcoxon signed-rank over participants).
"""
import argparse
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from ids_pipeline import explain as X                                                       # noqa: E402
from ids_pipeline.analyst_report import Baseline, build_report, raw_features, raw_roles     # noqa: E402
from ids_pipeline.data import _adapter, load_feature_space, load_split                      # noqa: E402
from ids_pipeline.features import ROLE_NAMES                                                # noqa: E402
from ids_pipeline.utils import get_logger, load_config                                      # noqa: E402
from xai_eval import sample_alerts                                                          # noqa: E402

log = get_logger()
OUT = ROOT / "docs" / "analyst_study"
N_ALERTS = 20
CATEGORY = {
    "DoS Hulk": "flood (DoS/DDoS)", "DoS GoldenEye": "flood (DoS/DDoS)", "DDoS": "flood (DoS/DDoS)",
    "DoS Slowloris": "slow DoS", "DoS Slowhttptest": "slow DoS",
    "FTP-Patator": "password guessing", "SSH-Patator": "password guessing", "Web Attack - Brute Force": "password guessing",
    "Portscan": "scanning / reconnaissance", "Infiltration - Portscan": "scanning / reconnaissance",
    "Web Attack - XSS": "web application attack", "Web Attack - SQL Injection": "web application attack",
    "Botnet": "botnet / command and control", "Benign": "not an attack (false alarm)",
}
EXPLANATION_BLOCKS = ("**Why it looks abnormal**", "**What the traffic shape resembles**", "**Suggested next steps**",
                      "**Explanation confidence:**", "No single property stands out")


def blind(card, condition):
    lines = [ln for ln in card.splitlines() if not ln.startswith("<sub>Evaluation only")]
    lines[0] = re.sub(r"\| (Monday|Tuesday|Wednesday|Thursday|Friday) \|", "|", lines[0])
    if condition == "B":
        return "\n".join(lines).rstrip() + "\n"
    out, drop = [], False
    for ln in lines:
        if ln.startswith("**") or ln.startswith("No single property"):
            drop = ln.startswith(EXPLANATION_BLOCKS)
        if not drop:
            out.append(ln)
    return "\n".join(out).rstrip() + "\n"


def build(args):
    cfg = load_config(args.config)
    e, fs = cfg["explain"], load_feature_space(cfg)
    names, d = fs.names, len(fs.names)
    tr, va = load_split(cfg, "train"), load_split(cfg, "val")
    tests = {day: load_split(cfg, f"test_{day}") for day in cfg["data"]["test_days"]}
    score, _, thr = X._scorer(cfg, args.method, d, tr, va)
    alerts, _ = sample_alerts(cfg, score, thr, tests, 1, N_ALERTS)
    alerts = alerts[alerts.label.isin(CATEGORY)]
    n_att = int((alerts.label != "Benign").sum())
    alerts = pd.concat([alerts[alerts.label != "Benign"], alerts[alerts.label == "Benign"].head(N_ALERTS - n_att)])
    alerts = alerts.sample(frac=1, random_state=7).reset_index(drop=True)
    log.info("study alerts: %s", alerts.label.value_counts().to_dict())

    rs = np.random.RandomState(cfg["data"]["seed"])
    loader = _adapter(cfg)[0]
    base_df = pd.concat([loader(cfg, dd) for dd in cfg["data"]["train_days"]])
    base_df = base_df[base_df.attack == 0]
    base_df = base_df.iloc[np.sort(rs.choice(len(base_df), min(150000, len(base_df)), replace=False))]
    baseline = Baseline(raw_features(cfg, base_df, names), raw_roles(cfg, base_df), names)
    items, days_raw = [], {}
    for _, a in alerts.iterrows():
        t = tests[a.day]
        x, role = t["X"][a.i], int(t["role"][a.i])
        f = (lambda role: (lambda Z: score(np.asarray(Z, np.float32), np.full(len(Z), role, np.int8))))(role)
        bgm = va["role"] == role
        bg = va["X"][bgm] if bgm.sum() >= e["background_size"] else va["X"]
        bg = bg[rs.choice(len(bg), min(e["background_size"], len(bg)), replace=False)]
        phi, _ = X.shap_values(f, x, bg, e, np.random.RandomState(0))
        phi2, _ = X.shap_values(f, x, bg, e, np.random.RandomState(1))
        if a.day not in days_raw:
            days_raw[a.day] = loader(cfg, a.day)
        rdf = days_raw[a.day]
        items.append(dict(raw=raw_features(cfg, rdf.iloc[[a.i]], names)[0], role=ROLE_NAMES[role], score=float(f(x[None])[0]),
                          phi=phi, phi2=phi2, base=baseline.get(role), ts=float(t["ts"][a.i]),
                          dst_port=float(rdf["Dst Port"].iloc[a.i]) if "Dst Port" in rdf else None))
    build_dir = OUT / "facilitator" / "_build"
    build_dir.mkdir(parents=True, exist_ok=True)
    build_report(cfg, args.method, fs, alerts, items, thr, X._provider(cfg), build_dir, "")
    full = (build_dir / "analyst_report.md").read_text(encoding="utf-8")
    cards = re.split(r"(?m)^(?=## Alert \d+:)", full)[1:]
    assert len(cards) == len(alerts), (len(cards), len(alerts))

    intro = ("Each card is one alert raised by the anomaly detector. For every card, answer the questions on your answer "
             "sheet before moving on, and do not go back to earlier cards. Some cards include an explanation of the alert "
             "and some do not; that is intended. Some alerts are real attacks and some are false alarms.\n\n")
    for form in (1, 2):
        md = [f"# Alert review - form {form}\n", intro]
        for n, card in enumerate(cards, 1):
            cond = ("A" if n % 2 else "B") if form == 1 else ("B" if n % 2 else "A")
            md.append(blind(card, cond))
            md.append("---\n")
        (OUT / f"form_{form}_alert_cards.md").write_text("\n".join(md), encoding="utf-8")
    key = pd.DataFrame(dict(alert=np.arange(1, len(alerts) + 1), true_label=alerts.label,
                            is_attack=(alerts.label != "Benign").astype(int), category=alerts.label.map(CATEGORY),
                            condition_form_1=["A" if n % 2 else "B" for n in range(1, len(alerts) + 1)],
                            condition_form_2=["B" if n % 2 else "A" for n in range(1, len(alerts) + 1)],
                            day=alerts.day, row=alerts.i, method=args.method))
    key.to_csv(OUT / "facilitator" / "answer_key.csv", index=False)
    log.info("wrote %s (forms 1 and 2) and facilitator/answer_key.csv", OUT)


def score_responses(args):
    key = pd.read_csv(OUT / "facilitator" / "answer_key.csv")
    r = pd.read_csv(args.responses).merge(key, on="alert")
    r["condition"] = np.where(r.form == 1, r.condition_form_1, r.condition_form_2)
    r["correct"] = (r.decision.str.strip().str.lower().str.startswith("attack")).astype(int) == r.is_attack
    r["category_correct"] = r.category_answer.str.strip().str.lower() == r.category.str.lower()
    cols = ["correct", "category_correct", "confidence", "seconds"]
    print("Per condition (A = score only, B = with explanation):")
    print(r.groupby("condition")[cols].mean().round(3).to_string())
    print("\nDecision accuracy on attacks (1) and false alarms (0), per condition (were participants misled?):")
    print(r.groupby(["is_attack", "condition"]).correct.mean().unstack().round(3).to_string())
    per = r.groupby(["participant", "condition"])[cols].mean().unstack()
    print("\nPer participant:\n" + per.round(3).to_string())
    b = r[r.condition == "B"]
    print("\nRatings of explained alerts (1-5):")
    print(b[["clarity", "usefulness", "trust"]].describe().round(2).to_string())
    if r.participant.nunique() >= 2:
        from scipy.stats import wilcoxon
        for c in cols:
            diff = per[(c, "B")] - per[(c, "A")]
            if diff.abs().sum() > 0:
                print(f"\n{c}: mean B - A {diff.mean():+.3f}; Wilcoxon p = {wilcoxon(diff).pvalue:.3f} (n = {len(diff)} participants)")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--config", default=str(ROOT / "config_cic2017_monday.yaml"))
    b.add_argument("--method", default="ssl_mm_ensemble")
    s = sub.add_parser("score")
    s.add_argument("responses")
    args = ap.parse_args()
    build(args) if args.cmd == "build" else score_responses(args)


if __name__ == "__main__":
    main()
