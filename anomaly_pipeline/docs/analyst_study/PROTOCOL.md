# Analyst study for RQ3: do the explanations help an analyst?

Facilitator document. Written 2026-10-04, before any participant has seen the material; this is the pre-registration of
the study (referenced from `results_comparison/PREREGISTRATION.md`, E10). Nothing below is changed after data collection.

## Question
RQ3 asks which explanation methods give *meaningful* explanations. The automatic checks (E10) measure whether the
explanations are faithful to the model. This study measures whether they help a person decide what an alert is.

## Participants
3 to 6 people with SOC, incident response or network security experience (Terma analysts first; if they are not available,
the company and academic supervisors and security-literate DTU students, reported as a separate, weaker group).
Participation is voluntary and anonymous (participant IDs P1, P2, ...). Only role and years of experience are recorded.

## Material
`scripts/analyst_study_pack.py build` made 20 alert cards from real alerts of the E9 detector (`ssl_mm_ensemble`) on
CIC-IDS2017: 12 attacks (one per attack type) and 8 false alarms, in random order. Ground truth and the day are removed.
- **Condition A (score only):** verdict, Suricata result, anomaly score, network context (IPs, ports, HTTP, DNS, TLS).
- **Condition B (explained):** A plus the evidence table (SHAP top features in readable units vs normal for the role),
  the behaviour hypothesis, suggested next steps and the explanation confidence.
- Form 1 shows odd alerts in A and even alerts in B; form 2 the reverse. Participants alternate between forms
  (P1 form 1, P2 form 2, ...), so every alert is seen in both conditions and the order is interleaved.
- `facilitator/answer_key.csv` and `facilitator/_build/` contain the labels: never give them to participants.

## Procedure (about 45 minutes)
1. Consent (`CONSENT.md`), 2 minutes of instructions; no information about the datasets or the attack schedule.
2. For each card in order, the participant fills one row of `ANSWER_SHEET.md`: decision, category, confidence, and for
   explained cards the three ratings. The facilitator records the seconds per card (or the participant notes start/end).
   No going back to earlier cards.
3. `QUESTIONNAIRE.md` at the end.
4. The facilitator types the answers into a copy of `RESPONSES_TEMPLATE.csv`.

## Analysis (fixed now)
`python scripts/analyst_study_pack.py score responses.csv`.
- Primary: decision accuracy (attack vs false alarm) in B vs A, per participant, then mean over participants.
- Secondary: category accuracy, confidence, seconds per alert, and in B the clarity / usefulness / trust ratings.
- Test: Wilcoxon signed-rank of the per-participant B - A differences. With 3-6 participants this has little power; the
  result is reported as descriptive evidence, together with the per-participant numbers and the free-text comments.
- Also reported: alerts where the explanation pointed in the wrong direction (e.g. a false alarm explained as "web
  probing") and whether participants were misled by them (accuracy on false alarms in B vs A).
- Every outcome is reported, including "explanations did not help" or "explanations misled".

## Limits to state in the thesis
Small sample; benchmark traffic (CIC-IDS2017), not Terma traffic; participants may know public IDS datasets; the
network context in A already contains strong cues (e.g. external attacker IPs), which makes A a strong baseline.
