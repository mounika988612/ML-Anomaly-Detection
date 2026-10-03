# Label audit: CSE-CIC-IDS2018 (reproduce with `python scripts/label_audit.py`)

The audit uses raw labels, timestamps and flow attributes only. It never uses model scores, so its conclusions do not depend on
any detector. Output: `results_comparison/label_audit_windows.csv` and `results_comparison/label_audit_identical_to_benign.csv`.

## 1. Wed-21: HOIC reverse-direction flows labelled Benign

| Benign-labelled flows | Wed-21, inside the HOIC window (22.4 min) | Wed-21, rest of the day | inside every other attack window (all days) |
|---|---|---|---|
| count | 358,623 | ~2,200 | |
| per minute | 16,046 | 6.5 | 0.6-1.7x the rate outside that window |
| share that is the single most common flow shape (fwd/bwd packets, fwd bytes) | 100% (5 / 2 / 935 B) | | 14-21% |
| share to an ephemeral destination port (>= 49152) | 100% | | 12-14% |

These flows are the HOIC HTTP connections recorded server-to-client: the destination port is the attacker's ephemeral source port.
The labelling matched only the client-to-server direction. No other attack window shows the pattern: the benign rate ratio
inside/outside the window is between 0.6 and 1.7 for every other attack, on every day, training days included.

Effect on the experiments before the fix:
- **2-day protocol.** 99.4% of Wed-21's "benign" test flows were HOIC. Wed-21's per-day FPR and the pooled FPR/MCC measured mostly
  whether a detector flagged HOIC twice. The per-day recalibration window (first 30 min) held 155 flows.
- **3-day protocol.** Wed-21 is a training day. Validation = the latest 15% of each training day's benign flows, which on Wed-21 falls
  entirely inside the HOIC window. HOIC flows were therefore in the benign training data and set part of the alert threshold.

Fix (`data.label_exclusions` in `config_context_clean.yaml` and `config_multiday_context_clean.yaml`; `data.drop_label_errors`): the 358,623 flows
are removed from training, validation and evaluation. They stay in the traffic the context features are computed on, as a sensor would see them.
They are not relabelled as attacks, so no detector gets credit for them. Earlier configs and results are unchanged, for comparison.

## 2. Separability ceiling: attack flows identical to benign flows

| day | attack | flows | identical to a benign flow of the same day | identical to a benign training flow |
|---|---|---|---|---|
| Thu-01 | Infilteration | 92,380 | 17.6% | 15.0% |
| all other test attacks | | | 0% | 0% |

Every CICFlowMeter feature the models use is equal (after rounding to 4 decimals) for these flows and a benign flow. Timestamp,
label and context features are excluded. No flow-level detector can rank them above their benign twins, so at least 17.6% of
Infiltration is undetectable without context outside the flow record. This bounds achievable Infiltration recall at any FPR, and it
agrees with the known problem that Infiltration flows were labelled by host (all traffic of the compromised machine), not by
activity. Exact identity is a strict test; near-identical flows raise the true ceiling further.
