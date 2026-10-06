# Representation analysis (X3) and error analysis (X4), CIC-IDS2017 P1

Post hoc and descriptive (`results_comparison/PREREGISTRATION.md`, X3 / X4): both were written after the E7–E10 test results were
known, and neither changes a reported number. Neither needs retraining. They use the saved models and score files of seeds 42, 1 and 2.
Reproduce with `python scripts/representation_analysis.py` and `python scripts/error_analysis.py`. Tables:
`results_comparison/representation/` and `results_comparison/error_analysis/`.

## X3: why does the SSL latent space help, and where does it not?

Sample: 20,000 benign training flows as the reference set and up to 2,000 test flows per label. The test sample is stratified by label,
so its AUCs are not comparable with the pooled E7 numbers; only the comparison between spaces is meaningful. Values are means over the
three seeds (`metrics_summary.csv`).

| space | role purity of the 10 nearest neighbours | kNN distance AUC, global reference | kNN distance AUC, same-role reference | linear probe AUC | effective dimensions (of 32) | seed stability: CKA / 10-NN overlap |
|---|---|---|---|---|---|---|
| input features (70) | 0.940 | 0.799 | 0.844 | **0.988** | 3.9 (of 70) | – |
| `ssl_mm_role` | **0.994** | **0.847** | 0.857 | 0.974 | 3.3 | 0.84 / 0.70 |
| `ssl_no_contrastive` | 0.993 | 0.849 | 0.859 | 0.966 | 3.4 | 0.83 / 0.70 |
| `ssl_mm_global` (no role) | 0.940 | 0.779 | 0.836 | 0.982 | 2.6 | 0.94 / 0.67 |
| `ae_concat` | 0.940 | 0.811 | **0.863** | 0.978 | 3.0 | 0.87 / 0.74 |

What this shows:

1. **The SSL model's advantage comes from the role, not from self-supervision.** The role embedding organises the latent space by
   service role: 99.4% of a flow's nearest neighbours share its role, against 94% in the input. That is why a *global* distance in the
   SSL space separates attacks better (0.847) than a global distance in the input (0.799) or in the AE space (0.811). Once the search
   itself is restricted to the same role, the advantage disappears: AE 0.863, SSL 0.857, input 0.844. This is the mechanism behind
   H5 (supported: role-aware beats global) and H7 (not supported: the AE with the same role-aware kNN scorer is as good).
2. **The contrastive term changes nothing in the representation.** `ssl_mm_role` and `ssl_no_contrastive` agree on every measure to
   within one seed standard deviation, which matches E6.
3. **The information is in the input; the bottleneck is the scoring.** A linear classifier separates attacks from benign flows best on
   the raw input (0.988). Every latent space loses a little (0.966–0.982). Unsupervised scoring by distance to normal traffic recovers
   only 0.84–0.86 of that. Better detection therefore needs a better notion of "far from normal", not more information.
4. **The latent spaces are low-rank.** Only about 3 of the 32 dimensions carry most of the variance (participation ratio 2.6–3.4). The
   global SSL model is the most collapsed (2.6).
5. **Neighbourhoods are only moderately stable across seeds.** The linear CKA is high (0.83–0.94), but only 67–74% of a flow's 10
   nearest neighbours are the same under another seed. A detector whose threshold sits at the edge of a dense attack cluster will
   therefore flip that cluster in or out from seed to seed, which is what E7 observed (see X4, seed flips).
6. **Attack types cluster equally well in every space.** The share of an attack flow's neighbours with the same label is
   0.87–0.88 everywhere (`tsne_latent_spaces.png`). The SSL space keeps the attack-type structure of the input; it neither improves nor
   destroys it.

The per-role table (`per_role.csv`) has only two roles with at least 50 attack and 50 benign flows in this sample. Web is separable
(AUC 0.74–0.78); DNS is not (0.39–0.43). The DNS attack flows there are mostly Infiltration – Portscan flows of the infected host,
which look like that host's normal lookups.

## X4: when and why does the model fail?

Fixed threshold (99th percentile of benign validation scores). `ssl_mm_ensemble` is the single E9 file, which already averages the three
seeds.

### False negatives

Recall per attack type at the fixed threshold (`per_attack.csv`). For the three seeded methods it is the mean over seeds 42, 1 and
2; the "missed by all" columns use seed 42 of each method plus the ensemble and Suricata:

| attack | `ssl_mm_role_knn` | `ssl_mm_ensemble` | `ae_concat_knnrole` | `iforest` | Suricata | missed by all | of those, near-identical to benign training flows |
|---|---|---|---|---|---|---|---|
| DDoS | 0.005 | **0.988** | 0.984 | 0.000 | 0.000 | 1.2% | 0% |
| DoS Hulk | 0.004 | 0.008 | 0.013 | 0.254 | 0.000 | 80.6% | 1.6% |
| DoS GoldenEye | 0.028 | 0.037 | 0.036 | 0.381 | 0.000 | 44.2% | 0.8% |
| DoS Slowloris | 0.191 | 0.573 | 0.574 | 0.001 | 0.000 | 42.6% | **99.7%** |
| DoS Slowhttptest | 0.088 | 0.293 | 0.274 | 0.008 | 0.000 | 67.6% | **98.4%** |
| Portscan | 0.280 | **0.964** | 0.280 | 0.000 | 0.001 | 3.5% | 39.7% |
| Infiltration – Portscan | 0.143 | 0.924 | 0.014 | 0.000 | 0.002 | 7.5% | 56.1% |
| FTP-Patator | 0.333 | **0.998** | 0.662 | 0.000 | 0.487 | 0.1% | 0% |
| SSH-Patator | 0.001 | 0.001 | 0.001 | 0.000 | 0.010 | **98.9%** | 0% |
| Botnet | 0.266 | 0.445 | 0.581 | 0.001 | 0.000 | 55.5% | 1.0% |
| Web Attack – Brute Force | 0.036 | 0.081 | 0.072 | 0.054 | 0.000 | 89.3% | **99.6%** |
| Web Attack – XSS | 0.001 | 0.007 | 0.016 | 0.031 | 0.028 | 96.6% | **98.6%** |
| Web Attack – SQL Injection (12) | 0 | 0 | 0 | 0 | 0.667 | 33.3% | 0% |

(Seed 42 of `ssl_mm_role_knn` alone catches almost nothing; see below.)

Three kinds of failure explain nearly all misses:

1. **Label artefacts (not fixable at flow level).** Almost every miss on Slowloris, Slowhttptest, Web Brute Force and XSS that no
   method catches is a flow that is near-identical to a benign Monday flow (98–100%). These flows sit inside the attack time window,
   but their content is ordinary (X2, L3). No flow-level detector can catch them, so they set a ceiling on recall rather than reveal a
   model weakness.
2. **Ranked above benign traffic, but not into the 1% tail.** SSH-Patator (98.9% missed by everyone) and DoS Hulk (80.6%) are not
   near-duplicates of benign flows, and the SSL model ranks them above most benign flows (per-attack ROC-AUC 0.88–0.90 and 0.94 over
   the three seeds). They still stay below the threshold, because the top 1% of benign scores (long sessions, rare services,
   end-of-capture flows) is more unusual than a single brute-force login or HTTP request. One login attempt looks like Monday's benign
   SSH sessions. Hulk's requests look like ordinary web requests one at a time; its anomaly is the *rate*, which is what the
   temporal-context view was built for on CSE-CIC-IDS2018, but that view is not part of the P1 model.
3. **An operating point at the edge of an attack cluster.** DDoS, Portscan and FTP-Patator are well ranked (per-attack ROC-AUC of
   `ssl_mm_role_knn` 0.958–0.993 over the three seeds), but the `ssl_mm_role_knn` threshold falls just above their scores for seeds 42 and 1 and just below for seed 2
   (`seed_flips.csv`: Portscan recall 0.011 / 0.015 / 0.814, FTP-Patator 0.005 / 0.005 / 0.990). Misses are deep, not marginal:
   the median missed DDoS or Hulk flow sits at about the 80th percentile of benign validation scores (`near_misses.csv`). That is
   why the E9 ensemble, which averages the seeds, catches DDoS, Portscan and FTP-Patator consistently.

Short flows separate the methods (`fn_by_factor.csv`, seed 42). Attack flows with 1–2 packets, mostly scan probes and label-artefact
flows, are missed by `ssl_mm_role_knn`, the AE, iForest and Suricata (99–100%), but the ensemble misses only 4.7% of them. Long flows
(> 100 packets) are caught by the AE and iForest (miss rates 18% and 14%) and by the ensemble (16%), but not by `ssl_mm_role_knn`
seed 42 (99%).

### False positives

- **Most SSL false alarms are flows flushed when the capture ended.** Each pcap ends with Suricata flushing all flows that are still
  open (`flow_reason = shutdown`). These are 3.2% of the benign test flows. `ssl_mm_role_knn` raises an alarm on 4–6% of them but on
  only 0.04–0.1% of other benign flows (seeds 42 and 1), so they account for 77% / 64% of its false alarms
  (`fp_shutdown_flows.csv`). In time this shows up as 78% of its false alarms falling in the last capture hour (19–20 UTC), and in role
  as 88% in the DNS role. The AE (8–20%), iForest (2–3%), Suricata (3.5%) and the ensemble (3.4%) are much less affected. This is a
  capture artefact: a continuously running sensor produces such flows only on restarts. Excluding them would lower the SSL model's
  realised false-positive rate, but they are kept in every reported number.
- **Without the shutdown artefact, the baselines' false alarms sit in the web role** (AE 91%, iForest 99%), on long flows
  (21–100 and > 100 packets), spread evenly over the four test days.
- **A quarter of SSL false alarms (25%) and half of the ensemble's (51%) are identical to a benign training flow.** A distance-based
  score flags them anyway because they are rare in the training sample (the kNN reference is a random subsample of 5,000–10,000
  flows per role): the flow exists in the training data but not in the reference set.

### Complementarity

Taking all five detectors together (`complementarity.csv`), at least one of them catches more than 90% of DDoS, Portscan,
Infiltration – Portscan and FTP-Patator, and 56–57% of Slowloris and GoldenEye. Suricata adds the SQL injections (8 of 12), which no
anomaly detector catches. The hard core that every method misses is SSH-Patator, DoS Hulk and the label-artefact flows of the web and
slow-DoS attacks.

### Implications for the thesis

- The low fixed-threshold recall of `ssl_mm_role_knn` in E7 is a **calibration problem** (the threshold sits at the edge of the main
  attack clusters, and false alarms from end-of-capture flows push it up), not a ranking problem. This supports the E9 move to a
  seed ensemble and tail-probability calibration.
- Remaining headroom lies in rate and aggregate features (Hulk, SSH brute force) and in excluding capture artefacts, not in a bigger
  encoder. That matches X3 and the E11 tuning result.
- 17.9% of the Tue–Fri attack flows are near-identical to benign training flows, which caps every flow-level method's recall at about
  82%. The cap should be reported next to the recall numbers.
