# Analyst alert report (ssl_mm_role)

How to read this: each alert shows (1) whether the signature IDS and the anomaly model agree, (2) the traffic properties that made it look abnormal compared with normal traffic of the same service role, (3) a hypothesis of what the behaviour resembles, and (4) what to check next. "Stable evidence" = the feature is in the top-10 of two independent explanation runs; unstable evidence should be treated with caution. Hypotheses are patterns, not diagnoses.

Signature source: none available for this dataset

## Alert 1: LOW priority | test | service role: other_system | anomaly score 1.2x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.2x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| ct_dst_sport_ltm | 8.00 | 1.00 (up to 2.00) | above normal | yes |
| uses a non-TCP/UDP protocol | yes | no (up to yes) | normal alone, unusual in combination | yes |
| client IP TTL | 254 | 31.00 (up to 254) | normal alone, unusual in combination | yes |
| is_sm_ips_ports | 0.00 | 0.00 (up to 1.00) | normal alone, unusual in combination | yes |
| ct_dst_src_ltm | 8.00 | 3.00 (up to 13.00) | normal alone, unusual in combination | no |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (4 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Analysis</sub>

## Alert 2: LOW priority | test | service role: other_system | anomaly score 1.1x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.1x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| uses a non-TCP/UDP protocol | yes | no (up to yes) | normal alone, unusual in combination | yes |
| client data rate (bit/s) | 800,000,000 /s | 336,499 /s (up to 119,999,992 /s) | far above normal | yes |
| smean | 100 | 64.00 (up to 532) | normal alone, unusual in combination | no |
| server data rate (bit/s) | 0 /s | 130,980 /s (up to 14,193,318 /s) | normal alone, unusual in combination | no |
| state_INT | 1.00 | 0.00 (up to 1.00) | normal alone, unusual in combination | no |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** medium (2 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Analysis</sub>

## Alert 3: LOW priority | test | service role: other_system | anomaly score 1.2x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.2x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| ct_state_ttl | 3.00 | 0.00 (up to 3.00) | normal alone, unusual in combination | yes |
| client IP TTL | 254 | 31.00 (up to 254) | normal alone, unusual in combination | yes |
| bytes sent by the client | 76 B | 1.5 KB (up to 7.8 KB) | normal alone, unusual in combination | yes |
| state_CON | 1.00 | 0.00 (up to 1.00) | normal alone, unusual in combination | yes |
| ct_srv_dst | 1.00 | 6.00 (up to 16.00) | below normal | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Backdoor</sub>

## Alert 4: LOW priority | test | service role: other_system | anomaly score 1.1x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.1x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| uses a non-TCP/UDP protocol | yes | no (up to yes) | normal alone, unusual in combination | yes |
| ct_dst_sport_ltm | 6.00 | 1.00 (up to 2.00) | above normal | yes |
| client data rate (bit/s) | 72,727,272 /s | 336,499 /s (up to 119,999,992 /s) | normal alone, unusual in combination | no |
| state_FIN | 0.00 | 1.00 (up to 1.00) | normal alone, unusual in combination | no |
| swin | 0.00 | 255 (up to 255) | normal alone, unusual in combination | no |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** medium (2 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Backdoor</sub>

## Alert 5: LOW priority | test | service role: other_system | anomaly score 1.0x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.0x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| uses a non-TCP/UDP protocol | yes | no (up to yes) | normal alone, unusual in combination | yes |
| client data rate (bit/s) | 88,888,888 /s | 336,499 /s (up to 119,999,992 /s) | normal alone, unusual in combination | no |
| swin | 0.00 | 255 (up to 255) | normal alone, unusual in combination | no |
| connections to this destination (last 100) | 1 | 3 (up to 9) | normal alone, unusual in combination | no |
| packets sent by the client | 2 | 16 (up to 122) | normal alone, unusual in combination | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** medium (2 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = DoS</sub>

## Alert 6: LOW priority | test | service role: other_system | anomaly score 1.2x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.2x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| uses a non-TCP/UDP protocol | yes | no (up to yes) | normal alone, unusual in combination | yes |
| client IP TTL | 254 | 31.00 (up to 254) | normal alone, unusual in combination | yes |
| flow duration | 7.9 s | 41 ms (up to 3.1 s) | far above normal | yes |
| state_INT | 1.00 | 0.00 (up to 1.00) | normal alone, unusual in combination | no |
| uses TCP | no | yes (up to yes) | normal alone, unusual in combination | no |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (3 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = DoS</sub>

## Alert 7: LOW priority | test | service role: other_system | anomaly score 1.1x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.1x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| uses a non-TCP/UDP protocol | yes | no (up to yes) | normal alone, unusual in combination | yes |
| ct_srv_dst | 1.00 | 6.00 (up to 16.00) | below normal | yes |
| connections from this client to this service (last 100) | 1 | 6 (up to 17) | below normal | yes |
| client data rate (bit/s) | 1,034,666,624 /s | 336,499 /s (up to 119,999,992 /s) | far above normal | yes |
| state_FIN | 0.00 | 1.00 (up to 1.00) | normal alone, unusual in combination | no |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (4 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Exploits</sub>

## Alert 8: LOW priority | test | service role: other_system | anomaly score 1.0x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.0x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| uses a non-TCP/UDP protocol | yes | no (up to yes) | normal alone, unusual in combination | yes |
| client data rate (bit/s) | 266,666,656 /s | 336,499 /s (up to 119,999,992 /s) | far above normal | yes |
| connections from this client to this service (last 100) | 3 | 6 (up to 17) | normal alone, unusual in combination | yes |
| connections from this client (last 100) | 19 | 3 (up to 11) | above normal | yes |
| dmean | 0.00 | 91.00 (up to 879) | normal alone, unusual in combination | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Exploits</sub>

## Alert 9: LOW priority | test | service role: other_system | anomaly score 1.0x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.0x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| uses a non-TCP/UDP protocol | yes | no (up to yes) | normal alone, unusual in combination | yes |
| ct_dst_sport_ltm | 5.00 | 1.00 (up to 2.00) | above normal | yes |
| client data rate (bit/s) | 72,727,272 /s | 336,499 /s (up to 119,999,992 /s) | normal alone, unusual in combination | yes |
| state_FIN | 0.00 | 1.00 (up to 1.00) | normal alone, unusual in combination | yes |
| client IP TTL | 254 | 31.00 (up to 254) | normal alone, unusual in combination | no |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (4 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Fuzzers</sub>

## Alert 10: LOW priority | test | service role: other_system | anomaly score 1.1x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.1x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| uses a non-TCP/UDP protocol | yes | no (up to yes) | normal alone, unusual in combination | yes |
| ct_dst_sport_ltm | 6.00 | 1.00 (up to 2.00) | above normal | yes |
| client data rate (bit/s) | 800,000,000 /s | 336,499 /s (up to 119,999,992 /s) | far above normal | yes |
| state_FIN | 0.00 | 1.00 (up to 1.00) | normal alone, unusual in combination | no |
| swin | 0.00 | 255 (up to 255) | normal alone, unusual in combination | no |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (3 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Fuzzers</sub>

## Alert 11: LOW priority | test | service role: other_system | anomaly score 1.7x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.7x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| svc_other | 1.00 | 0.00 (up to 0.00) | far above normal | yes |
| flow duration | 40.7 s | 41 ms (up to 3.1 s) | far above normal | yes |
| svc_none | 0.00 | 1.00 (up to 1.00) | well below normal | yes |
| dloss | 182 | 4.00 (up to 33.00) | far above normal | yes |
| packets sent by the server | 370 | 14 (up to 126) | far above normal | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Generic</sub>

## Alert 12: LOW priority | test | service role: web | anomaly score 1.2x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.2x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| ct_state_ttl | 3.00 | 0.00 (up to 1.00) | far above normal | yes |
| state_CON | 1.00 | 0.00 (up to 0.00) | far above normal | yes |
| state_FIN | 0.00 | 1.00 (up to 1.00) | well below normal | yes |
| dloss | 79.00 | 5.00 (up to 370) | normal alone, unusual in combination | yes |
| packets sent by the server | 170 | 18 (up to 746) | normal alone, unusual in combination | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Generic</sub>

## Alert 13: LOW priority | test | service role: other_system | anomaly score 1.3x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.3x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| uses a non-TCP/UDP protocol | yes | no (up to yes) | normal alone, unusual in combination | yes |
| ct_dst_src_ltm | 63.00 | 3.00 (up to 13.00) | far above normal | yes |
| connections from this client to this service (last 100) | 1 | 6 (up to 17) | below normal | yes |
| client data rate (bit/s) | 69,333,328 /s | 336,499 /s (up to 119,999,992 /s) | normal alone, unusual in combination | no |
| ct_srv_dst | 1.00 | 6.00 (up to 16.00) | below normal | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (4 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Reconnaissance</sub>

## Alert 14: LOW priority | test | service role: other_system | anomaly score 1.1x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.1x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| svc_other | 1.00 | 0.00 (up to 0.00) | far above normal | yes |
| svc_none | 0.00 | 1.00 (up to 1.00) | well below normal | yes |
| connections from this client to this service (last 100) | 1 | 6 (up to 17) | below normal | yes |
| dmean | 0.00 | 91.00 (up to 879) | normal alone, unusual in combination | no |
| ct_srv_dst | 1.00 | 6.00 (up to 16.00) | below normal | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (4 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Reconnaissance</sub>

## Alert 15: LOW priority | test | service role: other_system | anomaly score 1.0x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.0x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| connections to this destination (last 100) | 10 | 3 (up to 9) | above normal | yes |
| connections from this client to this service (last 100) | 1 | 6 (up to 17) | below normal | yes |
| ct_srv_dst | 1.00 | 6.00 (up to 16.00) | below normal | yes |
| client IP TTL | 254 | 31.00 (up to 254) | normal alone, unusual in combination | yes |
| ct_dst_src_ltm | 1.00 | 3.00 (up to 13.00) | normal alone, unusual in combination | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Shellcode</sub>

## Alert 16: LOW priority | test | service role: web | anomaly score 1.5x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.5x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| trans_depth | 0.00 | 1.00 (up to 1.00) | well below normal | yes |
| response_body_len | 0.00 | 3,924 (up to 524,288) | normal alone, unusual in combination | yes |
| ct_flw_http_mthd | 0.00 | 1.00 (up to 4.00) | well below normal | yes |
| dloss | 116 | 5.00 (up to 370) | normal alone, unusual in combination | yes |
| packets sent by the server | 236 | 18 (up to 746) | normal alone, unusual in combination | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Worms</sub>

## Alert 17: LOW priority | test | service role: web | anomaly score 1.5x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.5x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| response_body_len | 0.00 | 3,924 (up to 524,288) | normal alone, unusual in combination | yes |
| trans_depth | 0.00 | 1.00 (up to 1.00) | well below normal | yes |
| ct_flw_http_mthd | 0.00 | 1.00 (up to 4.00) | well below normal | yes |
| packets sent by the server | 372 | 18 (up to 746) | normal alone, unusual in combination | yes |
| dloss | 184 | 5.00 (up to 370) | normal alone, unusual in combination | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Worms</sub>

## Alert 18: LOW priority | test | service role: file_transfer | anomaly score 1.3x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.3x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| svc_ftp | 1.00 | 0.00 (up to 1.00) | normal alone, unusual in combination | yes |
| ct_ftp_cmd | 0.00 | 0.00 (up to 1.00) | normal alone, unusual in combination | yes |
| is_ftp_login | 0.00 | 0.00 (up to 1.00) | normal alone, unusual in combination | yes |
| svc_other | 0.00 | 1.00 (up to 1.00) | normal alone, unusual in combination | yes |
| flow duration | 3.0 s | 223 ms (up to 2.0 s) | far above normal | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Benign</sub>

## Alert 19: LOW priority | test | service role: other_system | anomaly score 1.1x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.1x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| dinpkt | 57,739 | 0.95 (up to 145) | far above normal | yes |
| djit | 57,739 | 21.79 (up to 898) | far above normal | yes |
| sinpkt | 19,296 | 1.52 (up to 60,001) | normal alone, unusual in combination | yes |
| state_FIN | 0.00 | 1.00 (up to 1.00) | normal alone, unusual in combination | yes |
| ct_state_ttl | 3.00 | 0.00 (up to 3.00) | normal alone, unusual in combination | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Benign</sub>

## Alert 20: LOW priority | test | service role: other_system | anomaly score 1.0x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.0x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| smean | 735 | 64.00 (up to 532) | far above normal | yes |
| dloss | 0.00 | 4.00 (up to 33.00) | normal alone, unusual in combination | yes |
| flow duration | 954 ms | 41 ms (up to 3.1 s) | normal alone, unusual in combination | yes |
| server data rate (bit/s) | 1,308 /s | 130,980 /s (up to 14,193,318 /s) | normal alone, unusual in combination | yes |
| client IP TTL | 31.00 | 31.00 (up to 254) | normal alone, unusual in combination | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Benign</sub>

## Alert 21: LOW priority | test | service role: other_system | anomaly score 1.0x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.0x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| state_CON | 1.00 | 0.00 (up to 1.00) | normal alone, unusual in combination | yes |
| state_FIN | 0.00 | 1.00 (up to 1.00) | normal alone, unusual in combination | yes |
| dmean | 890 | 91.00 (up to 879) | above normal | yes |
| sjit | 666 | 59.18 (up to 7,936) | normal alone, unusual in combination | yes |
| packets sent by the client | 10 | 16 (up to 122) | normal alone, unusual in combination | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Benign</sub>

## Alert 22: LOW priority | test | service role: other_system | anomaly score 1.1x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.1x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| state_CON | 1.00 | 0.00 (up to 1.00) | normal alone, unusual in combination | yes |
| state_FIN | 0.00 | 1.00 (up to 1.00) | normal alone, unusual in combination | yes |
| connections from this client to this service (last 100) | 2 | 6 (up to 17) | normal alone, unusual in combination | yes |
| sloss | 1.00 | 4.00 (up to 21.00) | normal alone, unusual in combination | yes |
| ct_srv_dst | 2.00 | 6.00 (up to 16.00) | normal alone, unusual in combination | yes |

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

<sub>Evaluation only (not used above): ground-truth label = Benign</sub>
