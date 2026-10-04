# Alert review - form 2

Each card is one alert raised by the anomaly detector. For every card, answer the questions on your answer sheet before moving on, and do not go back to earlier cards. Some cards include an explanation of the alert and some do not; that is intended. Some alerts are real attacks and some are false alarms.


## Alert 1: LOW priority | service role: web | anomaly score 1.1x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.1x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| FIN sent by client | no | yes (up to yes) | normal alone, unusual in combination | yes |
| HTTP response size | 11.3 KB | 0 B (up to 1.7 KB) | far above normal | yes |
| HTTP GET requests | 1 | 0 (up to 1) | normal alone, unusual in combination | yes |
| size of transferred file | 11.3 KB | 0 B (up to 1.8 KB) | far above normal | yes |
| files transferred in the flow | 1 | 0 (up to 2) | normal alone, unusual in combination | yes |

**Network context**

- 172.16.0.1:57056 -> 192.168.10.50:80 (TCP)

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

---

## Alert 2: LOW priority | service role: web | anomaly score 1.8x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.8x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Network context**

- 192.168.10.12:43658 -> 74.119.118.72:80 (TCP)
- HTTP request: bidder.criteo.com//cdb?ptv=18&profileId=154&cb=40482042119
- HTTP request: bidder.criteo.com//cdb?ptv=18&profileId=154&cb=70862264649

---

## Alert 3: LOW priority | service role: web | anomaly score 1.2x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.2x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| FIN sent by client | no | yes (up to yes) | normal alone, unusual in combination | yes |
| HTTP response size | 11.3 KB | 0 B (up to 1.7 KB) | far above normal | yes |
| size of transferred file | 11.3 KB | 0 B (up to 1.8 KB) | far above normal | yes |
| RST sent by server | yes | no (up to yes) | normal alone, unusual in combination | yes |
| longest HTTP URL | 59.00 | 0.00 (up to 82.00) | normal alone, unusual in combination | yes |

**Network context**

- 172.16.0.1:35956 -> 192.168.10.50:80 (TCP)
- HTTP request: 205.174.165.68//?7KLt0W=yQ1&uHPnH37CEN=XfgG8qPc&AfO=PJ81u&6ePD0=spRGgbuDa4
- HTTP request: 205.174.165.68//?YvGLWEXvG=MFmb2074g1IUphGLtiM1&nyKqd=83G

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

---

## Alert 4: LOW priority | service role: web | anomaly score 1.1x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.1x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Network context**

- 172.16.0.1:53798 -> 192.168.10.50:80 (TCP)

---

## Alert 5: LOW priority | service role: web | anomaly score 1.2x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.2x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| HTTP client-error responses (4xx) | 2 | 0 (up to 0) | far above normal | yes |
| HTTP redirects (3xx) | 2 | 0 (up to 0) | far above normal | yes |
| Suricata protocol-anomaly events | 2 | 0 (up to 0) | far above normal | yes |
| files transferred in the flow | 6 | 0 (up to 2) | far above normal | yes |
| HTTP GET requests | 6 | 0 (up to 1) | far above normal | yes |

**What the traffic shape resembles** (hypothesis)

- Unusual HTTP activity (long URLs, error responses, POSTs): consistent with web probing, brute-forcing or injection attempts.

**Network context**

- 172.16.0.1:52098 -> 192.168.10.50:80 (TCP)
- HTTP request: 205.174.165.68//dv/vulnerabilities/xss_r/
- HTTP request: 205.174.165.68//dv/login.php
- HTTP request: 205.174.165.68//dv/dvwa/css/login.css

**Suggested next steps**

- Read the request URIs and status codes in the web server / Zeek http.log
- Look for repeated login or parameter-tampering requests
- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

---

## Alert 6: LOW priority | service role: registered | anomaly score 2.3x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 2.3x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Network context**

- 192.168.10.9:4173 -> 205.174.165.73:8080 (TCP)
- HTTP request: 205.174.165.73//api/report

---

## Alert 7: LOW priority | service role: other_system | anomaly score 1.3x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.3x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| SYN sent by client | yes | no (up to yes) | normal alone, unusual in combination | yes |
| TCP flow | yes | no (up to yes) | normal alone, unusual in combination | yes |
| flow never completed (state new) | yes | no (up to no) | far above normal | yes |
| average server packet size | 0 B | 166 B (up to 821 B) | well below normal | yes |

**What the traffic shape resembles** (hypothesis)

- Many connection attempts with few or no replies: consistent with port scanning or probing of closed/filtered services.

**Network context**

- 192.168.10.8:44548 -> 192.168.10.5:691 (TCP)

**Suggested next steps**

- List the distinct destination ports contacted by this source
- Check firewall logs for blocked or reset connections from the same source
- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (4 of 4 evidence properties stable across two runs)

---

## Alert 8: LOW priority | service role: file_transfer | anomaly score 1.1x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.1x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Network context**

- 172.16.0.1:52506 -> 192.168.10.50:21 (TCP)

---

## Alert 9: LOW priority | service role: registered | anomaly score 1.2x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.2x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| FIN sent by client | no | no (up to yes) | normal alone, unusual in combination | yes |
| flow never completed (state new) | yes | no (up to yes) | normal alone, unusual in combination | yes |
| FIN sent by server | no | no (up to yes) | normal alone, unusual in combination | yes |
| average server packet size | 0 B | 61 B (up to 554 B) | normal alone, unusual in combination | yes |
| SYN sent by client | yes | yes (up to yes) | normal alone, unusual in combination | yes |

**Network context**

- 192.168.10.8:44549 -> 192.168.10.5:1166 (TCP)

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

---

## Alert 10: LOW priority | service role: registered | anomaly score 1.2x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.2x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Network context**

- 192.168.10.8:44548 -> 192.168.10.5:1309 (TCP)

---

## Alert 11: LOW priority | service role: web | anomaly score 1.7x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.7x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| HTTP POST requests | 25 | 0 (up to 1) | far above normal | yes |
| HTTP success responses (2xx) | 51 | 0 (up to 1) | far above normal | yes |
| files transferred in the flow | 76 | 0 (up to 2) | far above normal | yes |
| HTTP requests in the flow | 101 | 0 (up to 2) | far above normal | yes |
| HTTP redirects (3xx) | 50 | 0 (up to 0) | far above normal | yes |

**What the traffic shape resembles** (hypothesis)

- Unusual HTTP activity (long URLs, error responses, POSTs): consistent with web probing, brute-forcing or injection attempts.

**Network context**

- 172.16.0.1:53324 -> 192.168.10.50:80 (TCP)
- HTTP request: 205.174.165.68//dv/login.php
- HTTP request: 205.174.165.68//dv/vulnerabilities/xss_r/
- HTTP request: 205.174.165.68//dv/login.php

**Suggested next steps**

- Read the request URIs and status codes in the web server / Zeek http.log
- Look for repeated login or parameter-tampering requests
- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

---

## Alert 12: LOW priority | service role: registered | anomaly score 2.0x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 2.0x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Network context**

- 192.168.10.51:36732 -> 185.170.48.239:28903 (TCP)

---

## Alert 13: LOW priority | service role: registered | anomaly score 1.5x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.5x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| FIN sent by server | no | no (up to yes) | normal alone, unusual in combination | yes |
| RST sent by server | yes | no (up to yes) | normal alone, unusual in combination | yes |
| SYN sent by server | no | yes (up to yes) | normal alone, unusual in combination | yes |
| ACK sent by client | no | yes (up to yes) | normal alone, unusual in combination | yes |
| FIN sent by client | no | no (up to yes) | normal alone, unusual in combination | yes |

**Network context**

- 172.16.0.1:34866 -> 192.168.10.50:6566 (TCP)

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (5 of 5 evidence properties stable across two runs)

---

## Alert 14: LOW priority | service role: name_directory | anomaly score 1.2x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.2x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Network context**

- 192.168.10.3:60617 -> 192.168.10.1:53 (UDP)
- DNS query: 23.194.116.50.in-addr.arpa
- DNS query: 23.194.116.50.in-addr.arpa

---

## Alert 15: LOW priority | service role: remote_admin | anomaly score 1.8x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.8x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| RST sent by server | yes | no (up to no) | far above normal | yes |
| FIN sent by client | no | no (up to yes) | normal alone, unusual in combination | yes |
| PSH sent by server | no | no (up to yes) | normal alone, unusual in combination | yes |
| bytes sent by the server | 260 B | 362 B (up to 14.8 KB) | normal alone, unusual in combination | no |

**What the traffic shape resembles** (hypothesis)

- Many connection attempts with few or no replies: consistent with port scanning or probing of closed/filtered services.

**Network context**

- 172.16.0.1:48328 -> 192.168.10.50:22 (TCP)

**Suggested next steps**

- List the distinct destination ports contacted by this source
- Check firewall logs for blocked or reset connections from the same source
- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (3 of 4 evidence properties stable across two runs)

---

## Alert 16: LOW priority | service role: registered | anomaly score 1.2x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.2x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Network context**

- 192.168.10.8:44549 -> 192.168.10.5:65389 (TCP)

---

## Alert 17: LOW priority | service role: registered | anomaly score 1.2x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.2x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| average server packet size | 0 B | 61 B (up to 554 B) | normal alone, unusual in combination | yes |
| SYN sent by client | yes | yes (up to yes) | normal alone, unusual in combination | yes |
| bytes sent by the server | 0 B | 566 B (up to 12.1 KB) | normal alone, unusual in combination | yes |
| FIN sent by server | no | no (up to yes) | normal alone, unusual in combination | yes |

**Network context**

- 192.168.10.8:63810 -> 192.168.10.15:18101 (TCP)

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (4 of 4 evidence properties stable across two runs)

---

## Alert 18: LOW priority | service role: web | anomaly score 1.0x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.0x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Network context**

- 172.16.0.1:44592 -> 192.168.10.50:80 (TCP)

---

## Alert 19: LOW priority | service role: web | anomaly score 1.0x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.0x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Why it looks abnormal** (compared with normal traffic for this service role)

| Property | This flow | Normal (median, 95th pct) | Assessment | Stable evidence |
|---|---|---|---|---|
| TCP connection established | yes | no (up to no) | far above normal | yes |
| PSH sent by server | no | yes (up to yes) | normal alone, unusual in combination | yes |
| FIN sent by server | no | yes (up to yes) | normal alone, unusual in combination | yes |
| FIN sent by client | no | yes (up to yes) | normal alone, unusual in combination | yes |

**Network context**

- 172.16.0.1:38132 -> 192.168.10.50:80 (TCP)

**Suggested next steps**

- No signature matched: search the source host for other unusual flows around the same time before escalating

**Explanation confidence:** high (4 of 4 evidence properties stable across two runs)

---

## Alert 20: LOW priority | service role: web | anomaly score 1.2x the alert threshold

**Verdict:** ANOMALY ONLY - no Emerging Threats signature matched; the flow is unusual but not a known attack pattern (candidate novel activity or a false alarm)

**Detectors**

- Suricata: no Emerging Threats rule fired for this flow
- Anomaly model: 1.2x the alert threshold (the threshold is set so ~1% of normal traffic exceeds it)

**Network context**

- 192.168.10.5:56637 -> 23.15.4.9:80 (TCP)
- HTTP request: foodanddrink.tile.appex.bing.com//api/feed/?view-name=data&name=livetile&market=en-US&version=2_0&format=xml

---
