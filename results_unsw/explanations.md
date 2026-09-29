# Alert explanations (ssl_mm_role, attribution backend: shap.KernelExplainer)

## Alert 1: test | role=other_system | score 5.0 (threshold 4.3) | ground truth: Analysis

Modality contribution: volume 11%, timing_tcp 16%, categorical 25%, application 0%, context 48%

- ct_dst_sport_ltm (context): 7.4σ above the role's normal, raises the score by 1.55
- proto_other (categorical): 4.3σ above the role's normal, raises the score by 1.30
- sttl (timing_tcp): 1.5σ above the role's normal, raises the score by 0.38
- is_sm_ips_ports (context): 0.2σ below the role's normal, raises the score by 0.32
- ct_dst_src_ltm (context): 1.4σ above the role's normal, raises the score by 0.31

## Alert 2: test | role=other_system | score 4.6 (threshold 4.3) | ground truth: Analysis

Modality contribution: volume 26%, timing_tcp 12%, categorical 49%, application 0%, context 12%

- proto_other (categorical): 4.3σ above the role's normal, raises the score by 1.90
- sload (volume): 2.3σ above the role's normal, raises the score by 0.37
- smean (volume): 0.1σ above the role's normal, raises the score by 0.29
- dload (volume): 2.3σ below the role's normal, raises the score by 0.29
- state_INT (categorical): 3.0σ above the role's normal, raises the score by 0.28

## Alert 3: test | role=other_system | score 5.2 (threshold 4.3) | ground truth: Backdoor

Modality contribution: volume 35%, timing_tcp 19%, categorical 17%, application 0%, context 29%

- ct_state_ttl (context): 2.4σ above the role's normal, raises the score by 1.03
- sttl (timing_tcp): 1.5σ above the role's normal, raises the score by 0.72
- sbytes (volume): 1.6σ below the role's normal, raises the score by 0.68
- state_CON (categorical): 1.9σ above the role's normal, raises the score by 0.51
- ct_srv_dst (context): 1.5σ below the role's normal, raises the score by 0.49

## Alert 4: test | role=other_system | score 4.6 (threshold 4.3) | ground truth: Backdoor

Modality contribution: volume 14%, timing_tcp 23%, categorical 34%, application 0%, context 30%

- proto_other (categorical): 4.3σ above the role's normal, raises the score by 1.25
- ct_dst_sport_ltm (context): 6.2σ above the role's normal, raises the score by 1.12
- sload (volume): 1.7σ above the role's normal, raises the score by 0.40
- state_FIN (categorical): 1.4σ below the role's normal, raises the score by 0.31
- swin (timing_tcp): 1.5σ below the role's normal, raises the score by 0.30

## Alert 5: test | role=other_system | score 4.3 (threshold 4.3) | ground truth: DoS

Modality contribution: volume 21%, timing_tcp 22%, categorical 50%, application 0%, context 8%

- proto_other (categorical): 4.3σ above the role's normal, raises the score by 1.63
- sload (volume): 1.7σ above the role's normal, raises the score by 0.39
- swin (timing_tcp): 1.5σ below the role's normal, raises the score by 0.36
- ct_dst_ltm (context): 1.2σ below the role's normal, raises the score by 0.34
- spkts (volume): 1.2σ below the role's normal, raises the score by 0.32

## Alert 6: test | role=other_system | score 5.2 (threshold 4.3) | ground truth: DoS

Modality contribution: volume 41%, timing_tcp 11%, categorical 40%, application 0%, context 8%

- proto_other (categorical): 4.3σ above the role's normal, raises the score by 1.23
- sttl (timing_tcp): 1.5σ above the role's normal, raises the score by 0.65
- dur (volume): 3.2σ above the role's normal, raises the score by 0.60
- state_INT (categorical): 3.0σ above the role's normal, raises the score by 0.51
- proto_tcp (categorical): 1.5σ below the role's normal, raises the score by 0.51

## Alert 7: test | role=other_system | score 4.6 (threshold 4.3) | ground truth: Exploits

Modality contribution: volume 15%, timing_tcp 16%, categorical 49%, application 0%, context 20%

- proto_other (categorical): 4.3σ above the role's normal, raises the score by 1.54
- ct_srv_dst (context): 1.5σ below the role's normal, raises the score by 0.45
- ct_srv_src (context): 1.5σ below the role's normal, raises the score by 0.44
- sload (volume): 2.3σ above the role's normal, raises the score by 0.43
- state_FIN (categorical): 1.4σ below the role's normal, raises the score by 0.36

## Alert 8: test | role=other_system | score 4.5 (threshold 4.3) | ground truth: Exploits

Modality contribution: volume 32%, timing_tcp 0%, categorical 37%, application 0%, context 31%

- proto_other (categorical): 4.3σ above the role's normal, raises the score by 1.30
- sload (volume): 2.0σ above the role's normal, raises the score by 0.47
- ct_srv_src (context): 0.4σ below the role's normal, raises the score by 0.47
- ct_src_ltm (context): 2.8σ above the role's normal, raises the score by 0.38
- dmean (volume): 2.3σ below the role's normal, raises the score by 0.34

## Alert 9: test | role=other_system | score 4.4 (threshold 4.3) | ground truth: Fuzzers

Modality contribution: volume 18%, timing_tcp 13%, categorical 42%, application 0%, context 27%

- proto_other (categorical): 4.3σ above the role's normal, raises the score by 1.39
- ct_dst_sport_ltm (context): 5.4σ above the role's normal, raises the score by 1.02
- sload (volume): 1.7σ above the role's normal, raises the score by 0.44
- state_FIN (categorical): 1.4σ below the role's normal, raises the score by 0.37
- sttl (timing_tcp): 1.5σ above the role's normal, raises the score by 0.33

## Alert 10: test | role=other_system | score 4.9 (threshold 4.3) | ground truth: Fuzzers

Modality contribution: volume 22%, timing_tcp 18%, categorical 32%, application 0%, context 29%

- proto_other (categorical): 4.3σ above the role's normal, raises the score by 1.23
- ct_dst_sport_ltm (context): 6.2σ above the role's normal, raises the score by 1.12
- sload (volume): 2.3σ above the role's normal, raises the score by 0.60
- state_FIN (categorical): 1.4σ below the role's normal, raises the score by 0.37
- swin (timing_tcp): 1.5σ below the role's normal, raises the score by 0.35

## Alert 11: test | role=other_system | score 7.2 (threshold 4.3) | ground truth: Generic

Modality contribution: volume 41%, timing_tcp 18%, categorical 41%, application 0%, context 0%

- svc_other (categorical): 4.6σ above the role's normal, raises the score by 2.20
- dur (volume): 5.9σ above the role's normal, raises the score by 1.26
- svc_none (categorical): 1.4σ below the role's normal, raises the score by 0.67
- dloss (timing_tcp): 2.8σ above the role's normal, raises the score by 0.46
- dpkts (volume): 2.3σ above the role's normal, raises the score by 0.46

## Alert 12: test | role=web | score 5.2 (threshold 4.3) | ground truth: Generic

Modality contribution: volume 16%, timing_tcp 18%, categorical 32%, application 6%, context 27%

- ct_state_ttl (context): 2.4σ above the role's normal, raises the score by 1.28
- state_CON (categorical): 1.9σ above the role's normal, raises the score by 0.83
- state_FIN (categorical): 1.4σ below the role's normal, raises the score by 0.67
- dloss (timing_tcp): 2.1σ above the role's normal, raises the score by 0.41
- dpkts (volume): 1.8σ above the role's normal, raises the score by 0.40

## Alert 13: test | role=other_system | score 5.7 (threshold 4.3) | ground truth: Reconnaissance

Modality contribution: volume 25%, timing_tcp 0%, categorical 30%, application 0%, context 45%

- proto_other (categorical): 4.3σ above the role's normal, raises the score by 1.45
- ct_dst_src_ltm (context): 4.7σ above the role's normal, raises the score by 1.18
- ct_srv_src (context): 1.5σ below the role's normal, raises the score by 0.71
- sload (volume): 1.6σ above the role's normal, raises the score by 0.46
- ct_srv_dst (context): 1.5σ below the role's normal, raises the score by 0.44

## Alert 14: test | role=other_system | score 4.6 (threshold 4.3) | ground truth: Reconnaissance

Modality contribution: volume 22%, timing_tcp 4%, categorical 57%, application 0%, context 17%

- svc_other (categorical): 4.6σ above the role's normal, raises the score by 1.91
- svc_none (categorical): 1.4σ below the role's normal, raises the score by 0.60
- ct_srv_src (context): 1.5σ below the role's normal, raises the score by 0.51
- dmean (volume): 2.3σ below the role's normal, raises the score by 0.39
- ct_srv_dst (context): 1.5σ below the role's normal, raises the score by 0.30

## Alert 15: test | role=other_system | score 4.3 (threshold 4.3) | ground truth: Shellcode

Modality contribution: volume 0%, timing_tcp 26%, categorical 5%, application 0%, context 68%

- ct_dst_ltm (context): 2.0σ above the role's normal, raises the score by 1.30
- ct_srv_src (context): 1.5σ below the role's normal, raises the score by 0.55
- ct_srv_dst (context): 1.5σ below the role's normal, raises the score by 0.46
- sttl (timing_tcp): 1.5σ above the role's normal, raises the score by 0.42
- ct_dst_src_ltm (context): 1.1σ below the role's normal, raises the score by 0.35

## Alert 16: test | role=web | score 6.4 (threshold 4.3) | ground truth: Worms

Modality contribution: volume 22%, timing_tcp 34%, categorical 0%, application 44%, context 0%

- trans_depth (application): 0.3σ below the role's normal, raises the score by 0.93
- response_body_len (application): 0.3σ below the role's normal, raises the score by 0.86
- ct_flw_http_mthd (application): 0.3σ below the role's normal, raises the score by 0.78
- dloss (timing_tcp): 2.4σ above the role's normal, raises the score by 0.66
- dpkts (volume): 2.0σ above the role's normal, raises the score by 0.64

## Alert 17: test | role=web | score 6.3 (threshold 4.3) | ground truth: Worms

Modality contribution: volume 29%, timing_tcp 19%, categorical 0%, application 47%, context 4%

- response_body_len (application): 0.3σ below the role's normal, raises the score by 0.91
- trans_depth (application): 0.3σ below the role's normal, raises the score by 0.91
- ct_flw_http_mthd (application): 0.3σ below the role's normal, raises the score by 0.71
- dpkts (volume): 2.3σ above the role's normal, raises the score by 0.68
- dloss (timing_tcp): 2.8σ above the role's normal, raises the score by 0.68

## Alert 18: test | role=file_transfer | score 5.8 (threshold 4.3) | ground truth: Benign

Modality contribution: volume 13%, timing_tcp 10%, categorical 37%, application 30%, context 10%

- svc_ftp (categorical): 6.7σ above the role's normal, raises the score by 1.50
- ct_ftp_cmd (application): 0.1σ below the role's normal, raises the score by 0.90
- is_ftp_login (application): 0.1σ below the role's normal, raises the score by 0.88
- svc_other (categorical): 0.2σ below the role's normal, raises the score by 0.65
- dur (volume): 1.9σ above the role's normal, raises the score by 0.45

## Alert 19: test | role=other_system | score 4.8 (threshold 4.3) | ground truth: Benign

Modality contribution: volume 4%, timing_tcp 70%, categorical 18%, application 0%, context 9%

- dinpkt (timing_tcp): 4.8σ above the role's normal, raises the score by 1.37
- djit (timing_tcp): 2.9σ above the role's normal, raises the score by 0.69
- sinpkt (timing_tcp): 2.8σ above the role's normal, raises the score by 0.57
- state_FIN (categorical): 1.4σ below the role's normal, raises the score by 0.46
- ct_state_ttl (context): 2.4σ above the role's normal, raises the score by 0.43

## Alert 20: test | role=other_system | score 4.5 (threshold 4.3) | ground truth: Benign

Modality contribution: volume 45%, timing_tcp 46%, categorical 0%, application 0%, context 9%

- smean (volume): 2.8σ above the role's normal, raises the score by 0.78
- dloss (timing_tcp): 1.0σ below the role's normal, raises the score by 0.59
- dur (volume): 0.6σ above the role's normal, raises the score by 0.47
- dload (volume): 0.8σ below the role's normal, raises the score by 0.46
- sttl (timing_tcp): 0.2σ below the role's normal, raises the score by 0.43

## Alert 21: test | role=other_system | score 4.4 (threshold 4.3) | ground truth: Benign

Modality contribution: volume 20%, timing_tcp 22%, categorical 58%, application 0%, context 0%

- state_CON (categorical): 1.9σ above the role's normal, raises the score by 1.21
- state_FIN (categorical): 1.4σ below the role's normal, raises the score by 1.12
- dmean (volume): 1.2σ above the role's normal, raises the score by 0.41
- sjit (timing_tcp): 0.6σ above the role's normal, raises the score by 0.30
- spkts (volume): 0.2σ below the role's normal, raises the score by 0.28

## Alert 22: test | role=other_system | score 4.7 (threshold 4.3) | ground truth: Benign

Modality contribution: volume 12%, timing_tcp 15%, categorical 43%, application 0%, context 30%

- state_CON (categorical): 1.9σ above the role's normal, raises the score by 1.15
- state_FIN (categorical): 1.4σ below the role's normal, raises the score by 0.91
- ct_srv_src (context): 0.9σ below the role's normal, raises the score by 0.50
- sloss (timing_tcp): 0.6σ below the role's normal, raises the score by 0.46
- ct_srv_dst (context): 0.8σ below the role's normal, raises the score by 0.37

