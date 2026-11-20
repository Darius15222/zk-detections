# zk-detections

Detection as code for the [zk-secops lab](https://github.com/Darius15222/zk-secops-dev). This repository holds everything that turns raw events into alerts:

- the pipeline that normalizes network IDS events to ECS;
- the Suricata rules;
- the Sigma detection rules;
- a Kibana dashboard;
- a runbook for every alert.

It only holds and tests them. [zk-platform](https://github.com/Darius15222/zk-platform) deploys them into the SIEM, and CI there proves that each rule fires during a simulated attack.

## Detections

| Rule | Source | Detects | MITRE |
|---|---|---|---|
| zk-auth brute force from one source | zk-auth logs | 10 failed logins from one source in 5 minutes (correlation over the zk-auth failed login rule) | T1110.001 |
| zk-auth Schnorr proof replay | zk-auth logs | A proof sent again with a burned nonce (`nonce_reuse`) | T1550 |
| zk-auth forged Schnorr proof | zk-auth logs | A proof that does not verify against the stored key (`invalid_proof`) | T1110 |
| Suricata ZK-LAB login burst | Suricata | A burst of login requests seen on the wire | T1110 |

What to do for each alert: [RUNBOOKS.md](RUNBOOKS.md).

## Layout

```
pipelines/suricata.conf        Logstash filter: Suricata eve.json -> ECS (input and output come from the deployment)
rules/
├── suricata/local.rules       Suricata rules, sids 9000000-9000999
├── sigma/*.yml                Sigma rules on ECS fields
├── sigma-pipeline.yml         routes each Sigma logsource to its data stream
├── build.sh                   sigma check + conversion to Elastic ES|QL
└── elastic/sigma-rules.ndjson generated rules, never edited by hand (CI fails on drift)
dashboards/zk-lab.ndjson       Kibana dashboard for the lab, imported by zk-platform
tests/
├── test_suricata.py           runs the pipeline in real Logstash and `suricata -T` on the rules
├── harness.conf               test input and output for the pipeline
└── samples/                   one raw event per file, positive and negative cases
RUNBOOKS.md                    per alert: what it means, what to check, what to do, false positives
```

## Technologies and why

| Technology | Used for | Why |
|---|---|---|
| Sigma | Detection rules | A vendor-neutral rule format: the logic is readable and portable, and `sigma-cli` compiles it to the SIEM's language |
| Elastic ES\|QL | Compiled rules | What Elastic Security runs; correlation rules (thresholds over time) become ES\|QL aggregations |
| Logstash | Suricata to ECS | zk-auth already logs ECS; Suricata needs mapping so both sources share field names |
| Suricata | Network rules | A second, independent view of the login traffic, from the wire instead of the application |
| Python unittest + Docker | Tests | Pipelines run in the real Logstash image and rules in the real Suricata image, pinned by digest to the deployed versions |
| ECS | Field names | One schema across sources, so rules and dashboards do not depend on the producer |

## Commands

| Command | Does |
|---|---|
| `python3 -I tests/test_suricata.py -v` | Pipeline tests in Logstash and rule check in Suricata (needs Docker) |
| `rules/build.sh` | Validates the Sigma rules and regenerates `rules/elastic/sigma-rules.ndjson` (needs `pip install --require-hashes -r requirements-sigma.txt`) |

From zk-platform, `make detections` loads the rules and `make attack` proves they fire. Rules for changes are in [AGENTS.md](AGENTS.md).
