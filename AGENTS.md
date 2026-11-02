# zk-detections

Detection-as-code for the zk-secops lab: Logstash pipelines that map raw security logs to ECS, and detection rules. `zk-platform` deploys them; this repo only holds and tests them. Workspace rules (`zk-secops-dev/CLAUDE.md`, `harness/`) apply here too.

## Commands

| Command | Does |
|---|---|
| `python3 tests/test_suricata.py -v` | Runs the pipeline in real Logstash on `tests/samples/`, and `suricata -T` on the rules (needs Docker) |

## Layout

- `pipelines/*.conf`: filter blocks only; input and output are set by the deployment (`zk-platform`) or by `tests/harness.conf`.
- `rules/suricata/local.rules`: Suricata rules, sids 9000000-9000999.
- `tests/samples/`: one raw event per file; every pipeline has at least one positive and one negative sample.

## Rules

- A pipeline change ships with a sample and an assertion for the new field.
- Field names follow ECS. `zk-auth` already logs ECS directly and needs no pipeline.
- Images in tests are pinned by digest and match the versions deployed by `zk-platform`.
