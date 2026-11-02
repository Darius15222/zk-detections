#!/usr/bin/env bash
# Sigma -> Elastic Security ES|QL rules. CI reruns this and fails if the committed output differs (R-05).
set -euo pipefail
cd "$(dirname "$0")/.."
sigma check rules/sigma
sigma convert -t esql -p rules/sigma-pipeline.yml -f siem_rule_ndjson rules/sigma 2>/dev/null | grep "^{" > rules/elastic/sigma-rules.ndjson
echo "rules/elastic/sigma-rules.ndjson: $(wc -l < rules/elastic/sigma-rules.ndjson) rules"
