#!/usr/bin/env bash
# Sigma -> Elastic Security ES|QL rules. CI reruns this and fails if the committed output differs (R-05).
set -euo pipefail
cd "$(dirname "$0")/.."
# files in sorted order: directory order differs between machines and would make the drift check flaky
mapfile -t rules < <(LC_ALL=C ls rules/sigma/*.yml)
sigma check "${rules[@]}"
sigma convert -t esql -p rules/sigma-pipeline.yml -f siem_rule_ndjson "${rules[@]}" 2>/dev/null | grep "^{" > rules/elastic/sigma-rules.ndjson
echo "rules/elastic/sigma-rules.ndjson: $(wc -l < rules/elastic/sigma-rules.ndjson) rules"
