#!/usr/bin/env bash
# Run every simulated scenario end-to-end and produce HTML reports + a summary.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${ROOT}/demo-output"
mkdir -p "${OUT}"

echo "==> NetGuard demo: running all scenarios"
python3 -m netguard --no-notify demo --all --save-html "${OUT}/report.html"

echo
echo "==> Summaries"
python3 -m netguard --no-notify demo --list | sed 's/^/    /'

echo
echo "HTML reports written to: ${OUT}/"
ls -1 "${OUT}"
