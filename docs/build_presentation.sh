#!/usr/bin/env bash
# Render docs/presentation.html to a PDF using headless Chromium.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IN="${DIR}/presentation.html"
OUT="${DIR}/netguard-presentation.pdf"

BROWSER="${CHROMIUM:-}"
if [[ -z "${BROWSER}" ]]; then
  for candidate in chromium chromium-browser google-chrome google-chrome-stable; do
    if command -v "${candidate}" >/dev/null 2>&1; then BROWSER="$(command -v "${candidate}")"; break; fi
  done
fi
if [[ -z "${BROWSER}" ]]; then
  echo "error: no Chromium/Chrome found (set CHROMIUM=/path/to/browser)" >&2
  exit 1
fi

# A private profile dir avoids clashing with a running Chromium instance.
PROFILE="$(mktemp -d)"
trap 'rm -rf "${PROFILE}"' EXIT

"${BROWSER}" --headless --no-sandbox --disable-gpu --user-data-dir="${PROFILE}" \
  --no-pdf-header-footer --print-to-pdf="${OUT}" "file://${IN}" 2>&1 | tail -1

if command -v pdfinfo >/dev/null 2>&1; then
  pdfinfo "${OUT}" | grep -E "Pages|Page size" || true
fi
echo "Wrote ${OUT}"
