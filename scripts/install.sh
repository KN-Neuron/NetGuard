#!/usr/bin/env bash
# Install NetGuard for the current user (no root required).
#
#   ./scripts/install.sh            # install + enable the user service
#   ./scripts/install.sh --no-service
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${HOME}/.local"
APP_DIR="${PREFIX}/share/netguard"
BIN_DIR="${PREFIX}/bin"
UNIT_DIR="${HOME}/.config/systemd/user"
WITH_SERVICE=1

for arg in "$@"; do
  case "$arg" in
    --no-service) WITH_SERVICE=0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

echo "==> Installing NetGuard to ${APP_DIR}"
mkdir -p "${APP_DIR}" "${BIN_DIR}"
cp -r "${ROOT}/netguard" "${APP_DIR}/"
cp "${ROOT}/pyproject.toml" "${APP_DIR}/" 2>/dev/null || true

cat > "${BIN_DIR}/netguard" <<EOF
#!/usr/bin/env bash
exec "${PYTHON:-python3}" -m netguard "\$@"
EOF
chmod +x "${BIN_DIR}/netguard"

# Make the package importable regardless of the caller's CWD.
cat > "${APP_DIR}/netguard.pth" <<EOF
${APP_DIR}
EOF
PYVER="$("${PYTHON:-python3}" -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')"
SITE_DIR="$("${PYTHON:-python3}" -c 'import site; print(site.getusersitepackages())')"
mkdir -p "${SITE_DIR}"
cp "${APP_DIR}/netguard.pth" "${SITE_DIR}/netguard.pth"
echo "==> Added ${APP_DIR} to ${SITE_DIR}/netguard.pth"

echo "==> Checking runtime dependencies"
for tool in nmcli notify-send; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "    WARNING: '$tool' not found — some features will be limited"
  fi
done

if [[ "$WITH_SERVICE" -eq 1 ]] && command -v systemctl >/dev/null 2>&1; then
  echo "==> Installing user service"
  mkdir -p "${UNIT_DIR}"
  sed "s|%h/.local/bin/netguard|${BIN_DIR}/netguard|" \
    "${ROOT}/scripts/netguard.service" > "${UNIT_DIR}/netguard.service"
  systemctl --user daemon-reload || true
  systemctl --user enable --now netguard.service || \
    echo "    Could not enable the service automatically; run: systemctl --user enable --now netguard"
fi

echo
echo "Done. Try:"
echo "  netguard demo --list"
echo "  netguard demo hotel-mitm --save-html report.html"
echo "  netguard watch"
