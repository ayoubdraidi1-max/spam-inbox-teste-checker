#!/usr/bin/env bash
#
# Mailbox Hit Checker — one-command Linux installer.
#
#   curl-less usage (recommended): copy the whole project folder to the server,
#   then run:
#
#       bash install.sh
#
#   Options (environment variables):
#       PORT=5010            listening port
#       BIND=0.0.0.0         bind address
#       SERVICE_USER=name    user that runs the service (default: current user)
#       NO_SYSTEMD=1         only install dependencies, do not create a service
#
set -euo pipefail

APP_NAME="mailbox-hit-checker"
SERVICE_NAME="mailbox-hit-checker"
PORT="${PORT:-5010}"
BIND="${BIND:-0.0.0.0}"
THREADS="${THREADS:-16}"

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pick the service user: explicit > sudo invoker > current user.
if [[ -n "${SERVICE_USER:-}" ]]; then
  RUN_USER="$SERVICE_USER"
elif [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  RUN_USER="$SUDO_USER"
else
  RUN_USER="$(id -un)"
fi

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || die "This installer targets Linux."

log "Installing ${APP_NAME} from ${APP_DIR}"

# --------------------------------------------------------------------------- #
# 1. Python
# --------------------------------------------------------------------------- #
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done
[[ -n "$PY" ]] || die "python3 is required. Install it first (apt install python3 python3-venv)."
log "Using $(command -v "$PY") ($("$PY" --version 2>&1))"

# --------------------------------------------------------------------------- #
# 2. Virtual environment + dependencies
# --------------------------------------------------------------------------- #
VENV_DIR="${APP_DIR}/.venv"
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  log "Creating virtual environment at ${VENV_DIR}"
  "$PY" -m venv "$VENV_DIR" || die "Could not create a venv (try: apt install python3-venv)."
fi

log "Installing dependencies"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip >/dev/null
"${VENV_DIR}/bin/pip" install -r "${APP_DIR}/requirements.txt"

# Data files written by the app at runtime must belong to the run user.
touch "${APP_DIR}/users.json" 2>/dev/null || true
if [[ "$(id -u)" -eq 0 && "$RUN_USER" != "root" ]]; then
  chown -R "$RUN_USER":"$RUN_USER" "$APP_DIR"
fi

if [[ -n "${NO_SYSTEMD:-}" ]]; then
  log "Dependencies installed (NO_SYSTEMD set). Start with:"
  echo "    ${VENV_DIR}/bin/gunicorn --worker-class gthread --threads ${THREADS} -b ${BIND}:${PORT} app:app"
  exit 0
fi

# --------------------------------------------------------------------------- #
# 3. systemd service
# --------------------------------------------------------------------------- #
command -v systemctl >/dev/null 2>&1 || die "systemd not found. Re-run with NO_SYSTEMD=1 for a manual install."

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    die "Root privileges are required to install the systemd service."
  fi
fi

UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
log "Writing ${UNIT_PATH}"

$SUDO tee "$UNIT_PATH" >/dev/null <<EOF
[Unit]
Description=Mailbox Hit Checker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${APP_DIR}
# A single worker with many threads: the scan engine keeps its state in-process,
# so multiple workers would not share results. Threads keep it responsive.
ExecStart=${VENV_DIR}/bin/gunicorn --worker-class gthread --threads ${THREADS} --timeout 120 --bind ${BIND}:${PORT} app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

log "Enabling and starting the service"
$SUDO systemctl daemon-reload
$SUDO systemctl enable "${SERVICE_NAME}" >/dev/null
$SUDO systemctl restart "${SERVICE_NAME}"

# --------------------------------------------------------------------------- #
# 4. Firewall (best effort)
# --------------------------------------------------------------------------- #
if command -v ufw >/dev/null 2>&1 && $SUDO ufw status 2>/dev/null | grep -q "Status: active"; then
  log "Opening port ${PORT} in ufw"
  $SUDO ufw allow "${PORT}/tcp" >/dev/null || true
fi

sleep 1
if $SUDO systemctl is-active --quiet "${SERVICE_NAME}"; then
  IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo
  log "Done. ${APP_NAME} is running."
  echo "    URL          : http://${IP:-<server-ip>}:${PORT}"
  echo "    Admin console: http://${IP:-<server-ip>}:${PORT}/admin"
  echo "    Logs         : ${SUDO} journalctl -u ${SERVICE_NAME} -f"
  echo "    Stop         : ${SUDO} systemctl stop ${SERVICE_NAME}"
  echo
  warn "The admin console (/admin) is not linked anywhere — keep that URL private."
else
  die "Service failed to start. Check: ${SUDO} journalctl -u ${SERVICE_NAME} -n 50"
fi
