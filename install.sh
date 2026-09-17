#!/usr/bin/env bash
# ============================================================
#  Fariid Tech Security AI — one-command installer
#
#  Safe to run on Kali Linux / Debian-based Linux. This script:
#    1. Checks the OS and Python version
#    2. Creates a Python virtual environment
#    3. Installs dependencies and the CLI (editable)
#    4. Creates the config directory and .env.example
#    5. Runs `fariid-sec doctor`
#    6. Prints next steps
#
#  It never downloads or executes unknown remote scripts.
#  It never installs system packages silently.
# ============================================================
set -euo pipefail

GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[0;31m'; NC=$'\033[0m'
info()  { printf "${GREEN}[+]${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$1"; }
error() { printf "${RED}[-]${NC} %s\n" "$1"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT_DIR/.venv"
PY="${PYTHON:-python3}"

info "Fariid Tech Security AI installer"

# 1. Check OS
if ! command -v uname >/dev/null 2>&1; then error "uname not found"; exit 1; fi
OS="$(uname -s)"
case "$OS" in
  Linux)  info "Detected Linux" ;;
  *)      warn "Non-Linux OS detected ($OS). The CLI targets Kali Linux but may still run." ;;
esac

# 2. Check Python
if ! command -v "$PY" >/dev/null 2>&1; then
  error "Python 3 not found. Install it with: sudo apt install python3 python3-venv python3-pip"
  exit 1
fi
PYVER="$($PY --version 2>&1 | awk '{print $2}')"
info "Using $PY ($PYVER)"

# 3. Create venv
if [ ! -d "$VENV" ]; then
  info "Creating virtual environment"
  "$PY" -m venv "$VENV"
else
  info "Virtual environment already exists at .venv"
fi
PIP="$VENV/bin/pip"
"$PY" -m venv --upgrade "$VENV" >/dev/null 2>&1 || true

# 4. Install dependencies + CLI
info "Installing Fariid Sec (editable)"
"$PIP" install --upgrade pip >/dev/null
"$PIP" install -e "$ROOT_DIR"

# 5. Create config dir + .env.example
CONFIG_DIR="${FARIID_SEC_HOME:-$HOME/.config/fariid-sec}"
mkdir -p "$CONFIG_DIR"
if [ -f "$ROOT_DIR/.env.example" ] && [ ! -f "$CONFIG_DIR/.env.example" ]; then
  cp "$ROOT_DIR/.env.example" "$CONFIG_DIR/.env.example"
  info "Wrote $CONFIG_DIR/.env.example"
fi

# 6. Run doctor
info "Running doctor"
"$VENV/bin/fariid-sec" doctor || true

# 7. Next steps
echo
info "Install complete. Next steps:"
echo "  source $VENV/bin/activate"
echo "  export DEEPSEEK_API_KEY=\"sk-...\""
echo "  fariid-sec config set provider deepseek"
echo "  fariid-sec chat"
echo
warn "Only test systems you own or are explicitly authorized to test."
