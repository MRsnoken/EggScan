#!/usr/bin/env bash
set -euo pipefail

echo "=== EggScan installer ==="

# ------------------------------------------------------------------------------
# 1. Basic checks
# ------------------------------------------------------------------------------

if [ "${EUID}" -ne 0 ]; then
  echo "ERROR: This script must be run as root (use: sudo ./install_eggscan.sh)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/eggscan"
VENV_DIR="$INSTALL_DIR/venv"

WEB_SERVICE_FILE="/lib/systemd/system/eggscan-web.service"
SCAN_SERVICE_FILE="/lib/systemd/system/eggscan-scan.service"
OLD_SERVICE_FILE="/lib/systemd/system/eggscan.service"

DB_PATH="$INSTALL_DIR/eggscan.db"
SECRET_PATH="$INSTALL_DIR/secret_key.txt"
APP_MAIN="$INSTALL_DIR/eggscan.py"

IS_UPGRADE=0
if [ -f "$DB_PATH" ] || [ -f "$SECRET_PATH" ] || [ -f "$APP_MAIN" ]; then
  IS_UPGRADE=1
fi

echo "Installing from directory: $SCRIPT_DIR"
echo "Install directory: $INSTALL_DIR"
echo "Virtualenv: $VENV_DIR"
echo "Web service file: $WEB_SERVICE_FILE"
echo "Scan service file: $SCAN_SERVICE_FILE"
echo

check_dpkg_lock() {
  echo "Checking if apt/dpkg is busy (locks on dpkg + apt lists)..."
  while \
    fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
    fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
    fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
    echo "  dpkg/apt is locked by another process. Waiting 5 seconds..."
    sleep 5
  done
  echo "dpkg/apt is free, continuing."
}

need_cmd() {
  local c="$1"
  if ! command -v "$c" >/dev/null 2>&1; then
    echo "ERROR: Required command not found: $c"
    exit 1
  fi
}

# ------------------------------------------------------------------------------
# 2. Install system packages
# ------------------------------------------------------------------------------

echo "Updating package index..."
check_dpkg_lock
apt-get update -y

echo "Installing system packages (python3, pip, venv, nmap, iproute2, sqlite3, rsync, psmisc)..."
check_dpkg_lock
apt-get install -y python3 python3-pip python3-venv nmap iproute2 sqlite3 rsync psmisc

need_cmd rsync
need_cmd sqlite3
need_cmd fuser

echo
echo "System packages done."
echo

# ------------------------------------------------------------------------------
# 3. Create install dir + virtualenv (upgrade-safe)
# ------------------------------------------------------------------------------

echo "Creating install directory and virtualenv..."
mkdir -p "$INSTALL_DIR"

if [ -d "$VENV_DIR" ]; then
  echo "Virtualenv already exists at $VENV_DIR"
else
  python3 -m venv "$VENV_DIR"
  echo "Created virtualenv at $VENV_DIR"
fi

PYTHON_BIN="$VENV_DIR/bin/python"
PIP_BIN="$VENV_DIR/bin/pip"

if [ ! -x "$PYTHON_BIN" ]; then
  echo "ERROR: $PYTHON_BIN not found or not executable."
  exit 1
fi

echo
echo "Upgrading pip inside the virtualenv..."
"$PYTHON_BIN" -m pip install --upgrade pip

# ------------------------------------------------------------------------------
# 4. Install Python dependencies (prefer requirements.txt)
# ------------------------------------------------------------------------------

echo
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
  echo "Installing Python packages from requirements.txt inside venv..."
  "$PIP_BIN" install -r "$SCRIPT_DIR/requirements.txt"
else
  echo "requirements.txt not found, installing known deps explicitly..."
  "$PIP_BIN" install \
    Flask \
    flask_sqlalchemy \
    Flask-Login \
    Flask-Bcrypt \
    python-nmap \
    gunicorn
fi

echo
echo "Verifying that Python dependencies can be imported from the venv..."
"$PYTHON_BIN" - << 'EOF'
import flask
import flask_sqlalchemy
import flask_login
import flask_bcrypt
import nmap
print(" Python dependencies inside venv look OK.")
EOF

# ------------------------------------------------------------------------------
# 5. Copy application files (upgrade-safe)
#    - keeps eggscan.db + secret_key.txt + venv
# ------------------------------------------------------------------------------

echo
echo "Copying application files to $INSTALL_DIR (upgrade-safe)..."

if [ ! -f "$SCRIPT_DIR/eggscan.py" ]; then
  echo "ERROR: eggscan.py not found in $SCRIPT_DIR"
  exit 1
fi

BACKUP_DIR=""
if [ "$IS_UPGRADE" -eq 1 ]; then
  BACKUP_DIR="$INSTALL_DIR/_backup_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$BACKUP_DIR"
fi

if [ -n "$BACKUP_DIR" ] && [ -f "$APP_MAIN" ]; then
  echo "Backing up existing eggscan.py to $BACKUP_DIR/"
  cp -a "$APP_MAIN" "$BACKUP_DIR/eggscan.py"
fi

if [ -n "$BACKUP_DIR" ] && [ -f "$DB_PATH" ]; then
  echo "Backing up existing eggscan.db to $BACKUP_DIR/"
  cp -a "$DB_PATH" "$BACKUP_DIR/eggscan.db"
fi

if [ -n "$BACKUP_DIR" ] && [ -f "$SECRET_PATH" ]; then
  echo "Backing up existing secret_key.txt to $BACKUP_DIR/"
  cp -a "$SECRET_PATH" "$BACKUP_DIR/secret_key.txt"
fi

if [ -n "$BACKUP_DIR" ] && [ -d "$INSTALL_DIR/templates" ]; then
  echo "Backing up existing templates/ to $BACKUP_DIR/"
  cp -a "$INSTALL_DIR/templates" "$BACKUP_DIR/" || true
fi

if [ -n "$BACKUP_DIR" ] && [ -d "$INSTALL_DIR/static" ]; then
  echo "Backing up existing static/ to $BACKUP_DIR/"
  cp -a "$INSTALL_DIR/static" "$BACKUP_DIR/" || true
fi

cp -a "$SCRIPT_DIR/eggscan.py" "$APP_MAIN"
chmod 755 "$APP_MAIN"

if [ -f "$SCRIPT_DIR/version.json" ]; then
  cp -a "$SCRIPT_DIR/version.json" "$INSTALL_DIR/version.json"
else
  echo "WARNING: version.json not found in $SCRIPT_DIR - continuing without it."
fi

if [ -d "$SCRIPT_DIR/templates" ]; then
  mkdir -p "$INSTALL_DIR/templates"
  rsync -a --delete "$SCRIPT_DIR/templates/" "$INSTALL_DIR/templates/"
else
  echo "NOTE: templates/ not found in installer source; leaving existing templates as-is."
fi

if [ -d "$SCRIPT_DIR/static" ]; then
  mkdir -p "$INSTALL_DIR/static"
  rsync -a --delete "$SCRIPT_DIR/static/" "$INSTALL_DIR/static/"
else
  echo "NOTE: static/ not found in installer source; leaving existing static as-is."
fi

if [ -f "$SCRIPT_DIR/CHANGELOG.md" ]; then
  cp -a "$SCRIPT_DIR/CHANGELOG.md" "$INSTALL_DIR/CHANGELOG.md"
fi
if [ -f "$SCRIPT_DIR/README.md" ]; then
  cp -a "$SCRIPT_DIR/README.md" "$INSTALL_DIR/README.md"
fi
if [ -f "$SCRIPT_DIR/LICENSE" ]; then
  cp -a "$SCRIPT_DIR/LICENSE" "$INSTALL_DIR/LICENSE"
fi

if [ -f "$SCRIPT_DIR/secret_key.txt" ]; then
  if [ -f "$SECRET_PATH" ]; then
    echo "Keeping existing secret_key.txt (not overwriting)."
  else
    echo "Copying secret_key.txt (fresh install only)."
    cp -a "$SCRIPT_DIR/secret_key.txt" "$SECRET_PATH"
    chmod 600 "$SECRET_PATH" || true
  fi
fi

echo "Application files copied."
echo

# ------------------------------------------------------------------------------
# 6. Database schema bootstrap
# ------------------------------------------------------------------------------

echo "Skipping DB schema bootstrap (schema is handled automatically at startup)."
echo

# ------------------------------------------------------------------------------
# 7. Create/Update systemd units (web + scan worker)
#    - Migrates from old eggscan.service if it exists
# ------------------------------------------------------------------------------

echo "Creating systemd units:"
echo "  Web:  $WEB_SERVICE_FILE"
echo "  Scan: $SCAN_SERVICE_FILE"
echo

old_unit_exists=0
if systemctl list-unit-files eggscan.service >/dev/null 2>&1; then
  old_unit_exists=1
fi

if [ "$old_unit_exists" -eq 1 ]; then
  echo "Old eggscan.service detected -> stopping/disabling to avoid duplicate instances..."
  systemctl stop eggscan.service 2>/dev/null || true
  systemctl disable eggscan.service 2>/dev/null || true
  systemctl mask eggscan.service 2>/dev/null || true
fi

if [ -f "$OLD_SERVICE_FILE" ]; then
  echo "Removing old unit file: $OLD_SERVICE_FILE"
  rm -f "$OLD_SERVICE_FILE"
fi

cat > "$WEB_SERVICE_FILE" <<EOF
[Unit]
Description=EggScan - Web UI (Gunicorn)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
Environment="PYTHONUNBUFFERED=1"
ExecStart=$VENV_DIR/bin/gunicorn -w 2 --threads 2 -b 0.0.0.0:5000 --access-logfile - --error-logfile - eggscan:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$WEB_SERVICE_FILE"

cat > "$SCAN_SERVICE_FILE" <<EOF
[Unit]
Description=EggScan - Scan Worker (single instance)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
Environment="PYTHONUNBUFFERED=1"
ExecStart=$PYTHON_BIN $INSTALL_DIR/eggscan.py scan-worker
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SCAN_SERVICE_FILE"

systemctl daemon-reload

echo "Enabling services at boot..."
systemctl enable eggscan-web.service
systemctl enable eggscan-scan.service

echo "Restarting services..."
systemctl restart eggscan-scan.service || systemctl start eggscan-scan.service
systemctl restart eggscan-web.service || systemctl start eggscan-web.service

echo
echo "=== Status for eggscan-web.service ==="
systemctl status eggscan-web.service --no-pager || true

echo
echo "=== Status for eggscan-scan.service ==="
systemctl status eggscan-scan.service --no-pager || true

echo
echo " EggScan installation finished."
echo " Open the web UI on port 5000 of this machine."
echo " Virtualenv: $VENV_DIR"

if [ "$IS_UPGRADE" -eq 1 ]; then
  echo " Upgrade detected."
  echo " DB kept at: $DB_PATH (never overwritten)"
  echo " Secret key kept at: $SECRET_PATH (never overwritten)"
  if [ -n "$BACKUP_DIR" ]; then
    echo " Backups stored in: $BACKUP_DIR"
  fi
else
  echo " Fresh install detected."
  echo " DB path: $DB_PATH"
  echo " Secret key path: $SECRET_PATH"
fi
