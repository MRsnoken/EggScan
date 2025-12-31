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
SERVICE_FILE="/lib/systemd/system/eggscan.service"

DB_PATH="$INSTALL_DIR/eggscan.db"
SECRET_PATH="$INSTALL_DIR/secret_key.txt"

APP_MAIN="$INSTALL_DIR/eggscan.py"

echo "Installing from directory: $SCRIPT_DIR"
echo "Install directory: $INSTALL_DIR"
echo "Virtualenv: $VENV_DIR"
echo "Service file: $SERVICE_FILE"
echo

check_dpkg_lock() {
  echo "Checking if apt/dpkg is busy (locks on /var/lib/dpkg/lock* )..."
  while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
        fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
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

echo "Installing system packages (python3, pip, venv, nmap, iproute2, sqlite3, rsync)..."
check_dpkg_lock
apt-get install -y python3 python3-pip python3-venv nmap iproute2 sqlite3 rsync

need_cmd rsync
need_cmd sqlite3

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
    python-nmap
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

BACKUP_DIR="$INSTALL_DIR/_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

if [ -f "$APP_MAIN" ]; then
  echo "Backing up existing eggscan.py to $BACKUP_DIR/"
  cp -a "$APP_MAIN" "$BACKUP_DIR/eggscan.py"
fi

if [ -d "$INSTALL_DIR/templates" ]; then
  echo "Backing up existing templates/ to $BACKUP_DIR/"
  cp -a "$INSTALL_DIR/templates" "$BACKUP_DIR/" || true
fi

if [ -d "$INSTALL_DIR/static" ]; then
  echo "Backing up existing static/ to $BACKUP_DIR/"
  cp -a "$INSTALL_DIR/static" "$BACKUP_DIR/" || true
fi

# Copy eggscan.py + version.json always (code update)
cp -a "$SCRIPT_DIR/eggscan.py" "$APP_MAIN"
chmod 755 "$APP_MAIN"

if [ -f "$SCRIPT_DIR/version.json" ]; then
  cp -a "$SCRIPT_DIR/version.json" "$INSTALL_DIR/version.json"
else
  echo "WARNING: version.json not found in $SCRIPT_DIR - continuing without it."
fi

# Copy templates/static if they exist in the new version
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

# Copy optional docs/changelog etc (harmless)
if [ -f "$SCRIPT_DIR/CHANGELOG.md" ]; then
  cp -a "$SCRIPT_DIR/CHANGELOG.md" "$INSTALL_DIR/CHANGELOG.md"
fi
if [ -f "$SCRIPT_DIR/README.md" ]; then
  cp -a "$SCRIPT_DIR/README.md" "$INSTALL_DIR/README.md"
fi
if [ -f "$SCRIPT_DIR/LICENSE" ]; then
  cp -a "$SCRIPT_DIR/LICENSE" "$INSTALL_DIR/LICENSE"
fi

# IMPORTANT: do NOT overwrite DB or secret key (upgrade-safe)
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
# 6. Database migration (keep your existing safety migration)
# ------------------------------------------------------------------------------

echo "Checking for existing EggScan database for migration..."

if [ -f "$DB_PATH" ]; then
  echo "Existing database found at $DB_PATH"

  DEVICE_TABLE_EXISTS=$(sqlite3 "$DB_PATH" ".tables device" | grep -c '^device$' || true)

  if [ "$DEVICE_TABLE_EXISTS" -eq 1 ]; then
    echo "device table exists, checking for last_seen_at column..."

    HAS_LAST_SEEN_COL=$(sqlite3 "$DB_PATH" "PRAGMA table_info(device);" | awk -F'|' '{print $2}' | grep -c '^last_seen_at$' || true)

    if [ "$HAS_LAST_SEEN_COL" -eq 0 ]; then
      echo "last_seen_at column is missing, applying migration..."
      sqlite3 "$DB_PATH" "ALTER TABLE device ADD COLUMN last_seen_at DATETIME;"
      echo "Migration done: last_seen_at column added to device table."
    else
      echo "Migration skipped: last_seen_at column already exists."
    fi
  else
    echo "device table does not exist yet in $DB_PATH, skipping migration."
  fi
else
  echo "No existing database found at $DB_PATH (fresh install), skipping DB migration."
fi

echo

# ------------------------------------------------------------------------------
# 7. Create/Update systemd unit
# ------------------------------------------------------------------------------

echo "Creating systemd unit at $SERVICE_FILE ..."

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=EggScan - Network Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON_BIN $INSTALL_DIR/eggscan.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SERVICE_FILE"

echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Enabling EggScan service at boot..."
systemctl enable eggscan.service

echo "Restarting EggScan service..."
systemctl restart eggscan.service || systemctl start eggscan.service

echo
echo "=== Status for eggscan.service ==="
systemctl status eggscan.service --no-pager || true

echo
echo " EggScan installation finished."
echo " Open the web UI on port 5000 of this machine."
echo " Virtualenv: $VENV_DIR"
echo " DB kept at: $DB_PATH (never overwritten)"
echo " Secret key kept at: $SECRET_PATH (never overwritten)"
