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
APP_USER="eggscan"
APP_GROUP="eggscan"

WEB_SERVICE_FILE="/lib/systemd/system/eggscan-web.service"
SCAN_SERVICE_FILE="/lib/systemd/system/eggscan-scan.service"
UPDATE_SERVICE_FILE="/lib/systemd/system/eggscan-update.service"
UPDATER_SCRIPT_FILE="/usr/local/sbin/eggscan-update"
UPDATE_SUDOERS_FILE="/etc/sudoers.d/eggscan-update"
UPDATE_SERVICE_NAME="eggscan-update.service"
OLD_SERVICE_FILE="/lib/systemd/system/eggscan.service"

DB_PATH="$INSTALL_DIR/eggscan.db"
SECRET_PATH="$INSTALL_DIR/secret_key.txt"
APP_MAIN="$INSTALL_DIR/eggscan.py"
UPDATER_SOURCE="$SCRIPT_DIR/scripts/eggscan-update"
UPDATER_SERVICE_SOURCE="$SCRIPT_DIR/systemd/eggscan-update.service"

IS_UPGRADE=0
if [ -f "$DB_PATH" ] || [ -f "$SECRET_PATH" ] || [ -f "$APP_MAIN" ]; then
  IS_UPGRADE=1
fi

echo "Installing from directory: $SCRIPT_DIR"
echo "Install directory: $INSTALL_DIR"
echo "Virtualenv: $VENV_DIR"
echo "Web service user: $APP_USER"
echo "Web service file: $WEB_SERVICE_FILE"
echo "Scan service file: $SCAN_SERVICE_FILE"
echo "Update service file: $UPDATE_SERVICE_FILE"
echo "Updater script: $UPDATER_SCRIPT_FILE"
echo "Updater sudoers file: $UPDATE_SUDOERS_FILE"
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

ensure_app_user() {
  echo "Ensuring dedicated system user/group exists: $APP_USER"
  local nologin_shell="/usr/sbin/nologin"
  if [ ! -x "$nologin_shell" ]; then
    nologin_shell="/bin/false"
  fi

  if ! getent group "$APP_GROUP" >/dev/null 2>&1; then
    groupadd --system "$APP_GROUP"
  fi

  if ! id -u "$APP_USER" >/dev/null 2>&1; then
    useradd \
      --system \
      --no-create-home \
      --home-dir "$INSTALL_DIR" \
      --shell "$nologin_shell" \
      --gid "$APP_GROUP" \
      "$APP_USER"
  fi
}

set_app_permissions() {
  echo "Setting EggScan file permissions..."

  chown root:"$APP_GROUP" "$INSTALL_DIR"
  chmod 1775 "$INSTALL_DIR"

  if [ -f "$APP_MAIN" ]; then
    chown root:root "$APP_MAIN"
    chmod 755 "$APP_MAIN"
  fi

  for p in "$INSTALL_DIR/version.json" "$INSTALL_DIR/CHANGELOG.md" "$INSTALL_DIR/README.md" "$INSTALL_DIR/LICENSE" "$INSTALL_DIR/requirements.txt" "$INSTALL_DIR/install_eggscan.sh"; do
    if [ -e "$p" ]; then
      chown root:root "$p"
      if [ "$(basename "$p")" = "install_eggscan.sh" ]; then
        chmod 755 "$p" || true
      else
        chmod 644 "$p" || true
      fi
    fi
  done

  for d in "$INSTALL_DIR/templates" "$INSTALL_DIR/static" "$INSTALL_DIR/scripts" "$INSTALL_DIR/systemd"; do
    if [ -d "$d" ]; then
      chown -R root:root "$d"
      find "$d" -type d -exec chmod 755 {} \;
      find "$d" -type f -exec chmod 644 {} \;
    fi
  done

  if [ -f "$INSTALL_DIR/scripts/eggscan-update" ]; then
    chmod 755 "$INSTALL_DIR/scripts/eggscan-update" || true
  fi

  if [ -d "$VENV_DIR" ]; then
    chown -R root:root "$VENV_DIR"
  fi

  if [ -f "$SECRET_PATH" ]; then
    chown "$APP_USER:$APP_GROUP" "$SECRET_PATH"
    chmod 600 "$SECRET_PATH"
  fi

  for f in "$DB_PATH" "$DB_PATH-wal" "$DB_PATH-shm"; do
    if [ -e "$f" ]; then
      chown "$APP_USER:$APP_GROUP" "$f"
      chmod 660 "$f" || true
    fi
  done
}

secure_backup_dir() {
  local dir="$1"
  if [ -z "$dir" ] || [ ! -d "$dir" ]; then
    return
  fi

  chown root:root "$dir" || true
  chmod 700 "$dir" || true
  chown -R root:root "$dir" || true
  find "$dir" -type d -exec chmod 700 {} \; 2>/dev/null || true
  find "$dir" -type f -exec chmod 600 {} \; 2>/dev/null || true

  for f in "$dir/eggscan.db" "$dir/eggscan.db-wal" "$dir/eggscan.db-shm" "$dir/secret_key.txt"; do
    if [ -e "$f" ]; then
      chown root:root "$f" || true
      chmod 600 "$f" || true
    fi
  done
}

install_update_sudoers() {
  if ! command -v sudo >/dev/null 2>&1; then
    echo "NOTE: sudo not found - web-triggered updates will not be available."
    return
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    echo "NOTE: systemctl not found - web-triggered updates will not be available."
    return
  fi

  local systemctl_bin
  local sudoers_tmp
  systemctl_bin="$(command -v systemctl)"
  sudoers_tmp="$(mktemp)"

  {
    echo "# Allow EggScan web UI to queue only its updater service."
    echo "$APP_USER ALL=(root) NOPASSWD: $systemctl_bin --no-block start $UPDATE_SERVICE_NAME"
    if [ "$systemctl_bin" != "/usr/bin/systemctl" ] && [ -x "/usr/bin/systemctl" ]; then
      echo "$APP_USER ALL=(root) NOPASSWD: /usr/bin/systemctl --no-block start $UPDATE_SERVICE_NAME"
    fi
    if [ "$systemctl_bin" != "/bin/systemctl" ] && [ -x "/bin/systemctl" ]; then
      echo "$APP_USER ALL=(root) NOPASSWD: /bin/systemctl --no-block start $UPDATE_SERVICE_NAME"
    fi
  } > "$sudoers_tmp"

  chown root:root "$sudoers_tmp"
  chmod 440 "$sudoers_tmp"

  if command -v visudo >/dev/null 2>&1; then
    visudo -cf "$sudoers_tmp" >/dev/null
  fi

  install -D -o root -g root -m 440 "$sudoers_tmp" "$UPDATE_SUDOERS_FILE"
  rm -f "$sudoers_tmp"
}

# ------------------------------------------------------------------------------
# 2. Install system packages
# ------------------------------------------------------------------------------

echo "Updating package index..."
check_dpkg_lock
apt-get update -y

echo "Installing system packages (python3, pip, venv, nmap, iproute2, sqlite3, rsync, psmisc, sudo)..."
check_dpkg_lock
apt-get install -y python3 python3-pip python3-venv nmap iproute2 sqlite3 rsync psmisc sudo

need_cmd rsync
need_cmd sqlite3
need_cmd fuser
need_cmd install
need_cmd sudo

echo
echo "System packages done."
echo

ensure_app_user
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
    gunicorn \
    apprise
fi

echo
echo "Verifying that Python dependencies can be imported from the venv..."
"$PYTHON_BIN" - << 'EOF'
import flask
import flask_sqlalchemy
import flask_login
import flask_bcrypt
import nmap
import apprise
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
  secure_backup_dir "$BACKUP_DIR"
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

secure_backup_dir "$BACKUP_DIR"

if [ -n "$BACKUP_DIR" ] && [ -d "$INSTALL_DIR/templates" ]; then
  echo "Backing up existing templates/ to $BACKUP_DIR/"
  cp -a "$INSTALL_DIR/templates" "$BACKUP_DIR/" || true
fi

if [ -n "$BACKUP_DIR" ] && [ -d "$INSTALL_DIR/static" ]; then
  echo "Backing up existing static/ to $BACKUP_DIR/"
  cp -a "$INSTALL_DIR/static" "$BACKUP_DIR/" || true
fi

secure_backup_dir "$BACKUP_DIR"

cp -a "$SCRIPT_DIR/eggscan.py" "$APP_MAIN"
chmod 755 "$APP_MAIN"

if [ -f "$SCRIPT_DIR/install_eggscan.sh" ]; then
  cp -a "$SCRIPT_DIR/install_eggscan.sh" "$INSTALL_DIR/install_eggscan.sh"
  chmod 755 "$INSTALL_DIR/install_eggscan.sh"
elif [ -f "$SCRIPT_DIR/install.sh" ]; then
  echo "NOTE: install.sh found; copying it as install_eggscan.sh."
  cp -a "$SCRIPT_DIR/install.sh" "$INSTALL_DIR/install_eggscan.sh"
  chmod 755 "$INSTALL_DIR/install_eggscan.sh"
fi

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

if [ -d "$SCRIPT_DIR/scripts" ]; then
  mkdir -p "$INSTALL_DIR/scripts"
  rsync -a --delete "$SCRIPT_DIR/scripts/" "$INSTALL_DIR/scripts/"
fi

if [ -d "$SCRIPT_DIR/systemd" ]; then
  mkdir -p "$INSTALL_DIR/systemd"
  rsync -a --delete "$SCRIPT_DIR/systemd/" "$INSTALL_DIR/systemd/"
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

set_app_permissions

echo "Bootstrapping database schema as $APP_USER..."
if command -v runuser >/dev/null 2>&1; then
  (
    cd "$INSTALL_DIR"
    runuser -u "$APP_USER" -- env PYTHONUNBUFFERED=1 "$PYTHON_BIN" - << 'EOF'
import eggscan
print(" Database schema looks OK.")
EOF
  )
else
  echo "WARNING: runuser not found; bootstrapping as root and fixing ownership afterwards."
  (
    cd "$INSTALL_DIR"
    "$PYTHON_BIN" - << 'EOF'
import eggscan
print(" Database schema looks OK.")
EOF
  )
fi

set_app_permissions
echo

# ------------------------------------------------------------------------------
# 7. Create/Update systemd units (web + scan worker)
#    - Migrates from old eggscan.service if it exists
# ------------------------------------------------------------------------------

echo "Creating systemd units:"
echo "  Web:  $WEB_SERVICE_FILE"
echo "  Scan: $SCAN_SERVICE_FILE"
echo "  Update: $UPDATE_SERVICE_FILE (manual oneshot, not enabled)"
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
User=$APP_USER
Group=$APP_GROUP
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
User=$APP_USER
Group=$APP_GROUP
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=false
WorkingDirectory=$INSTALL_DIR
Environment="PYTHONUNBUFFERED=1"
ExecStart=$PYTHON_BIN $INSTALL_DIR/eggscan.py scan-worker
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SCAN_SERVICE_FILE"

if [ -f "$UPDATER_SOURCE" ]; then
  echo "Installing updater script: $UPDATER_SCRIPT_FILE"
  install -D -o root -g root -m 755 "$UPDATER_SOURCE" "$UPDATER_SCRIPT_FILE"

  echo "Creating updater systemd unit: $UPDATE_SERVICE_FILE"
  if [ -f "$UPDATER_SERVICE_SOURCE" ]; then
    install -D -o root -g root -m 644 "$UPDATER_SERVICE_SOURCE" "$UPDATE_SERVICE_FILE"
  else
    cat > "$UPDATE_SERVICE_FILE" <<EOF
[Unit]
Description=EggScan - Update from latest GitHub release
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
Environment="PYTHONUNBUFFERED=1"
ExecStart=$UPDATER_SCRIPT_FILE
TimeoutStartSec=30min
EOF
    chmod 644 "$UPDATE_SERVICE_FILE"
  fi
  echo "Creating restricted updater sudoers rule: $UPDATE_SUDOERS_FILE"
  install_update_sudoers
  echo "Updater service is installed but not enabled at boot."
else
  echo "NOTE: updater script not found at $UPDATER_SOURCE - updater service not installed."
fi

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
