from __future__ import annotations
import threading
import time
import ipaddress
import uuid
from typing import Optional, Tuple
import datetime
from zoneinfo import ZoneInfo, available_timezones
import subprocess
import os
import sys
import json
import secrets
import argparse
import tempfile
import sqlite3
import io
import pwd
import grp
import urllib.error
import urllib.request

import apprise

from flask import (
    Flask, render_template, redirect, url_for, request, flash,
    jsonify, has_request_context, session, abort, send_file
)

from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)
from flask_bcrypt import Bcrypt
import nmap
from sqlalchemy import text, case
from sqlalchemy.schema import UniqueConstraint

def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

# ---------------------------
#   PATHS, VERSION, SECRET
# ---------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION_FILE = os.path.join(BASE_DIR, "version.json")
SECRET_FILE = os.path.join(BASE_DIR, "secret_key.txt")
DB_FILE = os.path.join(BASE_DIR, "eggscan.db")
GITHUB_REPO_URL = "https://github.com/MRsnoken/EggScan"
GITHUB_LATEST_RELEASE_API = "https://api.github.com/repos/MRsnoken/EggScan/releases/latest"
UPDATE_CHECK_TIMEOUT_SECONDS = 6
UPDATE_CHECK_CACHE_SECONDS = 600
UPDATE_STATUS_FILE = "/var/lib/eggscan/update_status.json"
UPDATE_LOG_FILE = "/var/log/eggscan-update-latest.log"
UPDATE_LOG_TAIL_LINES = 80
UPDATE_LOG_TAIL_BYTES = 200 * 1024
UPDATER_SERVICE_NAME = "eggscan-update.service"
UPDATER_START_TIMEOUT_SECONDS = 10
OS_RELEASE_FILE = "/etc/os-release"
LEGACY_UPDATER_RELOAD_HINT_FRAGMENTS = (
    "reload this page to show the new version",
    "ladda om sidan för att visa ny version",
)
_UPDATE_CHECK_CACHE = {"checked_at": None, "payload": None}


def load_version():
    try:
        with open(VERSION_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("version", "unknown")
    except Exception:
        return "unknown"


def load_or_create_secret_key():
    if os.path.exists(SECRET_FILE):
        try:
            with open(SECRET_FILE, "r", encoding="utf-8") as f:
                key = f.read().strip()
                if key:
                    return key
        except Exception:
            pass

    key = secrets.token_hex(32)
    try:
        with open(SECRET_FILE, "w", encoding="utf-8") as f:
            f.write(key)
        try:
            os.chmod(SECRET_FILE, 0o600)
        except Exception:
            pass
    except Exception:
        pass
    return key


APP_VERSION = load_version()

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = load_or_create_secret_key()
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_FILE}"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"connect_args": {"timeout": 5}}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


def generate_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.before_request
def csrf_protect():
    if request.method != "POST":
        return None
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    session_token = session.get("_csrf_token")
    if not session_token or not token or not secrets.compare_digest(str(session_token), str(token)):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "csrf"}), 400
        abort(400)
    return None


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": generate_csrf_token}






# ---------------------------
#         MODELS
# ---------------------------


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=True)


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(200))
    mac_address = db.Column(db.String(40), unique=True)
    alias = db.Column(db.String(100), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    tags = db.Column(db.Text, nullable=True)
    manufacturer = db.Column(db.String(100), nullable=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)
    last_seen_scan = db.Column(db.String(36), nullable=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)  # UTC-naive
    is_new = db.Column(db.Boolean, default=False)
    last_subnet_id = db.Column(db.Integer, nullable=True)


class SubNetwork(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cidr = db.Column(db.String(50), unique=True, nullable=False)
    label = db.Column(db.String(80), nullable=True)
    sort_order = db.Column(db.Integer, default=0, nullable=False)


class DeviceSubnetSeen(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), nullable=False, index=True)
    device_id = db.Column(db.Integer, nullable=False, index=True)
    subnet_id = db.Column(db.Integer, nullable=True, index=True)  # None för IPv6 neighbor
    seen_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    __table_args__ = (
        UniqueConstraint("scan_id", "device_id", "subnet_id", name="uq_seen_scan_device_subnet"),
    )


class DeviceAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, nullable=False, unique=True, index=True)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    offline_threshold_minutes = db.Column(db.Integer, nullable=True)
    repeat_enabled = db.Column(db.Boolean, default=False, nullable=False)
    repeat_interval_minutes = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now
    )


class AlertLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)  # UTC-naive

    alert_type = db.Column(db.String(50), nullable=False)  # offline, online_back, test, new_device, new_device_subnet
    device_id = db.Column(db.Integer, nullable=True, index=True)

    mac_address = db.Column(db.String(40), nullable=True)
    device_label = db.Column(db.String(120), nullable=True)

    details_json = db.Column(db.Text, nullable=True)

    sent_to = db.Column(db.String(50), nullable=False, default="discord")
    status = db.Column(db.String(20), nullable=False, default="sent")  # sent, failed
    error = db.Column(db.Text, nullable=True)

    dedupe_key = db.Column(db.String(200), nullable=True, unique=True, index=True)


from sqlalchemy import text

def ensure_db_schema():
    with app.app_context():
        db.create_all()

        def has_column(table_name, col_name):
            rows = db.session.execute(text(f"PRAGMA table_info({table_name});")).fetchall()
            return any(r[1] == col_name for r in rows)

        if not has_column("sub_network", "label"):
            db.session.execute(text("ALTER TABLE sub_network ADD COLUMN label VARCHAR(80);"))

        if not has_column("sub_network", "sort_order"):
            db.session.execute(text("ALTER TABLE sub_network ADD COLUMN sort_order INTEGER DEFAULT 0;"))

        if not has_column("device", "last_subnet_id"):
            db.session.execute(text("ALTER TABLE device ADD COLUMN last_subnet_id INTEGER;"))

        # ---- FIX FÖR GAMLA DB: last_seen_at saknas i äldre versioner ----
        if not has_column("device", "last_seen_at"):
            db.session.execute(text("ALTER TABLE device ADD COLUMN last_seen_at DATETIME;"))

        if not has_column("device", "notes"):
            db.session.execute(text("ALTER TABLE device ADD COLUMN notes TEXT;"))

        if not has_column("device", "tags"):
            db.session.execute(text("ALTER TABLE device ADD COLUMN tags TEXT;"))

        try:
            db.session.execute(text("SELECT 1 FROM device_alert LIMIT 1;"))
        except Exception:
            db.session.rollback()
            db.create_all()

        if not has_column("device_alert", "repeat_enabled"):
            db.session.execute(text("ALTER TABLE device_alert ADD COLUMN repeat_enabled BOOLEAN NOT NULL DEFAULT 0;"))

        if not has_column("device_alert", "repeat_interval_minutes"):
            db.session.execute(text("ALTER TABLE device_alert ADD COLUMN repeat_interval_minutes INTEGER;"))

        try:
            db.session.execute(text("SELECT 1 FROM alert_log LIMIT 1;"))
        except Exception:
            db.session.rollback()
            db.create_all()

        db.session.commit()

def configure_sqlite_for_concurrency():
    with app.app_context():
        try:
            db.session.execute(text("PRAGMA journal_mode=WAL;"))
            db.session.execute(text("PRAGMA synchronous=NORMAL;"))
            db.session.execute(text("PRAGMA busy_timeout=5000;"))
            db.session.commit()
        except Exception:
            db.session.rollback()
ensure_db_schema()
configure_sqlite_for_concurrency()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------------
#     Language / Translation
# ---------------------------

TRANSLATIONS = {
    "sv": {
        "LANG_SV": "Svenska",
        "LANG_EN": "English",
        "LANGUAGE_LABEL": "Språk",
        "SAVE": "Spara",
        "BACK": "Tillbaka",
        "LOGOUT": "Logga ut",
        "CHANGE_PASSWORD": "Byt lösenord",
        "MANAGE_USERS": "Hantera användare",
        "SETTINGS": "Inställningar",
        "ABOUT": "Om",
        "CONFIRM_DELETE": "Är du säker?",
        "YES": "Ja",
        "NO": "Nej",
        "VERSION_LABEL": "Version",
        "ABOUT_TITLE": "Om EggScan",
        "ABOUT_CURRENT_VERSION": "Aktuell version",
        "ABOUT_INSTALL_INFO": "Installation",
        "ABOUT_RUNTIME_INFO": "Runtime",
        "ABOUT_REPO": "GitHub-repo",
        "ABOUT_INSTALL_DIR": "Installationsmapp",
        "ABOUT_DATABASE": "Databas",
        "ABOUT_DATABASE_SIZE": "Databasstorlek",
        "ABOUT_VERSION_FILE": "Versionsfil",
        "ABOUT_WEB_USER": "Webbprocess",
        "ABOUT_PYTHON": "Python",
        "ABOUT_SQLITE": "SQLite",
        "ABOUT_NOT_AVAILABLE": "Ej tillgängligt",
        "ABOUT_SERVICE_NOTE": "Uppdatering körs via installeraren och systemd; admin kan starta den härifrån.",
        "ABOUT_UPDATE_TITLE": "Uppdateringar",
        "ABOUT_UPDATE_HINT": "Kontrollerar senaste publicerade GitHub-release.",
        "ABOUT_CHECK_UPDATES": "Kolla uppdateringar",
        "ABOUT_UPDATE_CHECKING": "Kontrollerar...",
        "ABOUT_UPDATE_CURRENT": "Du kör senaste versionen.",
        "ABOUT_UPDATE_AVAILABLE": "Ny version finns.",
        "ABOUT_UPDATE_UNKNOWN": "Versionsstatus kunde inte avgöras.",
        "ABOUT_UPDATE_ERROR": "Kunde inte kontrollera uppdateringar just nu.",
        "ABOUT_UPDATE_LATEST_VERSION": "Senaste version",
        "ABOUT_UPDATE_RELEASE_LINK": "Öppna release",
        "ABOUT_UPDATE_LAST_CHECKED": "Senast kontrollerad",
        "ABOUT_UPDATER_STATUS_TITLE": "Updater-status",
        "ABOUT_UPDATER_STATUS_HINT": "Visar senaste status från den manuella updateraren.",
        "ABOUT_UPDATER_REFRESH": "Uppdatera status",
        "ABOUT_UPDATER_START": "Starta uppdatering",
        "ABOUT_UPDATER_STARTING": "Startar updateraren...",
        "ABOUT_UPDATER_STARTED": "Updateraren startades. Följ statusen nedan.",
        "ABOUT_UPDATER_RUNNING": "Updateraren kör. Status och logg uppdateras automatiskt.",
        "ABOUT_UPDATER_PLATFORM_NOTE": "Webbuppdateraren stöder Debian-, Ubuntu- och Raspberry Pi OS-baserade system med systemd.",
        "ABOUT_UPDATER_PLATFORM_UNSUPPORTED": "Webbuppdateraren är inaktiverad på detta system.",
        "ABOUT_UPDATER_PLATFORM_DETECTED": "Upptäckt system",
        "ABOUT_UPDATER_UNSUPPORTED_START": "Webbuppdateraren är bara tillgänglig på Debian-, Ubuntu- och Raspberry Pi OS-baserade system med systemd.",
        "ABOUT_UPDATER_MODAL_TITLE": "Uppdaterar EggScan",
        "ABOUT_UPDATER_MODAL_CLOSE": "Stäng och ladda om",
        "ABOUT_UPDATER_MODAL_WAIT": "Knappen aktiveras när uppdateringen är klar.",
        "ABOUT_UPDATER_START_ERROR": "Kunde inte starta updateraren.",
        "ABOUT_UPDATER_CONFIRM": "Starta uppdatering från senaste GitHub-release?",
        "ABOUT_UPDATER_STATE": "Status",
        "ABOUT_UPDATER_MESSAGE": "Meddelande",
        "ABOUT_UPDATER_UPDATED": "Uppdaterad",
        "ABOUT_UPDATER_PROGRESS": "Förlopp",
        "ABOUT_UPDATER_STEP_DOWNLOAD": "Hämtar release",
        "ABOUT_UPDATER_STEP_VALIDATE": "Kontrollerar paket",
        "ABOUT_UPDATER_STEP_INSTALL": "Kör installeraren",
        "ABOUT_UPDATER_STEP_FINISH": "Slutför uppdatering",
        "ABOUT_UPDATER_LOG": "Senaste logg",
        "ABOUT_UPDATER_HISTORY_HINT": "För historik över tidigare updater-körningar, se",
        "ABOUT_UPDATER_NO_STATUS": "Ingen updater-status ännu.",
        "ABOUT_UPDATER_LOG_EMPTY": "Ingen updater-logg ännu.",
        "ABOUT_UPDATER_ERROR": "Kunde inte läsa updater-status.",

        "INDEX_TITLE": "EggScan",
        "LOGGED_IN_AS": "Inloggad som:",
        "MANUAL_PING_PLACEHOLDER": "Ange IP att testa",
        "MANUAL_PING_BUTTON": "Testa adress",
        "FILTER_LABEL": "Filter:",
        "FILTER_BOTH": "Båda",
        "FILTER_ONLINE": "Endast online",
        "FILTER_OFFLINE": "Endast offline",
        "TAG_FILTER_LABEL": "Taggfilter:",
        "TAG_FILTER_ALL": "Alla",
        "QUICK_TAGS_ADMIN_LABEL": "Snabbtaggar",
        "QUICK_TAGS_MANAGE": "Hantera snabbtaggar",
        "QUICK_TAGS_PLACEHOLDER": "Skriv tagg och tryck Enter",
        "QUICK_TAGS_HINT": "Lägg till taggar för snabbfilter. Förslag visas från befintliga taggar.",
        "QUICK_TAGS_SAVE": "Spara snabbtaggar",
        "QUICK_TAGS_CONFIRM_REMOVE": "Vill du ta bort snabbtaggen \"{tag}\"?",
        "SEARCH_PLACEHOLDER": "Sök IP/MAC/Alias/Taggar",
        "SEARCH_FILTER_BUTTON": "Sök/Filtrera",
        "SORT_LABEL": "Sortera:",
        "SORT_IP": "IP",
        "SORT_MAC": "MAC",
        "SORT_ALIAS": "Alias",
        "SORT_MANUFACTURER": "Tillverkare",
        "SORT_UPDATED": "Uppdaterad",
        "SCAN_NOW": "Skanna nu",
        "BACKUP_DB": "Backup databas",
        "CONFIG_SNAPSHOT_TITLE": "Inställnings-snapshot",
        "CONFIG_SNAPSHOT_HINT": "Exportera/importera bara konfiguration (inte hela databasen).",
        "CONFIG_SNAPSHOT_SAVES": "Sparas: inställningar, notifieringskonfiguration, tysta tider, tema/språk, subnät och snabbtaggar.",
        "CONFIG_SNAPSHOT_NOT_SAVED": "Sparas inte: användare, enheter, enhetshistorik, larmhistorik och skanningsstatus.",
        "CONFIG_SNAPSHOT_EXPORT_OPTIONS": "Välj vad snapshoten ska innehålla:",
        "CONFIG_SNAPSHOT_IMPORT_OPTIONS": "Importera valda delar:",
        "CONFIG_SNAPSHOT_IMPORT_NOTE": "Import följer innehållet i snapshot-filen.",
        "CONFIG_SNAPSHOT_OPT_GENERAL": "Övriga inställningar",
        "CONFIG_SNAPSHOT_OPT_NOTIFICATIONS": "Notifieringsinställningar",
        "CONFIG_SNAPSHOT_OPT_QUIET_HOURS": "Tysta tider",
        "CONFIG_SNAPSHOT_OPT_THEME_LANG": "Tema / språk / tidszon",
        "CONFIG_SNAPSHOT_OPT_QUICK_TAGS": "Snabbtaggar",
        "CONFIG_SNAPSHOT_OPT_SUBNETS": "Subnät och etiketter",
        "CONFIG_SNAPSHOT_EXPORT": "Exportera snapshot",
        "CONFIG_SNAPSHOT_IMPORT": "Importera snapshot",
        "CONFIG_SNAPSHOT_FILE_LABEL": "Snapshot-fil (.json)",
        "SCAN_RUNNING": "Skanning pågår…",
        "TABLE_IP": "IP",
        "TABLE_MAC": "MAC",
        "TABLE_ALIAS": "Alias",
        "TABLE_PING": "Ping",
        "TABLE_MANUFACTURER": "Tillverkare",
        "TABLE_LAST_SEEN": "Senast sedd",
        "TABLE_STATUS": "Status",
        "TABLE_ACTIONS": "Åtgärder",
        "ALIAS_NONE": "Inget alias",
        "MANUFACTURER_UNKNOWN": "Okänd",
        "MARK_KNOWN": "Markera känd",
        "MARK_ALL_NEW_KNOWN": "Markera alla nya som kända",
        "DEVICE_KNOWN": "Känd",
        "NEW_DEVICES_MODAL_TITLE": "Nya enheter",
        "NEW_DEVICES_MODAL_EMPTY": "Inga nya enheter.",
        "DELETE": "Ta bort",
        "ALIAS_MODAL_TITLE": "Uppdatera Alias",
        "ALIAS_LABEL": "Alias",
        "ALIAS_DETAILS_LABEL": "Detaljer",
        "ALIAS_DETAILS_PLACEHOLDER": "Valfri anteckning om enheten...",
        "ALIAS_TAGS_LABEL": "Taggar",
        "ALIAS_TAGS_PLACEHOLDER": "t.ex. kamera, iot, gäst",
        "ALIAS_TAGS_HINT": "Separera flera taggar med kommatecken.",
        "CANCEL": "Avbryt",
        "ALIAS_SAVE": "Spara",

        "STATS_ONLINE_TOTAL_LABEL": "Online av totalt",
        "STATS_NEW_DEVICES_LABEL": "Nya enheter",
        "STATUSBAR_ONLINE": "Online",
        "STATUSBAR_OFFLINE": "Offline",
        "STATUSBAR_TOTAL": "Totalt",
        "STATUSBAR_NEW": "Nya enheter",
        "STATUSBAR_LAST_SCAN": "Senaste skanning",
        "STATUSBAR_IPV6": "IPv6",
        "STATUSBAR_ON": "På",
        "STATUSBAR_OFF": "Av",

        "MANUFACTURER_MODAL_TITLE": "Uppdatera tillverkare",
        "MANUFACTURER_LABEL": "Tillverkare",
        "MANUFACTURER_SAVE": "Spara",

        "SETUP_TITLE": "Setup Admin",
        "SETUP_USERNAME": "Användarnamn",
        "SETUP_PASSWORD": "Lösenord",
        "SETUP_CREATE_ADMIN": "Skapa Admin",

        "LOGIN_TITLE": "Logga in",
        "LOGIN_BUTTON": "Logga in",
        "LOGIN_USERNAME": "Användarnamn",
        "LOGIN_PASSWORD": "Lösenord",

        "CHANGE_PASSWORD_TITLE": "Byt lösenord",
        "CHANGE_PASSWORD_NEW": "Nytt lösenord",
        "CHANGE_PASSWORD_UPDATE": "Uppdatera lösenord",

        "MANAGE_USERS_TITLE": "Hantera användare",
        "MANAGE_USERS_ADD_TITLE": "Lägg till användare",
        "MANAGE_USERS_USERNAME": "Användarnamn",
        "MANAGE_USERS_PASSWORD": "Lösenord",
        "MANAGE_USERS_ADD_BUTTON": "Lägg till",
        "MANAGE_USERS_EXISTING": "Befintliga användare",
        "MANAGE_USERS_ID": "ID",
        "MANAGE_USERS_IS_ADMIN": "Admin?",
        "MANAGE_USERS_ACTION": "Åtgärd",
        "MANAGE_USERS_DELETE_BUTTON": "Radera",
        "MANAGE_USERS_ADMIN_LABEL": "Ja",
        "MANAGE_USERS_NOT_ADMIN_LABEL": "Nej",
        "MANAGE_USERS_ADMIN_TAG": "(Admin)",

        "CONFIG_TITLE": "Nätverksinställningar",
        "CONFIG_ADD_SUBNET_LABEL": "Lägg till subnät (t.ex. 192.168.0.0/24):",
        "CONFIG_ADD_SUBNET_BUTTON": "Lägg till",
        "CONFIG_SUBNET_COL": "Subnät",
        "CONFIG_SUBNET_DELETE_COL": "Ta bort",
        "CONFIG_SUBNET_DELETE_BUTTON": "Radera",
        "CONFIG_GUESS_BUTTON": "Gissa mitt IPv4-spann",
        "CONFIG_OTHER_SETTINGS": "Övriga inställningar",
        "SETTINGS_SEARCH_LABEL": "Sök inställningar",
        "SETTINGS_SEARCH_PLACEHOLDER": "Sök t.ex. språk, alerts, tema, subnet...",
        "SETTINGS_SEARCH_HINT": "Visar hela matchande sektioner. Rensa sökningen för att visa allt igen.",
        "SETTINGS_SEARCH_CLEAR": "Rensa",
        "SETTINGS_SEARCH_NO_RESULTS": "Inga inställningar matchar sökningen.",
        "CONFIG_IPV6_ENABLE": "Aktivera IPv6-upptäckt",
        "CONFIG_SCAN_INTERVAL": "Skanningsintervall (minuter):",
        "CONFIG_HIGHLIGHT_NEW": "Nya/okända enheter blinkar",
        "CONFIG_IPV6_UTILS": "IPv6-interface (t.ex. eth0):",
        "CONFIG_SAVE_BUTTON": "Spara",

        "FLASH_SETUP_USER_PASS_REQUIRED": "Användarnamn och lösenord krävs.",
        "FLASH_SETUP_ADMIN_CREATED": "Admin-konto skapat! Logga in.",
        "FLASH_LOGIN_OK": "Du har loggat in!",
        "FLASH_LOGIN_FAIL": "Felaktigt användarnamn eller lösenord.",
        "FLASH_LOGOUT": "Du har loggat ut.",
        "FLASH_PASSWORD_REQUIRED": "Nytt lösenord krävs.",
        "FLASH_PASSWORD_UPDATED": "Lösenordet har uppdaterats!",
        "FLASH_ALIAS_ADMIN_ONLY": "Endast admin kan ändra alias!",
        "FLASH_ALIAS_UPDATED": "Alias uppdaterat!",
        "FLASH_STATUS_ADMIN_ONLY": "Endast admin kan ändra status!",
        "FLASH_DEVICE_MARKED_KNOWN": "Enhet markerad som känd.",
        "FLASH_ALL_NEW_MARKED_KNOWN": "{count} nya enheter markerades som kända.",
        "FLASH_NO_NEW_DEVICES": "Inga nya enheter att markera.",
        "FLASH_CANNOT_PING_OFFLINE": "Kan inte pinga en offline-enhet.",
        "FLASH_PING_OK": "Ping OK: {ip}",
        "FLASH_PING_FAIL": "Ping misslyckades: {ip}",
        "FLASH_PING_ERROR": "Fel vid ping: {error}",
        "FLASH_MANUAL_PING_IP_REQUIRED": "Ingen IP angiven.",
        "FLASH_MANUAL_PING_ERROR": "Fel vid ping av {ip}: {error}",
        "FLASH_DELETE_ADMIN_ONLY": "Endast admin kan ta bort enheter!",
        "FLASH_DEVICE_DELETED": "Enhet raderad!",
        "FLASH_DEVICE_NOT_FOUND": "Enheten kunde inte hittas.",
        "FLASH_USER_ADDED": "Användare tillagd!",
        "FLASH_USER_DELETED": "Användare raderad!",
        "FLASH_USER_DELETE_FAIL": "Kunde inte radera (user ej funnen eller är admin).",
        "FLASH_SUBNET_ADDED": "Subnät {cidr} tillagt!",
        "FLASH_SUBNET_EXISTS": "Subnät {cidr} finns redan!",
        "FLASH_SUBNET_NOT_FOUND": "Subnätet kunde inte hittas.",
        "FLASH_SUBNET_ID_INVALID": "Ogiltigt subnät-ID.",
        "FLASH_GUESSED_SUBNET_ADDED": "Gissat subnät {cidr} tillagt!",
        "FLASH_GUESSED_SUBNET_EXISTS": "Subnät {cidr} finns redan!",
        "FLASH_SUBNET_DELETED": "Subnät {cidr} raderat!",
        "FLASH_SCAN_INTERVAL_INVALID": "Skanningsintervall måste vara ett positivt heltal.",
        "FLASH_SETTINGS_UPDATED": "Inställningar uppdaterade!",
        "FLASH_CONFIG_SNAPSHOT_FILE_MISSING": "Ingen snapshot-fil vald.",
        "FLASH_CONFIG_SNAPSHOT_INVALID_JSON": "Ogiltig snapshot-fil (JSON kunde inte läsas).",
        "FLASH_CONFIG_SNAPSHOT_IMPORT_FAILED": "Kunde inte importera snapshot: {error}",
        "FLASH_CONFIG_SNAPSHOT_IMPORTED": "Inställnings-snapshot importerad.",
        "FLASH_CONFIG_SNAPSHOT_NOTHING_SELECTED": "Välj minst en del att importera.",
        "FLASH_CONFIG_SNAPSHOT_EXPORT_FAILED": "Kunde inte exportera snapshot: {error}",
        "FLASH_QUICK_TAGS_UPDATED": "Snabbtaggar uppdaterade!",
        "FLASH_DB_BACKUP_FAILED": "Kunde inte skapa databasbackup: {error}",
        "FLASH_AJAX_MARK_KNOWN_FAIL": "Kunde inte markera enheten som känd.",
        "FLASH_AJAX_SUBNET_ORDER_FAIL": "Kunde inte spara subnätsordning.",
        "FLASH_AJAX_SCAN_STATUS_FAIL": "Kunde inte hämta skanningsstatus. Uppdatera sidan.",

        "FLASH_MANUFACTURER_ADMIN_ONLY": "Endast admin kan ändra tillverkare!",
        "FLASH_MANUFACTURER_UPDATED": "Tillverkare uppdaterad!",
        "FLASH_QUICK_TAGS_ADMIN_ONLY": "Endast admin kan ändra snabbtaggar!",

        "CONFIG_SCAN_INTERVAL_HINT": "Ändras vid nästa skanning.",
        "ACTIVE_SCAN_INTERVAL_LABEL": "Aktivt intervall just nu:",
        "THEME_LABEL": "Tema",
        "SAVE_THEME": "Spara tema",
        "SCAN_UPDATE_AVAILABLE": "Ny skanning klar – uppdatera listan",
        "SCAN_UPDATE_BUTTON": "Uppdatera",
        "NO_MATCHING_DEVICES": "Inga matchande enheter",
        "TABLE_SUBNET": "Subnät",

        "CONFIG_SUBNET_LABEL_COL": "Namn (valfritt)",
        "CONFIG_SUBNET_LABEL_PLACEHOLDER": "t.ex. Hem, Gäst, Lab",
        "CONFIG_SUBNET_VIEW_MODE": "Visningsläge för subnät",
        "CONFIG_SUBNET_VIEW_MODE_COLUMN": "Kolumn i tabellen",
        "CONFIG_SUBNET_VIEW_MODE_GROUPED": "Gruppera per subnät",

        "SUBNET_GROUP_OTHERS": "Övriga",
        "CONFIG_SUBNET_VIEW_MODE_HINT": "Subnät visas bara om minst ett subnät har ett namn.",

        "ALERTS_TITLE": "Larm",
        "ALERTS_PROVIDER_LABEL": "Larmkanal",
        "ALERTS_PROVIDER_DISCORD": "Discord",
        "ALERTS_PROVIDER_TELEGRAM": "Telegram",
        "ALERTS_PROVIDER_SLACK": "Slack",
        "ALERTS_PROVIDER_EMAIL": "Email",
        "ALERTS_PROVIDER_TEAMS": "Teams",
        "ALERTS_PROVIDER_PUSHOVER": "Pushover",
        "ALERTS_PROVIDER_GOTIFY": "Gotify",
        "ALERTS_PROVIDER_CUSTOM": "Custom (Apprise URL)",
        "ALERTS_ENABLE_LABEL": "Aktivera larm",
        "ALERTS_DISCORD_WEBHOOK": "Discord webhook URL",
        "ALERTS_SLACK_WEBHOOK": "Slack webhook URL",
        "ALERTS_TEAMS_WEBHOOK": "Teams webhook URL",
        "ALERTS_TELEGRAM_BOT_TOKEN": "Telegram bot token",
        "ALERTS_TELEGRAM_CHAT_ID": "Telegram chat ID",
        "ALERTS_TELEGRAM_BOT_TOKEN_PLACEHOLDER": "123456:ABC-DEF...",
        "ALERTS_TELEGRAM_CHAT_ID_PLACEHOLDER": "t.ex. 123456789 eller -100...",
        "ALERTS_EMAIL_URL": "Email (Apprise URL)",
        "ALERTS_EMAIL_URL_PLACEHOLDER": "mailto://user:pass@host/?to=you@example.com",
        "ALERTS_PUSHOVER_USER": "Pushover user key",
        "ALERTS_PUSHOVER_TOKEN": "Pushover app token",
        "ALERTS_PUSHOVER_DEVICE": "Pushover device (valfritt)",
        "ALERTS_GOTIFY_HOST": "Gotify host",
        "ALERTS_GOTIFY_TOKEN": "Gotify app token",
        "ALERTS_GOTIFY_HTTPS": "Använd HTTPS",
        "ALERTS_CUSTOM_URL": "Apprise URL",
        "ALERTS_CUSTOM_URL_PLACEHOLDER": "t.ex. discord://..., tgram://..., gotify://...",
        "ALERTS_OFFLINE_THRESHOLD": "Larma om offline längre än (minuter)",
        "ALERTS_SCOPE_LABEL": "Larm-omfattning",
        "ALERTS_SCOPE_ALL": "Alla enheter",
        "ALERTS_SCOPE_SELECTED": "Endast valda enheter",
        "ALERTS_DEVICES_TITLE": "Välj enheter",
        "ALERTS_FILTER_PLACEHOLDER": "Filtrera på alias/MAC…",
        "ALERTS_ENABLE_ALL": "Aktivera för alla",
        "ALERTS_DISABLE_ALL": "Stäng av för alla",
        "ALERTS_TEST_BUTTON": "Skicka testlarm",
        "ALERTS_TEST_SENT": "Testlarm skickat!",
        "ALERTS_TEST_FAIL": "Kunde inte skicka testlarm: {error}",
        "ALERTS_COL_REPEAT": "Påminn",
        "ALERTS_COL_REPEAT_INTERVAL": "Påminn var (min)",
        "ALERTS_REPEAT_HINT": "Påminnelser är av som standard och gäller bara enheter där du aktivt slår på dem.",

        "DISPLAY_TIMEZONE_LABEL": "Tidszon (visning)",
        "DISPLAY_TIMEZONE_HINT": "Lämna tomt för serverns tidszon. Exempel: Europe/Stockholm",
        "ALERTS_NEW_DEVICE_SUBNET_HINT": "Lämna tomt för att behandla subnäts-larm som “alla subnät”. Om du väljer subnät triggar endast dessa larm för nya enheter.",
        "ALERTS_SHOW": "Visa",
        "ALERTS_HIDE": "Dölj",
        "ALERTS_COL_ON": "På",
        "THEME_DEFAULT": "Standard",
        "THEME_DARK": "Mörkt",
        "THEME_LIGHT": "Ljust",
        "THEME_COSMOS": "Cosmos",
        "THEME_UPLINK": "Uplink",
        "ALERTS_DISCORD_WEBHOOK_PLACEHOLDER": "https://discord.com/api/webhooks/...",
        "ALERTS_NEW_DEVICE_TITLE": "Nya enheter",
        "ALERTS_NEW_DEVICE_OFF": "Av",
        "ALERTS_NEW_DEVICE_GLOBAL": "Globalt (endast helt ny enhet)",
        "ALERTS_NEW_DEVICE_SUBNETS": "Endast valda subnät",
        "ALERTS_NEW_DEVICE_BOTH": "Båda (globalt + subnät)",
        "ALERTS_NEW_DEVICE_HINT": "Globalt triggar bara när en enhet skapas första gången (ny MAC). Subnät triggar bara första gången en enhet syns i ett subnät.",
        "ALERTS_NEW_DEVICE_SUBNET_PICKER_TITLE": "Subnät som ska trigga subnäts-larm",
        "ALERT_NEW_DEVICE_GLOBAL_TITLE": "🆕 EggScan: Ny enhet upptäckt!",
        "ALERT_NEW_DEVICE_SUBNET_TITLE": "🆕 EggScan: Ny enhet i subnät!",
        "ALERT_LABEL_NAME": "Namn",
        "ALERT_LABEL_MAC": "MAC",
        "ALERT_LABEL_IP": "IP",
        "ALERT_LABEL_SUBNET": "Subnät",
        "QUIET_TITLE": "Tyst läge",
        "QUIET_ENABLE": "Aktivera tyst läge",
        "QUIET_START": "Starttid",
        "QUIET_END": "Sluttid",
        "QUIET_DAYS": "Dagar",
        "QUIET_DAY_MON": "Mån",
        "QUIET_DAY_TUE": "Tis",
        "QUIET_DAY_WED": "Ons",
        "QUIET_DAY_THU": "Tor",
        "QUIET_DAY_FRI": "Fre",
        "QUIET_DAY_SAT": "Lör",
        "QUIET_DAY_SUN": "Sön",
        "QUIET_WEEKDAYS": "Vardagar",
        "QUIET_WEEKENDS": "Helger",
        "QUIET_ALL_DAYS": "Alla dagar",
        "QUIET_HINT": "Larm under tyst läge skickas som sammanfattning när tyst läge slutar.",
        "QUIET_SUMMARY_TITLE": "⏱️ EggScan: Sammanfattning från tyst läge",
        "QUIET_SUMMARY_COUNTS": "Antal",
        "QUIET_SUMMARY_DEVICES": "Enheter",
        "QUIET_SUMMARY_WINDOW": "Period",
        "QUIET_SUMMARY_EVENTS": "Handelser",
        "ALERT_TYPE_OFFLINE": "Offline",
        "ALERT_TYPE_OFFLINE_REPEAT": "Offline-påminnelse",
        "ALERT_TYPE_ONLINE_BACK": "Online igen",
        "ALERT_TYPE_NEW_DEVICE": "Ny enhet",
        "ALERT_TYPE_NEW_DEVICE_SUBNET": "Ny enhet i subnät",
        "ALERT_TYPE_TEST": "Test",
        "ALERT_TYPE_UNKNOWN": "Larm",


        "DISPLAY_TIMEZONE_HINT_UI": "Sparade tider är UTC. Den här inställningen påverkar bara hur tider visas i gränssnittet.",
        "DISPLAY_TIMEZONE_PLACEHOLDER": "Börja skriva… (t.ex. Europe/Stockholm)",
    },

    "en": {
        "LANG_SV": "Swedish",
        "LANG_EN": "English",
        "LANGUAGE_LABEL": "Language",
        "SAVE": "Save",
        "BACK": "Back",
        "LOGOUT": "Log out",
        "CHANGE_PASSWORD": "Change password",
        "MANAGE_USERS": "Manage users",
        "SETTINGS": "Settings",
        "ABOUT": "About",
        "CONFIRM_DELETE": "Are you sure?",
        "YES": "Yes",
        "NO": "No",
        "VERSION_LABEL": "Version",
        "ABOUT_TITLE": "About EggScan",
        "ABOUT_CURRENT_VERSION": "Current version",
        "ABOUT_INSTALL_INFO": "Installation",
        "ABOUT_RUNTIME_INFO": "Runtime",
        "ABOUT_REPO": "GitHub repository",
        "ABOUT_INSTALL_DIR": "Install directory",
        "ABOUT_DATABASE": "Database",
        "ABOUT_DATABASE_SIZE": "Database size",
        "ABOUT_VERSION_FILE": "Version file",
        "ABOUT_WEB_USER": "Web process",
        "ABOUT_PYTHON": "Python",
        "ABOUT_SQLITE": "SQLite",
        "ABOUT_NOT_AVAILABLE": "Not available",
        "ABOUT_SERVICE_NOTE": "Updates run through the installer and systemd; admins can start them from here.",
        "ABOUT_UPDATE_TITLE": "Updates",
        "ABOUT_UPDATE_HINT": "Checks the latest published GitHub release.",
        "ABOUT_CHECK_UPDATES": "Check updates",
        "ABOUT_UPDATE_CHECKING": "Checking...",
        "ABOUT_UPDATE_CURRENT": "You are running the latest version.",
        "ABOUT_UPDATE_AVAILABLE": "New version available.",
        "ABOUT_UPDATE_UNKNOWN": "Version status could not be determined.",
        "ABOUT_UPDATE_ERROR": "Could not check updates right now.",
        "ABOUT_UPDATE_LATEST_VERSION": "Latest version",
        "ABOUT_UPDATE_RELEASE_LINK": "Open release",
        "ABOUT_UPDATE_LAST_CHECKED": "Last checked",
        "ABOUT_UPDATER_STATUS_TITLE": "Updater status",
        "ABOUT_UPDATER_STATUS_HINT": "Shows the latest status from the manual updater.",
        "ABOUT_UPDATER_REFRESH": "Refresh status",
        "ABOUT_UPDATER_START": "Start update",
        "ABOUT_UPDATER_STARTING": "Starting updater...",
        "ABOUT_UPDATER_STARTED": "Updater started. Follow the status below.",
        "ABOUT_UPDATER_RUNNING": "Updater is running. Status and log output refresh automatically.",
        "ABOUT_UPDATER_PLATFORM_NOTE": "The web updater supports Debian, Ubuntu and Raspberry Pi OS based systems with systemd.",
        "ABOUT_UPDATER_PLATFORM_UNSUPPORTED": "The web updater is disabled on this system.",
        "ABOUT_UPDATER_PLATFORM_DETECTED": "Detected system",
        "ABOUT_UPDATER_UNSUPPORTED_START": "The web updater is only available on Debian, Ubuntu and Raspberry Pi OS based systems with systemd.",
        "ABOUT_UPDATER_MODAL_TITLE": "Updating EggScan",
        "ABOUT_UPDATER_MODAL_CLOSE": "Close and reload",
        "ABOUT_UPDATER_MODAL_WAIT": "The button is enabled when the update is complete.",
        "ABOUT_UPDATER_START_ERROR": "Could not start the updater.",
        "ABOUT_UPDATER_CONFIRM": "Start update from the latest GitHub release?",
        "ABOUT_UPDATER_STATE": "Status",
        "ABOUT_UPDATER_MESSAGE": "Message",
        "ABOUT_UPDATER_UPDATED": "Updated",
        "ABOUT_UPDATER_PROGRESS": "Progress",
        "ABOUT_UPDATER_STEP_DOWNLOAD": "Download release",
        "ABOUT_UPDATER_STEP_VALIDATE": "Validate package",
        "ABOUT_UPDATER_STEP_INSTALL": "Run installer",
        "ABOUT_UPDATER_STEP_FINISH": "Finish update",
        "ABOUT_UPDATER_LOG": "Latest log",
        "ABOUT_UPDATER_HISTORY_HINT": "For previous updater run history, check",
        "ABOUT_UPDATER_NO_STATUS": "No updater status yet.",
        "ABOUT_UPDATER_LOG_EMPTY": "No updater log yet.",
        "ABOUT_UPDATER_ERROR": "Could not read updater status.",

        "INDEX_TITLE": "EggScan",
        "LOGGED_IN_AS": "Logged in as:",
        "MANUAL_PING_PLACEHOLDER": "Enter IP to test",
        "MANUAL_PING_BUTTON": "Test address",
        "FILTER_LABEL": "Filter:",
        "FILTER_BOTH": "Both",
        "FILTER_ONLINE": "Online only",
        "FILTER_OFFLINE": "Offline only",
        "TAG_FILTER_LABEL": "Tag filter:",
        "TAG_FILTER_ALL": "All",
        "QUICK_TAGS_ADMIN_LABEL": "Quick tags",
        "QUICK_TAGS_MANAGE": "Manage quick tags",
        "QUICK_TAGS_PLACEHOLDER": "Type a tag and press Enter",
        "QUICK_TAGS_HINT": "Add tags for quick filtering. Suggestions come from existing device tags.",
        "QUICK_TAGS_SAVE": "Save quick tags",
        "QUICK_TAGS_CONFIRM_REMOVE": "Do you want to remove quick tag \"{tag}\"?",
        "SEARCH_PLACEHOLDER": "Search IP/MAC/Alias/Tags",
        "SEARCH_FILTER_BUTTON": "Search/Filter",
        "SORT_LABEL": "Sort:",
        "SORT_IP": "IP",
        "SORT_MAC": "MAC",
        "SORT_ALIAS": "Alias",
        "SORT_MANUFACTURER": "Manufacturer",
        "SORT_UPDATED": "Updated",
        "SCAN_NOW": "Scan now",
        "BACKUP_DB": "Backup database",
        "CONFIG_SNAPSHOT_TITLE": "Config snapshot",
        "CONFIG_SNAPSHOT_HINT": "Export/import configuration only (not the full database).",
        "CONFIG_SNAPSHOT_SAVES": "Saved: settings, notification config, quiet hours, theme/language, subnets, and quick tags.",
        "CONFIG_SNAPSHOT_NOT_SAVED": "Not saved: users, devices, device history, alert history, and scan runtime status.",
        "CONFIG_SNAPSHOT_EXPORT_OPTIONS": "Choose what to include in the snapshot:",
        "CONFIG_SNAPSHOT_IMPORT_OPTIONS": "Import selected parts:",
        "CONFIG_SNAPSHOT_IMPORT_NOTE": "Import follows whatever is included in the snapshot file.",
        "CONFIG_SNAPSHOT_OPT_GENERAL": "General settings",
        "CONFIG_SNAPSHOT_OPT_NOTIFICATIONS": "Notification settings",
        "CONFIG_SNAPSHOT_OPT_QUIET_HOURS": "Quiet hours",
        "CONFIG_SNAPSHOT_OPT_THEME_LANG": "Theme / language / timezone",
        "CONFIG_SNAPSHOT_OPT_QUICK_TAGS": "Quick tags",
        "CONFIG_SNAPSHOT_OPT_SUBNETS": "Subnets and labels",
        "CONFIG_SNAPSHOT_EXPORT": "Export snapshot",
        "CONFIG_SNAPSHOT_IMPORT": "Import snapshot",
        "CONFIG_SNAPSHOT_FILE_LABEL": "Snapshot file (.json)",
        "SCAN_RUNNING": "Scanning in progress…",
        "TABLE_IP": "IP",
        "TABLE_MAC": "MAC",
        "TABLE_ALIAS": "Alias",
        "TABLE_PING": "Ping",
        "TABLE_MANUFACTURER": "Manufacturer",
        "TABLE_LAST_SEEN": "Last seen",
        "TABLE_STATUS": "Status",
        "TABLE_ACTIONS": "Actions",
        "ALIAS_NONE": "No alias",
        "MANUFACTURER_UNKNOWN": "Unknown",
        "MARK_KNOWN": "Mark as known",
        "MARK_ALL_NEW_KNOWN": "Mark all new as known",
        "DEVICE_KNOWN": "Known",
        "NEW_DEVICES_MODAL_TITLE": "New devices",
        "NEW_DEVICES_MODAL_EMPTY": "No new devices.",
        "DELETE": "Delete",
        "ALIAS_MODAL_TITLE": "Update Alias",
        "ALIAS_LABEL": "Alias",
        "ALIAS_DETAILS_LABEL": "Details",
        "ALIAS_DETAILS_PLACEHOLDER": "Optional notes about this device...",
        "ALIAS_TAGS_LABEL": "Tags",
        "ALIAS_TAGS_PLACEHOLDER": "e.g. camera, iot, guest",
        "ALIAS_TAGS_HINT": "Separate multiple tags with commas.",
        "CANCEL": "Cancel",
        "ALIAS_SAVE": "Save",

        "STATS_ONLINE_TOTAL_LABEL": "Online out of total",
        "STATS_NEW_DEVICES_LABEL": "New devices",
        "STATUSBAR_ONLINE": "Online",
        "STATUSBAR_OFFLINE": "Offline",
        "STATUSBAR_TOTAL": "Total",
        "STATUSBAR_NEW": "New devices",
        "STATUSBAR_LAST_SCAN": "Last scan",
        "STATUSBAR_IPV6": "IPv6",
        "STATUSBAR_ON": "On",
        "STATUSBAR_OFF": "Off",

        "MANUFACTURER_MODAL_TITLE": "Update manufacturer",
        "MANUFACTURER_LABEL": "Manufacturer",
        "MANUFACTURER_SAVE": "Save",

        "SETUP_TITLE": "Setup Admin",
        "SETUP_USERNAME": "Username",
        "SETUP_PASSWORD": "Password",
        "SETUP_CREATE_ADMIN": "Create Admin",

        "LOGIN_TITLE": "Log in",
        "LOGIN_BUTTON": "Log in",
        "LOGIN_USERNAME": "Username",
        "LOGIN_PASSWORD": "Password",

        "CHANGE_PASSWORD_TITLE": "Change password",
        "CHANGE_PASSWORD_NEW": "New password",
        "CHANGE_PASSWORD_UPDATE": "Update password",

        "MANAGE_USERS_TITLE": "Manage Users",
        "MANAGE_USERS_ADD_TITLE": "Add user",
        "MANAGE_USERS_USERNAME": "Username",
        "MANAGE_USERS_PASSWORD": "Password",
        "MANAGE_USERS_ADD_BUTTON": "Add",
        "MANAGE_USERS_EXISTING": "Existing users",
        "MANAGE_USERS_ID": "ID",
        "MANAGE_USERS_IS_ADMIN": "Admin?",
        "MANAGE_USERS_ACTION": "Action",
        "MANAGE_USERS_DELETE_BUTTON": "Delete",
        "MANAGE_USERS_ADMIN_LABEL": "Yes",
        "MANAGE_USERS_NOT_ADMIN_LABEL": "No",
        "MANAGE_USERS_ADMIN_TAG": "(Admin)",

        "CONFIG_TITLE": "Network settings",
        "CONFIG_ADD_SUBNET_LABEL": "Add subnet (e.g. 192.168.0.0/24):",
        "CONFIG_ADD_SUBNET_BUTTON": "Add",
        "CONFIG_SUBNET_COL": "Subnet",
        "CONFIG_SUBNET_DELETE_COL": "Delete",
        "CONFIG_SUBNET_DELETE_BUTTON": "Delete",
        "CONFIG_GUESS_BUTTON": "Guess my IPv4 range",
        "CONFIG_OTHER_SETTINGS": "Other settings",
        "SETTINGS_SEARCH_LABEL": "Search settings",
        "SETTINGS_SEARCH_PLACEHOLDER": "Search e.g. language, alerts, theme, subnet...",
        "SETTINGS_SEARCH_HINT": "Shows whole matching sections. Clear the search to show everything again.",
        "SETTINGS_SEARCH_CLEAR": "Clear",
        "SETTINGS_SEARCH_NO_RESULTS": "No settings match the search.",
        "CONFIG_IPV6_ENABLE": "Enable IPv6 discovery",
        "CONFIG_SCAN_INTERVAL": "Scan interval (minutes):",
        "CONFIG_HIGHLIGHT_NEW": "New/unknown devices blink",
        "CONFIG_IPV6_UTILS": "IPv6 interface (e.g. eth0):",
        "CONFIG_SAVE_BUTTON": "Save",

        "FLASH_SETUP_USER_PASS_REQUIRED": "Username and password are required.",
        "FLASH_SETUP_ADMIN_CREATED": "Admin account created! Please log in.",
        "FLASH_LOGIN_OK": "You have logged in!",
        "FLASH_LOGIN_FAIL": "Incorrect username or password.",
        "FLASH_LOGOUT": "You have logged out.",
        "FLASH_PASSWORD_REQUIRED": "New password is required.",
        "FLASH_PASSWORD_UPDATED": "Password has been updated!",
        "FLASH_ALIAS_ADMIN_ONLY": "Only admin can change aliases!",
        "FLASH_ALIAS_UPDATED": "Alias updated!",
        "FLASH_STATUS_ADMIN_ONLY": "Only admin can change status!",
        "FLASH_DEVICE_MARKED_KNOWN": "Device marked as known.",
        "FLASH_ALL_NEW_MARKED_KNOWN": "{count} new devices marked as known.",
        "FLASH_NO_NEW_DEVICES": "No new devices to mark.",
        "FLASH_CANNOT_PING_OFFLINE": "Cannot ping an offline device.",
        "FLASH_PING_OK": "Ping OK: {ip}",
        "FLASH_PING_FAIL": "Ping failed: {ip}",
        "FLASH_PING_ERROR": "Error while pinging: {error}",
        "FLASH_MANUAL_PING_IP_REQUIRED": "No IP address provided.",
        "FLASH_MANUAL_PING_ERROR": "Error while pinging {ip}: {error}",
        "FLASH_DELETE_ADMIN_ONLY": "Only admin can delete devices!",
        "FLASH_DEVICE_DELETED": "Device deleted!",
        "FLASH_DEVICE_NOT_FOUND": "Device could not be found.",
        "FLASH_USER_ADDED": "User added!",
        "FLASH_USER_DELETED": "User deleted!",
        "FLASH_USER_DELETE_FAIL": "Could not delete user (not found or is admin).",
        "FLASH_SUBNET_ADDED": "Subnet {cidr} added!",
        "FLASH_SUBNET_EXISTS": "Subnet {cidr} already exists!",
        "FLASH_SUBNET_DELETED": "Subnet {cidr} deleted!",
        "FLASH_SUBNET_NOT_FOUND": "Subnet could not be found.",
        "FLASH_SUBNET_ID_INVALID": "Invalid subnet ID.",
        "FLASH_GUESSED_SUBNET_ADDED": "Guessed subnet {cidr} added!",
        "FLASH_GUESSED_SUBNET_EXISTS": "Subnet {cidr} already exists!",
        "FLASH_SCAN_INTERVAL_INVALID": "Scan interval must be a positive integer.",
        "FLASH_SETTINGS_UPDATED": "Settings updated!",
        "FLASH_CONFIG_SNAPSHOT_FILE_MISSING": "No snapshot file selected.",
        "FLASH_CONFIG_SNAPSHOT_INVALID_JSON": "Invalid snapshot file (JSON could not be parsed).",
        "FLASH_CONFIG_SNAPSHOT_IMPORT_FAILED": "Could not import snapshot: {error}",
        "FLASH_CONFIG_SNAPSHOT_IMPORTED": "Config snapshot imported.",
        "FLASH_CONFIG_SNAPSHOT_NOTHING_SELECTED": "Select at least one part to import.",
        "FLASH_CONFIG_SNAPSHOT_EXPORT_FAILED": "Could not export snapshot: {error}",
        "FLASH_QUICK_TAGS_UPDATED": "Quick tags updated!",
        "FLASH_DB_BACKUP_FAILED": "Could not create database backup: {error}",
        "FLASH_AJAX_MARK_KNOWN_FAIL": "Could not mark device as known.",
        "FLASH_AJAX_SUBNET_ORDER_FAIL": "Could not save subnet order.",
        "FLASH_AJAX_SCAN_STATUS_FAIL": "Could not fetch scan status. Refresh the page.",

        "FLASH_MANUFACTURER_ADMIN_ONLY": "Only admin can change manufacturer!",
        "FLASH_MANUFACTURER_UPDATED": "Manufacturer updated!",
        "FLASH_QUICK_TAGS_ADMIN_ONLY": "Only admin can change quick tags!",

        "CONFIG_SCAN_INTERVAL_HINT": "Takes effect on next scan.",
        "ACTIVE_SCAN_INTERVAL_LABEL": "Active interval right now:",
        "THEME_LABEL": "Theme",
        "SAVE_THEME": "Save theme",
        "SCAN_UPDATE_AVAILABLE": "New scan finished – update the list",
        "SCAN_UPDATE_BUTTON": "Update",
        "NO_MATCHING_DEVICES": "No matching devices",
        "TABLE_SUBNET": "Subnet",

        "CONFIG_SUBNET_LABEL_COL": "Name (optional)",
        "CONFIG_SUBNET_LABEL_PLACEHOLDER": "e.g. Home, Guest, Lab",
        "CONFIG_SUBNET_VIEW_MODE": "Subnet display mode",
        "CONFIG_SUBNET_VIEW_MODE_COLUMN": "Column in table",
        "CONFIG_SUBNET_VIEW_MODE_GROUPED": "Group by subnet",

        "SUBNET_GROUP_OTHERS": "Others",
        "CONFIG_SUBNET_VIEW_MODE_HINT": "Subnets are only shown if at least one subnet has a name.",

        "ALERTS_TITLE": "Alerts",
        "ALERTS_PROVIDER_LABEL": "Alert provider",
        "ALERTS_PROVIDER_DISCORD": "Discord",
        "ALERTS_PROVIDER_TELEGRAM": "Telegram",
        "ALERTS_PROVIDER_SLACK": "Slack",
        "ALERTS_PROVIDER_EMAIL": "Email",
        "ALERTS_PROVIDER_TEAMS": "Teams",
        "ALERTS_PROVIDER_PUSHOVER": "Pushover",
        "ALERTS_PROVIDER_GOTIFY": "Gotify",
        "ALERTS_PROVIDER_CUSTOM": "Custom (Apprise URL)",
        "ALERTS_ENABLE_LABEL": "Enable alerts",
        "ALERTS_DISCORD_WEBHOOK": "Discord webhook URL",
        "ALERTS_SLACK_WEBHOOK": "Slack webhook URL",
        "ALERTS_TEAMS_WEBHOOK": "Teams webhook URL",
        "ALERTS_TELEGRAM_BOT_TOKEN": "Telegram bot token",
        "ALERTS_TELEGRAM_CHAT_ID": "Telegram chat ID",
        "ALERTS_TELEGRAM_BOT_TOKEN_PLACEHOLDER": "123456:ABC-DEF...",
        "ALERTS_TELEGRAM_CHAT_ID_PLACEHOLDER": "e.g. 123456789 or -100...",
        "ALERTS_EMAIL_URL": "Email (Apprise URL)",
        "ALERTS_EMAIL_URL_PLACEHOLDER": "mailto://user:pass@host/?to=you@example.com",
        "ALERTS_PUSHOVER_USER": "Pushover user key",
        "ALERTS_PUSHOVER_TOKEN": "Pushover app token",
        "ALERTS_PUSHOVER_DEVICE": "Pushover device (optional)",
        "ALERTS_GOTIFY_HOST": "Gotify host",
        "ALERTS_GOTIFY_TOKEN": "Gotify app token",
        "ALERTS_GOTIFY_HTTPS": "Use HTTPS",
        "ALERTS_CUSTOM_URL": "Apprise URL",
        "ALERTS_CUSTOM_URL_PLACEHOLDER": "e.g. discord://..., tgram://..., gotify://...",
        "ALERTS_OFFLINE_THRESHOLD": "Alert if offline longer than (minutes)",
        "ALERTS_SCOPE_LABEL": "Alert scope",
        "ALERTS_SCOPE_ALL": "All devices",
        "ALERTS_SCOPE_SELECTED": "Only selected devices",
        "ALERTS_DEVICES_TITLE": "Select devices",
        "ALERTS_FILTER_PLACEHOLDER": "Filter by alias/MAC…",
        "ALERTS_ENABLE_ALL": "Enable for all",
        "ALERTS_DISABLE_ALL": "Disable for all",
        "ALERTS_TEST_BUTTON": "Send test alert",
        "ALERTS_TEST_SENT": "Test alert sent!",
        "ALERTS_TEST_FAIL": "Could not send test alert: {error}",
        "ALERTS_COL_REPEAT": "Remind",
        "ALERTS_COL_REPEAT_INTERVAL": "Remind every (min)",
        "ALERTS_REPEAT_HINT": "Reminders are off by default and only apply to devices where you explicitly enable them.",
        "ALERTS_NEW_DEVICE_SUBNET_HINT": "Leave empty to treat subnet alerts as “all subnets”. If you select subnets, only those will trigger new-device alerts.",
        "ALERTS_NEW_DEVICE_TITLE": "New devices",
        "ALERTS_NEW_DEVICE_OFF": "Off",
        "ALERTS_NEW_DEVICE_GLOBAL": "Global (only brand new device)",
        "ALERTS_NEW_DEVICE_SUBNETS": "Selected subnets only",
        "ALERTS_NEW_DEVICE_BOTH": "Both (global + subnets)",
        "ALERTS_NEW_DEVICE_HINT": "Global triggers only when a device is first created (new MAC). Subnet triggers only the first time a device is seen in that subnet.",
        "ALERTS_NEW_DEVICE_SUBNET_PICKER_TITLE": "Subnets used for subnet alerts",
        "ALERTS_SHOW": "Show",
        "ALERTS_HIDE": "Hide",
        "ALERTS_COL_ON": "On",
        "THEME_DEFAULT": "Default",
        "THEME_DARK": "Dark",
        "THEME_LIGHT": "Light",
        "THEME_COSMOS": "Cosmos",
        "THEME_UPLINK": "Uplink",
        "ALERTS_DISCORD_WEBHOOK_PLACEHOLDER": "https://discord.com/api/webhooks/...",
        "ALERT_NEW_DEVICE_GLOBAL_TITLE": "🆕 EggScan: New device detected!",
        "ALERT_NEW_DEVICE_SUBNET_TITLE": "🆕 EggScan: New device in subnet!",
        "ALERT_LABEL_NAME": "Name",
        "ALERT_LABEL_MAC": "MAC",
        "ALERT_LABEL_IP": "IP",
        "ALERT_LABEL_SUBNET": "Subnet",
        "QUIET_TITLE": "Quiet hours",
        "QUIET_ENABLE": "Enable quiet hours",
        "QUIET_START": "Start time",
        "QUIET_END": "End time",
        "QUIET_DAYS": "Days",
        "QUIET_DAY_MON": "Mon",
        "QUIET_DAY_TUE": "Tue",
        "QUIET_DAY_WED": "Wed",
        "QUIET_DAY_THU": "Thu",
        "QUIET_DAY_FRI": "Fri",
        "QUIET_DAY_SAT": "Sat",
        "QUIET_DAY_SUN": "Sun",
        "QUIET_WEEKDAYS": "Weekdays",
        "QUIET_WEEKENDS": "Weekends",
        "QUIET_ALL_DAYS": "All days",
        "QUIET_HINT": "Alerts during quiet hours are sent as a summary when quiet hours end.",
        "QUIET_SUMMARY_TITLE": "⏱️ EggScan: Quiet hours summary",
        "QUIET_SUMMARY_COUNTS": "Counts",
        "QUIET_SUMMARY_DEVICES": "Devices",
        "QUIET_SUMMARY_WINDOW": "Window",
        "QUIET_SUMMARY_EVENTS": "Events",
        "ALERT_TYPE_OFFLINE": "Offline",
        "ALERT_TYPE_OFFLINE_REPEAT": "Offline reminder",
        "ALERT_TYPE_ONLINE_BACK": "Back online",
        "ALERT_TYPE_NEW_DEVICE": "New device",
        "ALERT_TYPE_NEW_DEVICE_SUBNET": "New device in subnet",
        "ALERT_TYPE_TEST": "Test",
        "ALERT_TYPE_UNKNOWN": "Alert",

        "DISPLAY_TIMEZONE_HINT_UI": "Stored timestamps are UTC. This setting only controls how times are shown in the UI.",
        "DISPLAY_TIMEZONE_PLACEHOLDER": "Start typing… (e.g. Europe/Stockholm)",

        "DISPLAY_TIMEZONE_LABEL": "Timezone (display)",
        "DISPLAY_TIMEZONE_HINT": "Leave empty for server timezone. Example: Europe/Stockholm",
    },
}


def get_setting(key, default_value=None):
    s = Settings.query.filter_by(key=key).first()
    return s.value if s else default_value


def set_setting(key, value):
    try:
        db.session.execute(text("PRAGMA busy_timeout=5000;"))
    except Exception:
        pass

    s = Settings.query.filter_by(key=key).first()
    if not s:
        s = Settings(key=key, value=value)
        db.session.add(s)
    else:
        s.value = value
    db.session.commit()

def _write_setting_in_current_transaction(key: str, value: str) -> None:
    result = db.session.execute(
        text("UPDATE settings SET value=:v WHERE key=:k;"),
        {"k": str(key), "v": str(value)}
    )
    if result.rowcount == 0:
        db.session.execute(
            text("INSERT INTO settings (key, value) VALUES (:k, :v);"),
            {"k": str(key), "v": str(value)}
        )


def set_settings_bulk(pairs: dict[str, str]) -> None:
    if not pairs:
        return

    with app.app_context():
        try:
            db.session.execute(text("BEGIN IMMEDIATE;"))
            for k, v in pairs.items():
                _write_setting_in_current_transaction(str(k), str(v))
            db.session.commit()
        except Exception as e:
            print("Settings bulk update error:", e)
            try:
                db.session.rollback()
            except Exception:
                pass

def get_bool_setting(key, default=False):
    v = get_setting(key, "true" if default else "false")
    return str(v).strip().lower() == "true"


def get_int_setting(key, default_value):
    v = str(get_setting(key, str(default_value))).strip()
    try:
        return int(v)
    except Exception:
        return int(default_value)


def get_alert_scope():
    scope = str(get_setting("alert_scope", "all")).strip().lower()
    if scope not in ("all", "selected"):
        scope = "all"
    return scope


def get_notify_provider() -> str:
    provider = str(get_setting("notify_provider", "")).strip().lower()
    if provider in ("discord", "telegram", "slack", "email", "teams", "pushover", "gotify", "custom"):
        return provider

    legacy_discord_enabled = (get_setting("discord_enabled", "false") == "true")
    if legacy_discord_enabled:
        return "discord"
    return "discord"


def get_notify_enabled() -> bool:
    raw = str(get_setting("notify_enabled", "")).strip().lower()
    if raw in ("true", "false"):
        return raw == "true"

    legacy_discord_enabled = (get_setting("discord_enabled", "false") == "true")
    return legacy_discord_enabled


def parse_time_str(value: str, default_value: str) -> str:
    raw = (value or "").strip()
    try:
        datetime.datetime.strptime(raw, "%H:%M")
        return raw
    except Exception:
        return default_value


def get_local_timezone():
    display_tz = get_display_timezone()
    if display_tz:
        try:
            return ZoneInfo(display_tz)
        except Exception:
            pass
    return datetime.datetime.now().astimezone().tzinfo


def get_quiet_settings():
    enabled = get_bool_setting("quiet_enabled", default=False)
    start_str = parse_time_str(str(get_setting("quiet_start", "22:00")), "22:00")
    end_str = parse_time_str(str(get_setting("quiet_end", "07:00")), "07:00")
    days_raw = str(get_setting("quiet_days", "0,1,2,3,4,5,6")).strip()
    days = set()
    for part in days_raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            v = int(part)
            if 0 <= v <= 6:
                days.add(v)
        except Exception:
            pass
    if not days:
        days = {0, 1, 2, 3, 4, 5, 6}
    return enabled, start_str, end_str, days


def is_quiet_now(now_local: datetime.datetime) -> bool:
    enabled, start_str, end_str, days = get_quiet_settings()
    if not enabled:
        return False

    try:
        start_t = datetime.datetime.strptime(start_str, "%H:%M").time()
        end_t = datetime.datetime.strptime(end_str, "%H:%M").time()
    except Exception:
        return False

    if start_t == end_t:
        return False

    weekday = now_local.weekday()
    prev_weekday = (weekday - 1) % 7
    now_t = now_local.time()

    if start_t < end_t:
        return (weekday in days) and (start_t <= now_t < end_t)

    return ((weekday in days) and (now_t >= start_t)) or ((prev_weekday in days) and (now_t < end_t))


def get_last_quiet_window(now_local: datetime.datetime):
    enabled, start_str, end_str, days = get_quiet_settings()
    if not enabled:
        return None

    try:
        start_t = datetime.datetime.strptime(start_str, "%H:%M").time()
        end_t = datetime.datetime.strptime(end_str, "%H:%M").time()
    except Exception:
        return None

    if start_t == end_t:
        return None

    best_start = None
    best_end = None

    for offset in range(0, 8):
        day = now_local.date() - datetime.timedelta(days=offset)
        if day.weekday() not in days:
            continue
        start_dt = datetime.datetime.combine(day, start_t, tzinfo=now_local.tzinfo)
        end_dt = datetime.datetime.combine(day, end_t, tzinfo=now_local.tzinfo)
        if end_dt <= start_dt:
            end_dt += datetime.timedelta(days=1)
        if end_dt <= now_local:
            if best_end is None or end_dt > best_end:
                best_start = start_dt
                best_end = end_dt

    if not best_start or not best_end:
        return None
    return best_start, best_end


def get_alert_type_label(alert_type: str) -> str:
    mapping = {
        "offline": "ALERT_TYPE_OFFLINE",
        "offline_repeat": "ALERT_TYPE_OFFLINE_REPEAT",
        "online_back": "ALERT_TYPE_ONLINE_BACK",
        "new_device": "ALERT_TYPE_NEW_DEVICE",
        "new_device_subnet": "ALERT_TYPE_NEW_DEVICE_SUBNET",
        "test": "ALERT_TYPE_TEST",
    }
    return t(mapping.get(alert_type, "ALERT_TYPE_UNKNOWN"))


def chunk_lines(lines: list[str], chunk_size: int) -> list[list[str]]:
    if chunk_size <= 0:
        return [lines]
    out = []
    for i in range(0, len(lines), chunk_size):
        out.append(lines[i:i + chunk_size])
    return out


def send_quiet_digest_if_needed():
    provider = get_notify_provider()
    enabled = get_notify_enabled()
    notify_url = get_notify_url()
    if not enabled or not notify_url:
        return

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    tz = get_local_timezone()
    now_local = now_utc.astimezone(tz)

    quiet_now = is_quiet_now(now_local)
    prev_state = str(get_setting("quiet_state", "open")).strip().lower()

    if quiet_now:
        if prev_state != "quiet":
            set_setting("quiet_state", "quiet")
        return

    if prev_state != "quiet":
        if prev_state != "open":
            set_setting("quiet_state", "open")
        return

    window = get_last_quiet_window(now_local)
    set_setting("quiet_state", "open")
    if not window:
        return

    start_local, end_local = window
    start_utc = start_local.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    end_utc = end_local.astimezone(datetime.timezone.utc).replace(tzinfo=None)

    last_end_raw = str(get_setting("quiet_last_end", "")).strip()
    if last_end_raw:
        try:
            last_end = datetime.datetime.fromisoformat(last_end_raw)
            if last_end >= end_utc:
                return
        except Exception:
            pass

    rows = (
        AlertLog.query
        .filter(AlertLog.status == "muted")
        .filter(AlertLog.created_at >= start_utc)
        .filter(AlertLog.created_at < end_utc)
        .order_by(AlertLog.created_at.asc())
        .all()
    )

    set_setting("quiet_last_end", end_utc.replace(microsecond=0).isoformat())

    if not rows:
        return

    counts = {}
    event_lines = []
    tz_name = get_display_timezone()
    for r in rows:
        counts[r.alert_type] = counts.get(r.alert_type, 0) + 1
        label = (r.device_label or r.mac_address or "-").strip()
        when_local = format_local(r.created_at, tz_name)
        type_label = get_alert_type_label(r.alert_type)
        event_lines.append(f"- [{when_local}] {type_label}: {label}")

    summary_lines = []
    for k in ("offline", "offline_repeat", "online_back", "new_device", "new_device_subnet", "test"):
        if k in counts:
            summary_lines.append(f"{get_alert_type_label(k)}: {counts[k]}")
    for k, v in counts.items():
        if k in ("offline", "offline_repeat", "online_back", "new_device", "new_device_subnet", "test"):
            continue
        summary_lines.append(f"{get_alert_type_label(k)}: {v}")

    start_local_text = start_local.strftime("%Y-%m-%d %H:%M")
    end_local_text = end_local.strftime("%Y-%m-%d %H:%M")
    msg = f"{t('QUIET_SUMMARY_TITLE')}\n"
    msg += f"{t('QUIET_SUMMARY_WINDOW')}: {start_local_text} -> {end_local_text}\n"
    if summary_lines:
        msg += f"{t('QUIET_SUMMARY_COUNTS')}: " + ", ".join(summary_lines) + "\n"
    if event_lines:
        msg += f"{t('QUIET_SUMMARY_EVENTS')}: {len(event_lines)}"

    event_chunks = chunk_lines(event_lines, 25)
    messages = [msg]
    if event_chunks:
        total_parts = len(event_chunks)
        for idx, chunk in enumerate(event_chunks, start=1):
            header = f"{t('QUIET_SUMMARY_EVENTS')} ({idx}/{total_parts})"
            messages.append(header + "\n" + "\n".join(chunk))

    try:
        for m in messages:
            send_apprise_notification(notify_url, m)
        log_alert("quiet_digest", provider, "sent", device=None, details={
            "count": len(rows),
            "start_utc": start_utc.replace(microsecond=0).isoformat(),
            "end_utc": end_utc.replace(microsecond=0).isoformat(),
            "parts": len(messages),
        })
    except Exception as e:
        err = str(e)
        try:
            log_alert("quiet_digest", provider, "failed", device=None, details={
                "count": len(rows),
                "start_utc": start_utc.replace(microsecond=0).isoformat(),
                "end_utc": end_utc.replace(microsecond=0).isoformat(),
                "parts": len(messages),
            }, error=err, dedupe_key=None)
        except Exception:
            db.session.rollback()
def get_language():
    lang = get_setting("language", "sv")
    if lang not in ("sv", "en"):
        lang = "sv"
    return lang


def get_theme():
    theme = get_setting("theme", "default")
    if not theme:
        theme = "default"

    allowed = {"default", "dark", "light", "cosmos", "uplink"}
    if theme not in allowed:
        theme = "default"

    return theme


def get_subnet_view_mode():
    mode = str(get_setting("subnet_view_mode", "column")).strip().lower()
    if mode not in ("column", "grouped"):
        mode = "column"
    return mode


def detect_os_timezone_name() -> str:
    tz = None

    
    try:
        r = subprocess.run(
            ["timedatectl", "show", "-p", "Timezone", "--value"],
            capture_output=True,
            text=True,
            timeout=2
        )
        if r.returncode == 0:
            v = (r.stdout or "").strip()
            if v:
                tz = v
    except Exception:
        tz = None

    
    if not tz:
        try:
            if os.path.exists("/etc/timezone"):
                with open("/etc/timezone", "r", encoding="utf-8") as f:
                    v = f.read().strip()
                    if v:
                        tz = v
        except Exception:
            tz = None

    
    if not tz:
        try:
            if os.path.exists("/etc/localtime"):
                target = os.path.realpath("/etc/localtime")
                marker = "/usr/share/zoneinfo/"
                if marker in target:
                    v = target.split(marker, 1)[1].strip()
                    if v:
                        tz = v
        except Exception:
            tz = None

    if not tz:
        tz = "UTC"

    try:
        ZoneInfo(tz)
        return tz
    except Exception:
        return "UTC"


def get_display_timezone() -> str:
    chosen = str(get_setting("display_timezone", "")).strip()
    if chosen:
        try:
            ZoneInfo(chosen)
            return chosen
        except Exception:
            pass
    return detect_os_timezone_name()





def ensure_utc(dt: Optional[datetime.datetime]) -> Optional[datetime.datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def format_local(dt_value: Optional[datetime.datetime], tz_name: str) -> str:
    if not isinstance(dt_value, datetime.datetime):
        return "-"


    dt_utc = dt_value.replace(tzinfo=datetime.timezone.utc)

    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = ZoneInfo("UTC")

    return dt_utc.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")

def t(key):
    lang = get_language()
    return TRANSLATIONS.get(lang, TRANSLATIONS["sv"]).get(key, key)


def tf(key, **kwargs):
    text_value = t(key)
    try:
        return text_value.format(**kwargs)
    except Exception:
        return text_value


def format_file_size(num_bytes: int) -> str:
    try:
        size = float(num_bytes)
    except Exception:
        return "-"

    units = ("B", "KB", "MB", "GB", "TB")
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024

    return f"{int(num_bytes)} B"


def get_process_identity_label() -> str:
    uid = os.geteuid()
    gid = os.getegid()
    try:
        user_name = pwd.getpwuid(uid).pw_name
    except Exception:
        user_name = str(uid)

    try:
        group_name = grp.getgrgid(gid).gr_name
    except Exception:
        group_name = str(gid)

    return f"{user_name}:{group_name}"


def parse_os_release(path: str = OS_RELEASE_FILE) -> dict:
    data = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if not raw or raw.startswith("#") or "=" not in raw:
                    continue
                key, value = raw.split("=", 1)
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]
                data[key.strip()] = value
    except Exception:
        return {}
    return data


def executable_exists(candidates: tuple[str, ...]) -> bool:
    return any(os.path.exists(path) and os.access(path, os.X_OK) for path in candidates)


def get_updater_platform_info() -> dict:
    os_release = parse_os_release()
    os_id = str(os_release.get("ID", "")).strip().lower()
    os_like = str(os_release.get("ID_LIKE", "")).strip().lower()
    os_family = {os_id} if os_id else set()
    os_family.update(part for part in os_like.replace(",", " ").split() if part)

    debian_based = bool({"debian", "ubuntu"} & os_family)
    systemctl_available = executable_exists(("/usr/bin/systemctl", "/bin/systemctl"))
    supported = debian_based and systemctl_available
    label = (
        str(os_release.get("PRETTY_NAME", "")).strip()
        or str(os_release.get("NAME", "")).strip()
        or os_id
        or "Unknown Linux"
    )

    return {
        "supported": supported,
        "debian_based": debian_based,
        "systemctl_available": systemctl_available,
        "label": label,
    }


def get_about_info() -> dict:
    db_exists = os.path.exists(DB_FILE)
    db_size = os.path.getsize(DB_FILE) if db_exists else None

    return {
        "version": APP_VERSION,
        "repo_url": GITHUB_REPO_URL,
        "install_dir": BASE_DIR,
        "db_file": DB_FILE,
        "db_size": format_file_size(db_size) if db_size is not None else "-",
        "version_file": VERSION_FILE,
        "updater_platform": get_updater_platform_info(),
        "process_identity": get_process_identity_label(),
        "python_version": sys.version.split()[0],
        "sqlite_version": sqlite3.sqlite_version,
    }


def normalize_release_version(value: str) -> str:
    raw = str(value or "").strip()
    if raw.startswith("refs/tags/"):
        raw = raw[len("refs/tags/"):]
    if len(raw) > 1 and raw[0].lower() == "v" and raw[1].isdigit():
        raw = raw[1:]
    return raw.strip()


def parse_release_version(value: str):
    normalized = normalize_release_version(value)
    if not normalized:
        return None

    main = normalized.split("+", 1)[0]
    release_part, _, suffix = main.partition("-")
    numbers = []
    for part in release_part.split("."):
        digits = []
        for ch in part:
            if ch.isdigit():
                digits.append(ch)
            else:
                break
        if not digits:
            return None
        numbers.append(int("".join(digits)))

    while len(numbers) < 4:
        numbers.append(0)
    numbers = numbers[:4]

    final_rank = 0 if suffix else 1
    return tuple(numbers + [final_rank, suffix])


def compare_release_versions(current_version: str, latest_version: str) -> Optional[int]:
    current_key = parse_release_version(current_version)
    latest_key = parse_release_version(latest_version)
    if current_key is None or latest_key is None:
        return None
    if latest_key > current_key:
        return 1
    if latest_key < current_key:
        return -1
    return 0


def fetch_latest_release_payload(force: bool = False) -> dict:
    now = utc_now()
    checked_at = _iso_utc(now)
    try:
        checked_at_local = format_local(now, get_display_timezone())
    except Exception:
        checked_at_local = checked_at
    cached_at = _UPDATE_CHECK_CACHE.get("checked_at")
    cached_payload = _UPDATE_CHECK_CACHE.get("payload")
    if (
        not force
        and isinstance(cached_at, datetime.datetime)
        and isinstance(cached_payload, dict)
        and (now - cached_at).total_seconds() < UPDATE_CHECK_CACHE_SECONDS
    ):
        payload = dict(cached_payload)
        payload["cached"] = True
        return payload

    req = urllib.request.Request(
        GITHUB_LATEST_RELEASE_API,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"EggScan/{APP_VERSION}",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=UPDATE_CHECK_TIMEOUT_SECONDS) as response:
            release_data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"GitHub returned HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(str(e.reason)) from e
    except Exception as e:
        raise RuntimeError(str(e)) from e

    latest_tag = str(release_data.get("tag_name", "")).strip()
    release_url = str(release_data.get("html_url", GITHUB_REPO_URL)).strip() or GITHUB_REPO_URL
    latest_version = normalize_release_version(latest_tag)
    current_version = normalize_release_version(APP_VERSION)
    comparison = compare_release_versions(current_version, latest_version)

    payload = {
        "ok": True,
        "current_version": current_version,
        "latest_version": latest_version or latest_tag,
        "latest_tag": latest_tag,
        "release_url": release_url,
        "checked_at_utc": checked_at,
        "checked_at_local": checked_at_local,
        "cached": False,
        "update_available": (comparison > 0) if comparison is not None else None,
    }

    _UPDATE_CHECK_CACHE["checked_at"] = now
    _UPDATE_CHECK_CACHE["payload"] = dict(payload)
    return payload


def format_updater_timestamp(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "-"

    try:
        iso_value = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        dt_value = datetime.datetime.fromisoformat(iso_value)
        if dt_value.tzinfo is not None:
            dt_value = dt_value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return format_local(dt_value, get_display_timezone())
    except Exception:
        return raw


def read_json_file_if_exists(path: str) -> Optional[dict]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else None


def tail_text_file(path: str, max_lines: int, max_bytes: int) -> list[str]:
    if not os.path.exists(path):
        return []

    file_size = os.path.getsize(path)
    with open(path, "rb") as f:
        if file_size > max_bytes:
            f.seek(file_size - max_bytes)
            f.readline()
        raw = f.read(max_bytes)

    text_value = raw.decode("utf-8", errors="replace")
    return text_value.splitlines()[-max_lines:]


def clean_legacy_updater_reload_hint(value: str, fallback: str = "Update complete") -> str:
    text_value = str(value or "")
    normalized = text_value.lower()
    if any(fragment in normalized for fragment in LEGACY_UPDATER_RELOAD_HINT_FRAGMENTS):
        return fallback
    return text_value


def get_updater_status_payload() -> dict:
    status = read_json_file_if_exists(UPDATE_STATUS_FILE)
    if status:
        updated_at_utc = str(status.get("updated_at_utc", "")).strip()
        status["updated_at_local"] = format_updater_timestamp(updated_at_utc)
        latest_version = str(status.get("latest_version", "")).strip()
        fallback_message = f"Update complete: EggScan {latest_version}" if latest_version else "Update complete"
        status["message"] = clean_legacy_updater_reload_hint(status.get("message", ""), fallback_message)

    return {
        "ok": True,
        "status": status,
        "log_lines": [
            clean_legacy_updater_reload_hint(line)
            for line in tail_text_file(UPDATE_LOG_FILE, UPDATE_LOG_TAIL_LINES, UPDATE_LOG_TAIL_BYTES)
        ],
    }


def first_executable_path(candidates: tuple[str, ...]) -> str:
    for path in candidates:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return candidates[0]


def start_updater_service() -> dict:
    if not get_updater_platform_info().get("supported"):
        raise RuntimeError("Web updater is not supported on this system.")

    sudo_path = first_executable_path(("/usr/bin/sudo", "/bin/sudo"))
    systemctl_path = first_executable_path(("/usr/bin/systemctl", "/bin/systemctl"))
    command = [
        sudo_path,
        "-n",
        systemctl_path,
        "--no-block",
        "start",
        UPDATER_SERVICE_NAME,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=UPDATER_START_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError("systemd did not accept the updater start request in time") from e

    if result.returncode != 0:
        output = (result.stderr or result.stdout or "").strip()
        if not output:
            output = f"sudo/systemctl exited with status {result.returncode}"
        raise RuntimeError(output)

    return {
        "service": UPDATER_SERVICE_NAME,
        "queued": True,
    }


# ---------------------------
#   HELPERS
# ---------------------------

def normalize_tags(raw_value: str) -> Optional[str]:
    raw_value = str(raw_value or "")
    tags = []
    seen = set()
    for part in raw_value.split(","):
        tag = " ".join(part.strip().split())
        if not tag:
            continue
        tag_lower = tag.lower()
        if tag_lower in seen:
            continue
        seen.add(tag_lower)
        tags.append(tag_lower)
    return ", ".join(tags) if tags else None


def parse_tags(raw_value: str) -> list[str]:
    normalized = normalize_tags(raw_value)
    if not normalized:
        return []
    return [p.strip() for p in normalized.split(",") if p.strip()]


SNAPSHOT_EXCLUDED_SETTING_KEYS = {
    "scan_status",
    "scan_lock_token",
    "scan_lock_until_utc",
    "scan_requested",
    "scan_request_id",
    "scan_request_at_utc",
    "last_scan_id",
    "last_scan_time_utc",
    "scan_interval_active",
    "quiet_state",
    "quiet_last_end",
}

SNAPSHOT_NOTIFICATION_SETTING_KEYS = {
    "notify_provider",
    "notify_enabled",
    "notify_url",
    "discord_webhook_url",
    "telegram_bot_token",
    "telegram_chat_id",
    "slack_webhook_url",
    "teams_webhook_url",
    "email_url",
    "pushover_user",
    "pushover_token",
    "pushover_device",
    "gotify_host",
    "gotify_token",
    "gotify_https",
    "custom_url",
    "alert_scope",
    "new_device_alert_mode",
    "new_device_alert_subnets",
    "offline_threshold_minutes",
}

SNAPSHOT_QUIET_SETTING_KEYS = {
    "quiet_enabled",
    "quiet_start",
    "quiet_end",
    "quiet_days",
}

SNAPSHOT_THEME_LANG_SETTING_KEYS = {
    "theme",
    "language",
    "display_timezone",
}

SNAPSHOT_QUICK_TAG_SETTING_KEYS = {
    "quick_filter_tags",
}

SNAPSHOT_CATEGORIZED_SETTING_KEYS = (
    SNAPSHOT_NOTIFICATION_SETTING_KEYS
    | SNAPSHOT_QUIET_SETTING_KEYS
    | SNAPSHOT_THEME_LANG_SETTING_KEYS
    | SNAPSHOT_QUICK_TAG_SETTING_KEYS
)


def build_config_snapshot(
    include_general: bool = True,
    include_notifications: bool = True,
    include_quiet_hours: bool = True,
    include_theme_lang: bool = True,
    include_quick_tags: bool = True,
    include_subnets: bool = True,
) -> dict:
    settings_map = {}
    rows = Settings.query.all()
    for row in rows:
        key = str(row.key or "").strip()
        if not key or key in SNAPSHOT_EXCLUDED_SETTING_KEYS:
            continue

        is_categorized = key in SNAPSHOT_CATEGORIZED_SETTING_KEYS
        include_key = False

        if key in SNAPSHOT_NOTIFICATION_SETTING_KEYS and include_notifications:
            include_key = True
        elif key in SNAPSHOT_QUIET_SETTING_KEYS and include_quiet_hours:
            include_key = True
        elif key in SNAPSHOT_THEME_LANG_SETTING_KEYS and include_theme_lang:
            include_key = True
        elif key in SNAPSHOT_QUICK_TAG_SETTING_KEYS and include_quick_tags:
            include_key = True
        elif include_general and not is_categorized:
            include_key = True

        if include_key:
            settings_map[key] = str(row.value or "")

    subnets_payload = []
    if include_subnets:
        for sn in SubNetwork.query.order_by(SubNetwork.sort_order.asc(), SubNetwork.id.asc()).all():
            subnets_payload.append({
                "cidr": str(sn.cidr or "").strip(),
                "label": str(sn.label or "").strip(),
                "sort_order": int(sn.sort_order or 0),
            })

    included_sections = []
    if include_general:
        included_sections.append("general")
    if include_notifications:
        included_sections.append("notifications")
    if include_quiet_hours:
        included_sections.append("quiet_hours")
    if include_theme_lang:
        included_sections.append("theme_lang")
    if include_quick_tags:
        included_sections.append("quick_tags")
    if include_subnets:
        included_sections.append("subnets")

    return {
        "format": "eggscan-config-snapshot",
        "format_version": 1,
        "app_version": APP_VERSION,
        "created_at_utc": _iso_utc(utc_now()),
        "included_sections": included_sections,
        "settings": settings_map,
        "subnets": subnets_payload,
    }

SCAN_LOCK_KEY = "scan_lock_token"
SCAN_LOCK_UNTIL_KEY = "scan_lock_until_utc"
SCAN_REQUEST_KEY = "scan_requested"
SCAN_REQUEST_ID_KEY = "scan_request_id"
SCAN_REQUEST_AT_KEY = "scan_request_at_utc"
NMAP_PING_ARGS = os.environ.get("EGGSCAN_NMAP_PING_ARGS", "-sn --privileged").strip() or "-sn --privileged"
NMAP_PING_FALLBACK_ARGS = "-sn"


def nmap_ping_scan(nm, hosts: str):
    try:
        return nm.scan(hosts=hosts, arguments=NMAP_PING_ARGS)
    except Exception as e:
        if NMAP_PING_ARGS != NMAP_PING_FALLBACK_ARGS:
            print(f"Nmap ping scan error for {hosts} with '{NMAP_PING_ARGS}': {e}; retrying with '{NMAP_PING_FALLBACK_ARGS}'")
            return nm.scan(hosts=hosts, arguments=NMAP_PING_FALLBACK_ARGS)
        raise


def _iso_utc(dt: datetime.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    dt = dt.astimezone(datetime.timezone.utc)
    return dt.replace(tzinfo=None, microsecond=0).isoformat()


def _parse_iso(dt_str: str) -> Optional[datetime.datetime]:
    dt_str = (dt_str or "").strip()
    if not dt_str:
        return None
    try:
        return datetime.datetime.fromisoformat(dt_str)
    except Exception:
        return None


def request_scan_now() -> str:
    rid = str(uuid.uuid4())
    set_setting(SCAN_REQUEST_KEY, "true")
    set_setting(SCAN_REQUEST_ID_KEY, rid)
    set_setting(SCAN_REQUEST_AT_KEY, _iso_utc(utc_now()))
    return rid


def clear_scan_request_if_matches(request_id: str) -> None:
    current = str(get_setting(SCAN_REQUEST_ID_KEY, "")).strip()
    if current and current == request_id:
        set_setting(SCAN_REQUEST_KEY, "false")


def is_scan_requested() -> Tuple[bool, str]:
    requested = str(get_setting(SCAN_REQUEST_KEY, "false")).strip().lower() == "true"
    rid = str(get_setting(SCAN_REQUEST_ID_KEY, "")).strip()
    return requested, rid


def acquire_scan_lock(ttl_seconds: int = 3600) -> Optional[str]:
    """
    Atomiskt DB-lås (SQLite) som funkar även om scan-worker råkar starta två gånger.
    Viktigt: INGA set_setting() här eftersom set_setting() committar.
    """
    token = str(uuid.uuid4())
    now = utc_now()
    until = now + datetime.timedelta(seconds=int(ttl_seconds))

    now_iso = _iso_utc(now)
    until_iso = _iso_utc(until)

    with app.app_context():
        try:
            db.session.execute(text("BEGIN IMMEDIATE;"))

            rows = db.session.execute(
                text("SELECT key, value FROM settings WHERE key IN (:k1, :k2);"),
                {"k1": SCAN_LOCK_KEY, "k2": SCAN_LOCK_UNTIL_KEY}
            ).fetchall()

            cur = {r[0]: (r[1] or "") for r in rows}
            cur_token = (cur.get(SCAN_LOCK_KEY, "") or "").strip()
            cur_until_str = (cur.get(SCAN_LOCK_UNTIL_KEY, "") or "").strip()
            cur_until = _parse_iso(cur_until_str)

            if cur_until and cur_until > now and cur_token:
                db.session.rollback()
                return None

            _write_setting_in_current_transaction(SCAN_LOCK_KEY, token)
            _write_setting_in_current_transaction(SCAN_LOCK_UNTIL_KEY, until_iso)

            db.session.commit()
            return token

        except Exception as e:
            print("Scan lock acquire error:", e)
            try:
                db.session.rollback()
            except Exception:
                pass
            return None


def release_scan_lock(token: str) -> None:
    token = (token or "").strip()
    if not token:
        return

    with app.app_context():
        try:
            db.session.execute(text("BEGIN IMMEDIATE;"))

            row = db.session.execute(
                text("SELECT value FROM settings WHERE key=:k LIMIT 1;"),
                {"k": SCAN_LOCK_KEY}
            ).fetchone()

            cur_token = (row[0] if row and row[0] else "").strip()

            if cur_token == token:
                _write_setting_in_current_transaction(SCAN_LOCK_KEY, "")
                _write_setting_in_current_transaction(SCAN_LOCK_UNTIL_KEY, "")

            db.session.commit()

        except Exception as e:
            print("Scan lock release error:", e)
            try:
                db.session.rollback()
            except Exception:
                pass


def get_effective_scan_status() -> str:
    status = str(get_setting("scan_status", "done")).strip().lower()
    if status != "running":
        return "done" if status not in ("done", "running") else status

    now = utc_now()
    lock_token = str(get_setting(SCAN_LOCK_KEY, "")).strip()
    lock_until = _parse_iso(str(get_setting(SCAN_LOCK_UNTIL_KEY, "")).strip())

    # If UI says running but lock is missing/expired, self-heal stale state.
    if not lock_token or not lock_until or lock_until <= now:
        set_settings_bulk({
            "scan_status": "done",
            SCAN_LOCK_KEY: "",
            SCAN_LOCK_UNTIL_KEY: "",
        })
        return "done"

    return "running"


def guess_network_range():
    try:
        result = subprocess.run(["ip", "route", "show", "default"],
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception("Could not read default route")
        default_line = result.stdout.strip().splitlines()[0]
        parts = default_line.split()
        default_if = parts[parts.index("dev") + 1]

        result = subprocess.run(["ip", "-o", "-f", "inet", "addr", "show", "dev", default_if],
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception("Could not read IP")
        line = result.stdout.strip().splitlines()[0]
        ip_with_prefix = line.split()[3]
        net = ipaddress.ip_network(ip_with_prefix, strict=False)
        return str(net)
    except Exception as e:
        print("Error in guess_network_range:", e)
        return "192.168.0.0/24"


def discover_ipv6_neighbors():
    mac_to_v6 = {}
    ipv6_utils = str(get_setting("ipv6_utils", "")).strip()

    if ipv6_utils:
        ping_cmd = ["ping", "-6", "-I", ipv6_utils, "ff02::1", "-c", "3"]
    else:
        ping_cmd = ["ping", "-6", "ff02::1", "-c", "3"]

    try:
        subprocess.run(ping_cmd, timeout=5, check=False)
    except Exception as e:
        print("Error ping6 ff02::1:", e)

    try:
        result = subprocess.run(["ip", "-6", "neighbor", "show"],
                                capture_output=True, text=True)
        lines = result.stdout.strip().splitlines()
        for line in lines:
            parts = line.split()
            if len(parts) >= 5 and parts[1] == "dev" and parts[3] == "lladdr":
                ipv6_addr = parts[0].lower()
                mac_addr = parts[4].lower()
                mac_to_v6.setdefault(mac_addr, [])
                if ipv6_addr not in mac_to_v6[mac_addr]:
                    mac_to_v6[mac_addr].append(ipv6_addr)
    except Exception as e:
        print("Error ip -6 neighbor show:", e)

    return mac_to_v6


def build_apprise_url(provider: str, fields: dict) -> str:
    provider = (provider or "").strip().lower()

    if provider == "discord":
        webhook = (fields.get("discord_webhook_url") or "").strip()
        return webhook

    if provider == "telegram":
        token = (fields.get("telegram_bot_token") or "").strip()
        chat_id = (fields.get("telegram_chat_id") or "").strip()
        if not token:
            return ""
        return f"tgram://{token}/{chat_id}" if chat_id else f"tgram://{token}/"

    if provider == "slack":
        webhook = (fields.get("slack_webhook_url") or "").strip()
        return webhook

    if provider == "teams":
        webhook = (fields.get("teams_webhook_url") or "").strip()
        return webhook

    if provider == "email":
        return (fields.get("email_url") or "").strip()

    if provider == "pushover":
        user_key = (fields.get("pushover_user") or "").strip()
        api_token = (fields.get("pushover_token") or "").strip()
        device = (fields.get("pushover_device") or "").strip()
        if not user_key or not api_token:
            return ""
        if device:
            device_path = "/".join([d.strip() for d in device.split(",") if d.strip()])
            return f"pover://{user_key}@{api_token}/{device_path}"
        return f"pover://{user_key}@{api_token}"

    if provider == "gotify":
        host = (fields.get("gotify_host") or "").strip()
        token = (fields.get("gotify_token") or "").strip()
        use_https = str(fields.get("gotify_https") or "true").strip().lower() == "true"
        if not host or not token:
            return ""
        host = host.replace("https://", "").replace("http://", "").strip()
        scheme = "gotifys" if use_https else "gotify"
        return f"{scheme}://{host.rstrip('/')}/{token}"

    if provider == "custom":
        return (fields.get("custom_url") or "").strip()

    return ""


def send_apprise_notification(url: str, content: str) -> None:
    url = (url or "").strip()
    if not url:
        raise Exception("Missing notification URL")

    apobj = apprise.Apprise()
    if not apobj.add(url):
        raise Exception("Invalid notification URL")

    ok = apobj.notify(body=content, title="EggScan")
    if not ok:
        raise Exception("Notification failed")


def get_notify_url() -> str:
    url = str(get_setting("notify_url", "")).strip()
    if url:
        return url

    legacy_enabled = (get_setting("discord_enabled", "false") == "true")
    legacy_webhook = str(get_setting("discord_webhook_url", "")).strip()
    if legacy_enabled and legacy_webhook:
        return legacy_webhook

    return ""


def device_display_name(dev: Device) -> str:
    if dev.alias and dev.alias.strip():
        return dev.alias.strip()
    if dev.mac_address and dev.mac_address.strip():
        return dev.mac_address.strip()
    return f"Device {dev.id}"


def get_alert_scope_all_or_selected() -> str:
    return get_alert_scope()


def get_new_device_alert_mode() -> str:
    mode = str(get_setting("new_device_alert_mode", "both")).strip().lower()
    if mode not in ("off", "global", "subnets", "both"):
        mode = "both"
    return mode


def get_new_device_alert_subnet_ids() -> set[int]:
    raw = str(get_setting("new_device_alert_subnets", "")).strip()
    if not raw:
        return set()
    out = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.add(int(part))
        except Exception:
            pass
    return out


def is_device_alert_enabled(dev: Device) -> bool:
    scope = get_alert_scope_all_or_selected()
    if scope == "all":
        return True

    row = DeviceAlert.query.filter_by(device_id=dev.id).first()
    return bool(row and row.enabled)


def get_device_threshold_minutes(dev: Device, default_minutes: int) -> int:
    row = DeviceAlert.query.filter_by(device_id=dev.id).first()
    if row and row.enabled and row.offline_threshold_minutes is not None:
        try:
            v = int(row.offline_threshold_minutes)
            return v if v > 0 else default_minutes
        except Exception:
            return default_minutes
    return default_minutes


def get_device_repeat_minutes(dev: Device) -> Optional[int]:
    row = DeviceAlert.query.filter_by(device_id=dev.id).first()
    if not row or not row.enabled or not row.repeat_enabled:
        return None

    try:
        v = int(row.repeat_interval_minutes or 0)
    except Exception:
        return None

    return v if v > 0 else None


def make_offline_dedupe_key(dev: Device) -> str:
    if dev.last_seen_at:
        ts = dev.last_seen_at.replace(microsecond=0).isoformat()
    else:
        ts = "unknown"
    return f"offline:{dev.id}:{ts}"


def make_offline_repeat_dedupe_key(
    offline_dedupe_key: str,
    offline_minutes: int,
    threshold_minutes: int,
    repeat_minutes: Optional[int]
) -> Optional[str]:
    if not repeat_minutes or repeat_minutes <= 0:
        return None

    minutes_since_initial_alert = offline_minutes - threshold_minutes
    if minutes_since_initial_alert < repeat_minutes:
        return None

    repeat_index = minutes_since_initial_alert // repeat_minutes
    if repeat_index <= 0:
        return None

    return f"{offline_dedupe_key}:repeat:{repeat_index}"


def make_online_recovery_dedupe_key(dev: Device, offline_dedupe_key: str) -> str:
    return f"online_back:{dev.id}:{offline_dedupe_key or 'unknown'}"


def make_new_device_dedupe_key(mac_lower: str) -> str:
    return f"new_device:{mac_lower}"


def make_new_device_subnet_dedupe_key(mac_lower: str, subnet_id: int) -> str:
    return f"new_device_subnet:{mac_lower}:{subnet_id}"


def log_alert(
    alert_type: str,
    sent_to: str,
    status: str,
    device: Device = None,
    details: dict = None,
    error: str = None,
    dedupe_key: str = None
):
    mac = None
    label = None
    did = None

    if device:
        did = device.id
        mac = (device.mac_address or "").strip().lower() if device.mac_address else None
        label = device_display_name(device)

    row = AlertLog(
        alert_type=alert_type,
        device_id=did,
        mac_address=mac,
        device_label=label,
        details_json=json.dumps(details or {}, ensure_ascii=False),
        sent_to=sent_to,
        status=status,
        error=error,
        dedupe_key=dedupe_key
    )
    db.session.add(row)
    db.session.commit()


def send_new_device_alert_if_enabled(dev: Device, subnet: Optional[SubNetwork]):
    provider = get_notify_provider()
    enabled = get_notify_enabled()
    notify_url = get_notify_url()
    if not enabled or not notify_url:
        return

    mode = get_new_device_alert_mode()
    if mode == "off":
        return

    mac_lower = (dev.mac_address or "").strip().lower()
    if not mac_lower:
        return

    now_utc = utc_now()

    # ---------- GLOBAL ----------
    if mode in ("global", "both"):
        dedupe_key = make_new_device_dedupe_key(mac_lower)

        already = AlertLog.query.filter_by(dedupe_key=dedupe_key).first()
        if not (already and already.status in ("sent", "muted")):
            subnet_label = "-"
            subnet_cidr = "-"
            if subnet:
                subnet_cidr = subnet.cidr or "-"
                subnet_label = (subnet.label.strip() if subnet.label and subnet.label.strip() else "-")
            msg = (
                f"{t('ALERT_NEW_DEVICE_GLOBAL_TITLE')}\n"
                f"{t('ALERT_LABEL_NAME')}: {device_display_name(dev)}\n"
                f"{t('ALERT_LABEL_MAC')}: {mac_lower}\n"
                f"{t('ALERT_LABEL_IP')}: {dev.ip_address or '-'}\n"
                f"{t('ALERT_LABEL_SUBNET')}: {subnet_label} ({subnet_cidr})"
)
           
            

            details = {
                "device_id": dev.id,
                "alias": dev.alias,
                "mac": mac_lower,
                "ip": dev.ip_address,
                "first_seen_at_utc": (dev.last_seen_at.replace(microsecond=0).isoformat() if dev.last_seen_at else None),
                "subnet_id": (subnet.id if subnet else None),
                "subnet_label": subnet_label,
                "subnet_cidr": subnet_cidr,
                "mode": mode,
                "created_at_utc": now_utc.replace(microsecond=0).isoformat(),
            }

            try:
                now_local = datetime.datetime.now(datetime.timezone.utc).astimezone(get_local_timezone())
                if is_quiet_now(now_local):
                    log_alert("new_device", provider, "muted", device=dev, details=details, error="quiet_hours", dedupe_key=dedupe_key)
                else:
                    send_apprise_notification(notify_url, msg)
                    log_alert("new_device", provider, "sent", device=dev, details=details, dedupe_key=dedupe_key)
            except Exception as e:
                err = str(e)
                try:
                    log_alert("new_device", provider, "failed", device=dev, details=details, error=err, dedupe_key=dedupe_key)
                except Exception:
                    db.session.rollback()

    # ---------- SUBNET ----------
    if mode in ("subnets", "both"):
        if not subnet:
            return

        allowed = get_new_device_alert_subnet_ids()
        if allowed and subnet.id not in allowed:
            return

        dedupe_key = make_new_device_subnet_dedupe_key(mac_lower, subnet.id)

        already = AlertLog.query.filter_by(dedupe_key=dedupe_key).first()
        if already and already.status in ("sent", "muted"):
            return

        subnet_label = (subnet.label.strip() if subnet.label and subnet.label.strip() else subnet.cidr)

        msg = (
            f"{t('ALERT_NEW_DEVICE_SUBNET_TITLE')}\n"
            f"{t('ALERT_LABEL_SUBNET')}: {subnet_label}\n"
            f"{t('ALERT_LABEL_NAME')}: {device_display_name(dev)}\n"
            f"{t('ALERT_LABEL_MAC')}: {mac_lower}\n"
            f"{t('ALERT_LABEL_IP')}: {dev.ip_address or '-'}"
        )       

        details = {
            "device_id": dev.id,
            "alias": dev.alias,
            "mac": mac_lower,
            "ip": dev.ip_address,
            "subnet_id": subnet.id,
            "subnet_label": (subnet.label.strip() if subnet.label and subnet.label.strip() else None),
            "subnet_cidr": subnet.cidr,
            "mode": mode,
            "created_at_utc": now_utc.replace(microsecond=0).isoformat(),
        }

        try:
            now_local = datetime.datetime.now(datetime.timezone.utc).astimezone(get_local_timezone())
            if is_quiet_now(now_local):
                log_alert("new_device_subnet", provider, "muted", device=dev, details=details, error="quiet_hours", dedupe_key=dedupe_key)
            else:
                send_apprise_notification(notify_url, msg)
                log_alert("new_device_subnet", provider, "sent", device=dev, details=details, dedupe_key=dedupe_key)
        except Exception as e:
            err = str(e)
            try:
                log_alert("new_device_subnet", provider, "failed", device=dev, details=details, error=err, dedupe_key=dedupe_key)
            except Exception:
                db.session.rollback()


def evaluate_offline_alerts(current_scan_id: str):
    provider = get_notify_provider()
    enabled = get_notify_enabled()
    notify_url = get_notify_url()
    if not enabled or not notify_url:
        return

    default_threshold = get_int_setting("offline_threshold_minutes", 60)
    if default_threshold <= 0:
        default_threshold = 60

    now_utc = utc_now()
    offline_devices = Device.query.filter(Device.last_seen_scan != current_scan_id).all()

    for dev in offline_devices:
        if not dev.last_seen_at:
            continue
        if not is_device_alert_enabled(dev):
            continue

        threshold = get_device_threshold_minutes(dev, default_threshold)
        if threshold <= 0:
            threshold = default_threshold

        offline_for = now_utc - dev.last_seen_at
        offline_minutes = int(offline_for.total_seconds() // 60)

        if offline_minutes < threshold:
            continue

        dedupe_key = make_offline_dedupe_key(dev)
        alert_type = "offline"
        repeat_minutes = get_device_repeat_minutes(dev)

        already = AlertLog.query.filter_by(dedupe_key=dedupe_key).first()
        if already:
            repeat_dedupe_key = make_offline_repeat_dedupe_key(
                dedupe_key,
                offline_minutes,
                threshold,
                repeat_minutes
            )
            if not repeat_dedupe_key:
                continue

            already_repeat = AlertLog.query.filter_by(dedupe_key=repeat_dedupe_key).first()
            if already_repeat:
                continue

            dedupe_key = repeat_dedupe_key
            alert_type = "offline_repeat"

        msg = f"🔴 EggScan alert: {device_display_name(dev)} is offline "

        details = {
            "device_id": dev.id,
            "alias": dev.alias,
            "mac": dev.mac_address,
            "ip": dev.ip_address,
            "last_seen_at_utc": dev.last_seen_at.replace(microsecond=0).isoformat() if dev.last_seen_at else None,
            "offline_minutes": offline_minutes,
            "threshold_minutes": threshold,
            "repeat_interval_minutes": repeat_minutes
        }

        try:
            now_local = datetime.datetime.now(datetime.timezone.utc).astimezone(get_local_timezone())
            if is_quiet_now(now_local):
                log_alert(alert_type, provider, "muted", device=dev, details=details, error="quiet_hours", dedupe_key=dedupe_key)
            else:
                send_apprise_notification(notify_url, msg)
                log_alert(alert_type, provider, "sent", device=dev, details=details, dedupe_key=dedupe_key)
        except Exception as e:
            err = str(e)
            try:
                log_alert(alert_type, provider, "failed", device=dev, details=details, error=err, dedupe_key=dedupe_key)
            except Exception:
                db.session.rollback()


def evaluate_online_recovery_alerts(current_scan_id: str):
    provider = get_notify_provider()
    enabled = get_notify_enabled()
    notify_url = get_notify_url()
    if not enabled or not notify_url:
        return

    now_utc = utc_now()
    online_devices = Device.query.filter(Device.last_seen_scan == current_scan_id).all()

    for dev in online_devices:
        if not is_device_alert_enabled(dev):
            continue

        last_offline = (
            AlertLog.query
            .filter(AlertLog.alert_type == "offline")
            .filter(AlertLog.device_id == dev.id)
            .order_by(AlertLog.created_at.desc())
            .first()
        )
        if not last_offline:
            continue

        offline_dedupe_key = last_offline.dedupe_key or ""
        online_dedupe_key = make_online_recovery_dedupe_key(dev, offline_dedupe_key)

        already = AlertLog.query.filter_by(dedupe_key=online_dedupe_key).first()
        if already:
            continue

        offline_start = None
        try:
            parts = offline_dedupe_key.split(":", 2)
            if len(parts) == 3:
                offline_start_str = parts[2]
                if offline_start_str != "unknown":
                    offline_start = datetime.datetime.fromisoformat(offline_start_str)
        except Exception:
            offline_start = None

        if offline_start is None:
            offline_start = last_offline.created_at

        offline_seconds = int((now_utc - offline_start).total_seconds())
        if offline_seconds < 0:
            offline_seconds = 0
        offline_minutes = offline_seconds // 60

        msg = f"🟢 EggScan alert: {device_display_name(dev)} is back online "

        details = {
            "device_id": dev.id,
            "alias": dev.alias,
            "mac": dev.mac_address,
            "ip": dev.ip_address,
            "back_online_at_utc": now_utc.replace(microsecond=0).isoformat(),
            "offline_start_utc": offline_start.replace(microsecond=0).isoformat() if offline_start else None,
            "offline_minutes_estimated": offline_minutes,
            "linked_offline_dedupe_key": offline_dedupe_key,
        }

        try:
            now_local = datetime.datetime.now(datetime.timezone.utc).astimezone(get_local_timezone())
            if is_quiet_now(now_local):
                log_alert(
                    "online_back",
                    provider,
                    "muted",
                    device=dev,
                    details=details,
                    error="quiet_hours",
                    dedupe_key=online_dedupe_key
                )
            else:
                send_apprise_notification(notify_url, msg)
                log_alert(
                    "online_back",
                    provider,
                    "sent",
                    device=dev,
                    details=details,
                    dedupe_key=online_dedupe_key
                )
        except Exception as e:
            err = str(e)
            try:
                log_alert(
                    "online_back",
                    provider,
                    "failed",
                    device=dev,
                    details=details,
                    error=err,
                    dedupe_key=online_dedupe_key
                )
            except Exception:
                db.session.rollback()


OFFLINE_VERIFY_MAX_IPS_PER_DEVICE = 3


def get_device_ipv4_candidates(dev: Device) -> list[str]:
    raw_value = str(dev.ip_address or "").strip()
    if not raw_value or raw_value == "-":
        return []

    ips = []
    seen = set()
    for part in raw_value.split(","):
        addr = part.strip()
        if not addr or addr == "-":
            continue

        try:
            ip_obj = ipaddress.ip_address(addr)
        except ValueError:
            continue

        if ip_obj.version != 4:
            continue

        normalized = str(ip_obj)
        if normalized in seen:
            continue

        seen.add(normalized)
        ips.append(normalized)
        if len(ips) >= OFFLINE_VERIFY_MAX_IPS_PER_DEVICE:
            break

    return ips


def build_ipv4_subnet_entries(subnets):
    entries = []
    for sn in subnets:
        cidr = str(sn.cidr or "").strip()
        if not cidr:
            continue

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue

        if network.version == 4:
            entries.append((sn, network))

    return entries


def find_subnet_for_ipv4(ip_addr: str, subnet_entries):
    try:
        ip_obj = ipaddress.ip_address(ip_addr)
    except ValueError:
        return None

    if ip_obj.version != 4:
        return None

    for sn, network in subnet_entries:
        if ip_obj in network:
            return sn

    return None


def find_scan_info_for_mac(scan_map: dict, mac_lower: str):
    for host, info in (scan_map or {}).items():
        addresses = (info.get("addresses", {}) or {})
        found_mac = str(addresses.get("mac") or "").strip().lower()
        if found_mac == mac_lower:
            return host, info

    return None, None


def get_vendor_for_mac(info: dict, mac_lower: str) -> Optional[str]:
    vendor_map = (info.get("vendor", {}) or {})
    for vendor_mac, vendor_name in vendor_map.items():
        if str(vendor_mac or "").strip().lower() == mac_lower and vendor_name:
            return str(vendor_name)

    return None


def verify_missing_known_devices(nm, current_scan_id: str, subnets, scan_ips_per_mac: dict[str, set[str]], seen_pairs: set[Tuple[int, Optional[int]]]) -> None:
    subnet_entries = build_ipv4_subnet_entries(subnets)
    candidates = Device.query.filter(Device.last_seen_scan != current_scan_id).all()

    for dev in candidates:
        mac_lower = str(dev.mac_address or "").strip().lower()
        if not mac_lower:
            continue

        for ip_addr in get_device_ipv4_candidates(dev):
            try:
                verify_output = nmap_ping_scan(nm, ip_addr)
                verify_map = verify_output.get("scan", {}) or {}
            except Exception as e:
                print(f"Offline verify scan error for {ip_addr}: {e}")
                continue

            _, info = find_scan_info_for_mac(verify_map, mac_lower)
            if not info:
                continue

            manufacturer = get_vendor_for_mac(info, mac_lower)
            if manufacturer:
                dev.manufacturer = manufacturer

            dev.last_seen_scan = current_scan_id
            dev.last_seen_at = utc_now()
            scan_ips_per_mac.setdefault(mac_lower, set()).add(ip_addr)

            sn = find_subnet_for_ipv4(ip_addr, subnet_entries)
            subnet_id = sn.id if sn else None
            if sn:
                dev.last_subnet_id = sn.id

            pair = (dev.id, subnet_id)
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                db.session.add(DeviceSubnetSeen(
                    scan_id=current_scan_id,
                    device_id=dev.id,
                    subnet_id=subnet_id,
                    seen_at=utc_now()
                ))

            break


def nmap_scan_and_save():
    with app.app_context():
        subnets = SubNetwork.query.order_by(SubNetwork.sort_order.asc(), SubNetwork.id.asc()).all()

        if not subnets:
            set_settings_bulk({
                "scan_status": "done",
            })
            return

        current_scan_id = str(uuid.uuid4())
        set_settings_bulk({
            "scan_status": "running",
            "last_scan_id": current_scan_id,
        })

        try:
            nm = nmap.PortScanner()
        except Exception as e:
            print("Nmap init error:", e)
            set_settings_bulk({
                "scan_status": "done",
            })
            return

        existing_devices = {((d.mac_address or "").lower()): d for d in Device.query.all() if d.mac_address}
        ipv6_enabled = (get_setting("ipv6_enabled", "false") == "true")

        scan_ips_per_mac: dict[str, set[str]] = {}
        seen_pairs: set[Tuple[int, Optional[int]]] = set()

        try:
            DeviceSubnetSeen.query.filter_by(scan_id=current_scan_id).delete()
            db.session.commit()
        except Exception:
            db.session.rollback()

        for sn in subnets:
            cidr = str(sn.cidr or "").strip()
            if not cidr:
                continue

            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if network.version != 4:
                    continue
            except Exception as e:
                print(f"Invalid CIDR {cidr}: {e}")
                continue

            try:
                scan_output = nmap_ping_scan(nm, cidr)
                scan_map = scan_output.get("scan", {}) or {}
            except Exception as e:
                print(f"Scan error for {cidr}: {e}")
                continue

            for host, info in scan_map.items():
                mac = (info.get("addresses", {}) or {}).get("mac", None)
                if not mac:
                    continue

                mac_lower = mac.lower()
                manufacturer = (info.get("vendor", {}) or {}).get(mac, None)

                scan_ips_per_mac.setdefault(mac_lower, set()).add(host)

                is_created_now = False
                if mac_lower in existing_devices:
                    dev = existing_devices[mac_lower]
                    if manufacturer:
                        dev.manufacturer = manufacturer
                    dev.last_seen_scan = current_scan_id
                    dev.last_seen_at = utc_now()
                else:
                    dev = Device(
                        ip_address=host,
                        mac_address=mac_lower,
                        manufacturer=manufacturer,
                        last_seen_scan=current_scan_id,
                        last_seen_at=utc_now(),
                        is_new=True,
                        last_subnet_id=None
                    )
                    db.session.add(dev)
                    db.session.flush()
                    existing_devices[mac_lower] = dev
                    is_created_now = True

                dev.last_subnet_id = sn.id

                pair = (dev.id, sn.id)
                if pair not in seen_pairs:
                    seen_pairs.add(pair)

                    existed_before = (
                        db.session.query(DeviceSubnetSeen.id)
                        .filter(DeviceSubnetSeen.device_id == dev.id, DeviceSubnetSeen.subnet_id == sn.id)
                        .first()
                        is not None
                    )

                    db.session.add(DeviceSubnetSeen(
                        scan_id=current_scan_id,
                        device_id=dev.id,
                        subnet_id=sn.id,
                        seen_at=utc_now()
                    ))

                    if is_created_now:
                        try:
                            send_new_device_alert_if_enabled(dev, sn)
                        except Exception as e:
                            print("New device alert error:", e)
                    elif not existed_before:
                        try:
                            send_new_device_alert_if_enabled(dev, sn)
                        except Exception as e:
                            print("New subnet device alert error:", e)

            try:
                db.session.commit()
            except Exception as e:
                print("DB commit error after subnet scan:", e)
                db.session.rollback()

        if ipv6_enabled:
            v6_map = discover_ipv6_neighbors()
            for mac_lower, ipv6_list in v6_map.items():
                if not ipv6_list:
                    continue

                scan_ips_per_mac.setdefault(mac_lower, set())
                for ip6 in ipv6_list:
                    scan_ips_per_mac[mac_lower].add(ip6)

                if mac_lower in existing_devices:
                    dev = existing_devices[mac_lower]
                    dev.last_seen_scan = current_scan_id
                    dev.last_seen_at = utc_now()
                else:
                    dev = Device(
                        ip_address=",".join(ipv6_list),
                        mac_address=mac_lower,
                        manufacturer=None,
                        last_seen_scan=current_scan_id,
                        last_seen_at=utc_now(),
                        is_new=True,
                        last_subnet_id=None
                    )
                    db.session.add(dev)
                    db.session.flush()
                    existing_devices[mac_lower] = dev

                    try:
                        send_new_device_alert_if_enabled(dev, None)
                    except Exception as e:
                        print("New device (ipv6) alert error:", e)

                pair = (dev.id, None)
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    db.session.add(DeviceSubnetSeen(
                        scan_id=current_scan_id,
                        device_id=dev.id,
                        subnet_id=None,
                        seen_at=utc_now()
                    ))

            try:
                db.session.commit()
            except Exception as e:
                print("DB commit error after ipv6:", e)
                db.session.rollback()

        verify_missing_known_devices(nm, current_scan_id, subnets, scan_ips_per_mac, seen_pairs)

        for mac_lower, dev in existing_devices.items():
            if dev.last_seen_scan == current_scan_id:
                addr_set = scan_ips_per_mac.get(mac_lower, set())
                if addr_set:
                    addr_list = sorted(addr_set)

                    ipv4_addrs = []
                    ipv6_addrs = []
                    for addr in addr_list:
                        try:
                            ip_obj = ipaddress.ip_address(addr)
                            if ip_obj.version == 4:
                                ipv4_addrs.append(addr)
                            else:
                                ipv6_addrs.append(addr)
                        except ValueError:
                            continue

                    ordered = ipv4_addrs + ipv6_addrs
                    dev.ip_address = ",".join(ordered) if ordered else "-"
                else:
                    dev.ip_address = "-"

        try:
            db.session.commit()
        except Exception as e:
            print("DB commit error updating ip list:", e)
            db.session.rollback()

        offline_devs = Device.query.filter(Device.last_seen_scan != current_scan_id).all()
        for d in offline_devs:
            d.ip_address = "-"

        try:
            db.session.commit()
        except Exception as e:
            print("DB commit error setting offline ip '-':", e)
            db.session.rollback()

        if not ipv6_enabled:
            all_devs = Device.query.all()
            for d in all_devs:
                if d.ip_address and d.ip_address != "-":
                    addresses = [x.strip() for x in d.ip_address.split(",") if x.strip()]
                    keep_only_v4 = []
                    for addr in addresses:
                        try:
                            ip_obj = ipaddress.ip_address(addr)
                            if ip_obj.version == 4:
                                keep_only_v4.append(addr)
                        except Exception:
                            pass
                    d.ip_address = ",".join(keep_only_v4) if keep_only_v4 else "-"
            try:
                db.session.commit()
            except Exception as e:
                print("DB commit error stripping ipv6:", e)
                db.session.rollback()

       

        try:
            evaluate_offline_alerts(current_scan_id)
            evaluate_online_recovery_alerts(current_scan_id)
            send_quiet_digest_if_needed()
        except Exception as e:
            print("Alert evaluation error:", e)
        finally:
            set_settings_bulk({
                "last_scan_time_utc": utc_now().replace(microsecond=0).isoformat(),
                "scan_status": "done",
            })

def run_scan_worker():
    """
    EN process ska köra detta (systemd eggscan-scan).
    - Periodisk scan enligt scan_interval
    - Scan-now requests från webben via Settings-flagga
    - Aldrig parallella scans (DB-lås)
    """
    # Worker restart should never leave stale "running" state in UI.
    with app.app_context():
        set_settings_bulk({
            "scan_status": "done",
            SCAN_LOCK_KEY: "",
            SCAN_LOCK_UNTIL_KEY: "",
        })

    next_run = utc_now()
    next_quiet_check = utc_now()
    quiet_check_interval_seconds = 15

    while True:
        with app.app_context():
            now = utc_now()
            if now >= next_quiet_check:
                try:
                    send_quiet_digest_if_needed()
                except Exception as e:
                    print("Quiet digest check error:", e)
                next_quiet_check = now + datetime.timedelta(seconds=quiet_check_interval_seconds)

            interval_str = str(get_setting("scan_interval", "5")).strip()
            try:
                interval_minutes = int(interval_str)
            except Exception:
                interval_minutes = 5
            if interval_minutes <= 0:
                interval_minutes = 5

            set_setting("scan_interval_active", str(interval_minutes))

            now = utc_now()
            requested, req_id = is_scan_requested()
            due = (now >= next_run)

            if not requested and not due:
                pass
            else:
                lock_token = acquire_scan_lock(ttl_seconds=max(60, interval_minutes * 60 + 600))
                if not lock_token:
                    # Någon annan scan pågår (eller låset sitter kvar). Vänta lite.
                    time.sleep(1)
                    continue

                try:
                    my_req_id = req_id if requested else ""

                    nmap_scan_and_save()

                    # Rensa request om den fortfarande är samma
                    if my_req_id:
                        clear_scan_request_if_matches(my_req_id)

                    # Nästa periodiska körning räknas från nu
                    next_run = utc_now() + datetime.timedelta(minutes=interval_minutes)

                finally:
                    try:
                        release_scan_lock(lock_token)
                    except Exception:
                        pass

        time.sleep(1)


@app.context_processor
def inject_globals():
    theme_value = "default"
    if has_request_context():
        try:
            if current_user.is_authenticated:
                theme_value = get_theme()
        except Exception:
            theme_value = "default"

    return {
        "t": t,
        "lang": get_language(),
        "version": APP_VERSION,
        "theme": theme_value,
    }


# ---------------------------
#          ROUTES
# ---------------------------

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if User.query.first():
        return redirect(url_for("login"))

    if request.method == "POST":
        language = request.form.get("language", "").strip()
        if language in ("sv", "en"):
            set_setting("language", language)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash(t("FLASH_SETUP_USER_PASS_REQUIRED"), "danger")
            return redirect(url_for("setup"))

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        admin_user = User(username=username, password=hashed_pw, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()

        flash(t("FLASH_SETUP_ADMIN_CREATED"), "success")
        return redirect(url_for("login"))

    lang = get_language()
    return render_template("setup.html", t=t, lang=lang, version=APP_VERSION, theme="default")


@app.route("/login", methods=["GET", "POST"])
def login():
    if User.query.count() == 0:
        return redirect(url_for("setup"))

    if request.method == "POST":
        language = request.form.get("language", "").strip()
        if language in ("sv", "en"):
            set_setting("language", language)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash(t("FLASH_LOGIN_OK"), "success")
            return redirect(url_for("index"))

        flash(t("FLASH_LOGIN_FAIL"), "danger")

    lang = get_language()
    return render_template("login.html", t=t, lang=lang, version=APP_VERSION, theme="default")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash(t("FLASH_LOGOUT"), "info")
    return redirect(url_for("login"))


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        new_password = request.form.get("password", "")
        if not new_password:
            flash(t("FLASH_PASSWORD_REQUIRED"), "danger")
            return redirect(url_for("change_password"))

        hashed_pw = bcrypt.generate_password_hash(new_password).decode("utf-8")
        current_user.password = hashed_pw
        db.session.commit()

        flash(t("FLASH_PASSWORD_UPDATED"), "success")
        return redirect(url_for("index"))

    lang = get_language()
    theme = get_theme()
    return render_template("change_password.html", t=t, lang=lang, version=APP_VERSION, theme=theme)


@app.route("/about", methods=["GET"])
@login_required
def about():
    lang = get_language()
    theme = get_theme()
    return render_template(
        "about.html",
        about_info=get_about_info(),
        t=t,
        lang=lang,
        version=APP_VERSION,
        theme=theme,
    )


@app.route("/api/update_check", methods=["GET"])
@login_required
def api_update_check():
    if not current_user.is_admin:
        abort(403)

    force = str(request.args.get("force", "")).strip().lower() in ("1", "true", "yes")
    try:
        return jsonify(fetch_latest_release_payload(force=force))
    except Exception as e:
        error_now = utc_now()
        error_checked_at = _iso_utc(error_now)
        try:
            error_checked_at_local = format_local(error_now, get_display_timezone())
        except Exception:
            error_checked_at_local = error_checked_at
        return jsonify({
            "ok": False,
            "error": str(e),
            "current_version": normalize_release_version(APP_VERSION),
            "repo_url": GITHUB_REPO_URL,
            "checked_at_utc": error_checked_at,
            "checked_at_local": error_checked_at_local,
        }), 502


@app.route("/api/updater_status", methods=["GET"])
@login_required
def api_updater_status():
    if not current_user.is_admin:
        abort(403)

    try:
        return jsonify(get_updater_status_payload())
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


@app.route("/api/updater_start", methods=["POST"])
@login_required
def api_updater_start():
    if not current_user.is_admin:
        abort(403)

    if not get_updater_platform_info().get("supported"):
        return jsonify({
            "ok": False,
            "error": t("ABOUT_UPDATER_UNSUPPORTED_START"),
        }), 400

    try:
        payload = start_updater_service()
        payload["ok"] = True
        return jsonify(payload)
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


@app.route("/")
@login_required
def index():
    scan_status = get_effective_scan_status()
    last_scan_id = get_setting("last_scan_id", "")
    highlight_new = (get_setting("highlight_new", "false") == "true")

    filter_mode = request.args.get("filter", "both")
    search_q = request.args.get("search", "").strip()
    sort_field = request.args.get("sort", "ip")
    sort_dir = request.args.get("dir", "asc")
    review_device_id = None
    review_device_id_raw = str(request.args.get("review_device_id", "")).strip()
    if review_device_id_raw:
        try:
            review_device_id = int(review_device_id_raw)
        except Exception:
            review_device_id = None

    q = Device.query

    if search_q:
        pattern = f"%{search_q}%"
        q = q.filter(
            db.or_(
                Device.ip_address.ilike(pattern),
                Device.mac_address.ilike(pattern),
                Device.alias.ilike(pattern),
                Device.manufacturer.ilike(pattern),
                Device.tags.ilike(pattern)
            )
        )

    if filter_mode in ("online", "offline") and last_scan_id:
        if filter_mode == "online":
            q = q.filter(Device.last_seen_scan == last_scan_id)
        else:
            q = q.filter(
                db.or_(
                    Device.last_seen_scan != last_scan_id,
                    Device.last_seen_scan.is_(None)
                )
            )

    devices = q.all()
    tag_rows = Device.query.with_entities(Device.tags).all()
    tag_set = set()
    for row in tag_rows:
        if not row or not row[0]:
            continue
        for tag in str(row[0]).split(","):
            tag = tag.strip()
            if not tag:
                continue
            tag_set.add(tag.lower())
    available_tags = sorted(tag_set)
    quick_filter_tags = parse_tags(get_setting("quick_filter_tags", ""))
    device_by_id = {d.id: d for d in devices}

    total_devices = len(devices)
    online_devices = 0
    new_devices = 0

    for dev in devices:
        if dev.last_seen_scan == last_scan_id:
            online_devices += 1
        if dev.is_new:
            new_devices += 1

    offline_devices = total_devices - online_devices

    subnets = SubNetwork.query.order_by(SubNetwork.sort_order.asc(), SubNetwork.id.asc()).all()
    subnet_map = {sn.id: (sn.label.strip() if sn.label and sn.label.strip() else "") for sn in subnets}

    has_named_subnets = any(bool(sn.label and sn.label.strip()) for sn in subnets)
    subnet_view_mode = get_subnet_view_mode()

    def none_str(x):
        return x if x else ""

    def ip_sort_tuple(dev: Device):
        if dev.ip_address == "-" or not dev.ip_address:
            return (999, ipaddress.ip_address("255.255.255.255"))
        first_ip = dev.ip_address.split(",")[0].strip()
        try:
            ip_obj = ipaddress.ip_address(first_ip)
            return (ip_obj.version, ip_obj)
        except Exception:
            return (999, ipaddress.ip_address("255.255.255.255"))

    def updated_key(d):
        return d.updated_at if d.updated_at else datetime.datetime(1970, 1, 1)

    def device_key_for_sort(d: Device):
        if sort_field == "ip":
            return ip_sort_tuple(d)
        if sort_field == "mac":
            return none_str(d.mac_address).lower()
        if sort_field == "alias":
            return none_str(d.alias).lower()
        if sort_field == "manufacturer":
            return none_str(d.manufacturer).lower()
        if sort_field == "updated":
            return updated_key(d)
        if sort_field == "subnet":
            if d.last_subnet_id and d.last_subnet_id in subnet_map:
                return (subnet_map[d.last_subnet_id] or "").lower()
            return ""
        return ip_sort_tuple(d)

    is_grouped_active = (
        has_named_subnets
        and subnet_view_mode == "grouped"
    )

    device_groups = []
    if is_grouped_active and last_scan_id:
        seen_rows = DeviceSubnetSeen.query.filter_by(scan_id=last_scan_id).all()
        seen_device_ids_per_subnet = {}
        all_grouped_device_ids = set()

        for r in seen_rows:
            if r.subnet_id is None:
                continue
            lbl = subnet_map.get(r.subnet_id, "").strip()
            if not lbl:
                continue
            seen_device_ids_per_subnet.setdefault(r.subnet_id, set()).add(r.device_id)

        reverse_rows = (sort_dir == "desc")

        for sn in subnets:
            lbl = (sn.label.strip() if sn.label and sn.label.strip() else "")
            if not lbl:
                continue
            dev_ids = seen_device_ids_per_subnet.get(sn.id, set())
            if not dev_ids:
                continue

            items = []
            for did in dev_ids:
                d = device_by_id.get(did)
                if d:
                    items.append(d)

            items.sort(key=device_key_for_sort, reverse=reverse_rows)
            if items:
                device_groups.append({"title": lbl, "devices": items})
                all_grouped_device_ids |= set([d.id for d in items])

        others = []
        for d in devices:
            if d.id not in all_grouped_device_ids:
                others.append(d)

        if others:
            others.sort(key=device_key_for_sort, reverse=reverse_rows)
            device_groups.append({"title": t("SUBNET_GROUP_OTHERS"), "devices": others})

    if sort_field == "subnet" and not is_grouped_active:
        def subnet_label_for_device(dev: Device) -> str:
            if dev.last_subnet_id and dev.last_subnet_id in subnet_map:
                return subnet_map[dev.last_subnet_id] or ""
            return ""

        devices.sort(
            key=lambda d: (subnet_label_for_device(d).lower(), ip_sort_tuple(d)),
            reverse=(sort_dir == "desc")
        )
        devices.sort(
            key=lambda d: 1 if subnet_label_for_device(d).strip() == "" else 0
        )

    elif is_grouped_active:
        pass
    else:
        reverse_rows = (sort_dir == "desc")
        devices.sort(key=device_key_for_sort, reverse=reverse_rows)

    if review_device_id is not None:
        review_device = Device.query.filter_by(id=review_device_id).first()
        if review_device is None:
            review_device_id = None

    new_device_review_devices = [
        dev for dev in devices
        if dev.is_new or (review_device_id is not None and dev.id == review_device_id)
    ]

    lang = get_language()
    theme = get_theme()
    display_tz = get_display_timezone()

    ipv6_enabled = (get_setting("ipv6_enabled", "false") == "true")

    last_scan_time_utc = str(get_setting("last_scan_time_utc", "")).strip()
    last_scan_time_local = "-"
    if last_scan_time_utc:
        try:
            dt_utc = datetime.datetime.fromisoformat(last_scan_time_utc)
            last_scan_time_local = format_local(dt_utc, display_tz)
        except Exception:
            last_scan_time_local = "-"

    configured_scan_interval = get_setting("scan_interval", "5")
    active_scan_interval = get_setting("scan_interval_active", configured_scan_interval)

    return render_template(
        "index.html",
        devices=devices,
        device_groups=device_groups,
        is_grouped_active=is_grouped_active,
        current_user=current_user,
        scan_status=scan_status,
        last_scan_id=last_scan_id,
        filter_mode=filter_mode,
        search_q=search_q,
        sort_field=sort_field,
        sort_dir=sort_dir,
        highlight_new=highlight_new,
        total_devices=total_devices,
        online_devices=online_devices,
        offline_devices=offline_devices,
        new_devices=new_devices,
        new_device_review_devices=new_device_review_devices,
        review_device_id=review_device_id,
        ipv6_enabled=ipv6_enabled,
        last_scan_time=last_scan_time_local,
        configured_scan_interval=configured_scan_interval,
        active_scan_interval=active_scan_interval,
        subnet_map=subnet_map,
        has_named_subnets=has_named_subnets,
        subnet_view_mode=subnet_view_mode,
        available_tags=available_tags,
        quick_filter_tags=quick_filter_tags,
        display_tz=display_tz,
        format_local=format_local,
        t=t,
        lang=lang,
        version=APP_VERSION,
        theme=theme
    )


@app.route("/scan_status", methods=["GET"])
def get_scan_status():
    status = get_effective_scan_status()
    return jsonify({"status": status})


@app.route("/force_scan", methods=["POST"])
@login_required
def force_scan():
    request_scan_now()
    return redirect(get_safe_next_url())


def get_safe_next_url(default_endpoint="index"):
    next_url = str(request.form.get("next", "")).strip()
    if next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return url_for(default_endpoint)


@app.route("/update_alias", methods=["POST"])
@login_required
def update_alias():
    if not current_user.is_admin:
        flash(t("FLASH_ALIAS_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))

    mac = request.form.get("mac", "").strip()
    alias = request.form.get("alias", "").strip()
    notes = request.form.get("notes", "").strip()
    tags = normalize_tags(request.form.get("tags", ""))

    if mac:
        mac_norm = mac.lower()
        dev = Device.query.filter(db.func.lower(Device.mac_address) == mac_norm).first()
        if dev:
            dev.alias = alias
            dev.notes = notes if notes else None
            dev.tags = tags
            if dev.is_new:
                dev.is_new = False
            db.session.commit()
            flash(t("FLASH_ALIAS_UPDATED"), "success")

    return redirect(get_safe_next_url())


@app.route("/update_quick_tags", methods=["POST"])
@login_required
def update_quick_tags():
    if not current_user.is_admin:
        flash(t("FLASH_QUICK_TAGS_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))

    raw_tags = request.form.get("quick_tags", "")
    normalized = normalize_tags(raw_tags) or ""
    set_setting("quick_filter_tags", normalized)
    flash(t("FLASH_QUICK_TAGS_UPDATED"), "success")
    return redirect(url_for("index"))


@app.route("/update_manufacturer", methods=["POST"])
@login_required
def update_manufacturer():
    if not current_user.is_admin:
        flash(t("FLASH_MANUFACTURER_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))

    mac = request.form.get("mac", "").strip()
    manufacturer = request.form.get("manufacturer", "").strip()

    if mac:
        mac_norm = mac.lower()
        dev = Device.query.filter(db.func.lower(Device.mac_address) == mac_norm).first()
        if dev:
            dev.manufacturer = manufacturer if manufacturer else None
            db.session.commit()
            flash(t("FLASH_MANUFACTURER_UPDATED"), "success")

    return redirect(get_safe_next_url())


@app.route("/mark_known/<int:device_id>", methods=["POST"])
@login_required
def mark_known(device_id):
    if not current_user.is_admin:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "admin_only"}), 403
        flash(t("FLASH_STATUS_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))

    dev = Device.query.get(device_id)
    if not dev:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "not_found"}), 404
        flash(t("FLASH_DEVICE_NOT_FOUND"), "warning")
        return redirect(url_for("index"))

    changed = False

    if dev.is_new:
        dev.is_new = False
        db.session.commit()
        changed = True

        if request.headers.get("X-Requested-With") != "XMLHttpRequest":
            flash(t("FLASH_DEVICE_MARKED_KNOWN"), "success")

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": True, "device_id": device_id, "changed": changed}), 200

    return redirect(url_for("index"))


@app.route("/mark_known_all", methods=["POST"])
@login_required
def mark_known_all():
    if not current_user.is_admin:
        flash(t("FLASH_STATUS_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))

    changed_count = (
        Device.query
        .filter(Device.is_new.is_(True))
        .update({Device.is_new: False}, synchronize_session=False)
    )
    db.session.commit()

    if changed_count > 0:
        flash(tf("FLASH_ALL_NEW_MARKED_KNOWN", count=changed_count), "success")
    else:
        flash(t("FLASH_NO_NEW_DEVICES"), "info")

    return redirect(url_for("index"))


@app.route("/backup_db", methods=["POST"])
@login_required
def backup_db():
    if not current_user.is_admin:
        flash(t("FLASH_STATUS_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))

    src_conn = None
    dst_conn = None
    temp_path = None

    try:
        fd, temp_path = tempfile.mkstemp(prefix="eggscan_backup_", suffix=".db")
        os.close(fd)

        src_conn = sqlite3.connect(f"file:{DB_FILE}?mode=ro", uri=True, timeout=30)
        dst_conn = sqlite3.connect(temp_path, timeout=30)
        src_conn.backup(dst_conn)
        dst_conn.commit()

        with open(temp_path, "rb") as f:
            payload = f.read()
    except Exception as e:
        flash(tf("FLASH_DB_BACKUP_FAILED", error=str(e)), "danger")
        return redirect(url_for("index"))
    finally:
        try:
            if dst_conn is not None:
                dst_conn.close()
        except Exception:
            pass
        try:
            if src_conn is not None:
                src_conn.close()
        except Exception:
            pass
        try:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass

    fname = f"eggscan_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    return send_file(
        io.BytesIO(payload),
        as_attachment=True,
        download_name=fname,
        mimetype="application/octet-stream"
    )


@app.route("/export_config_snapshot", methods=["POST"])
@login_required
def export_config_snapshot():
    if not current_user.is_admin:
        flash(t("FLASH_STATUS_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))

    include_general = (request.form.get("export_general") == "on")
    include_notifications = (request.form.get("export_notifications") == "on")
    include_quiet_hours = (request.form.get("export_quiet_hours") == "on")
    include_theme_lang = (request.form.get("export_theme_lang") == "on")
    include_quick_tags = (request.form.get("export_quick_tags") == "on")
    include_subnets = (request.form.get("export_subnets") == "on")

    if not any([include_general, include_notifications, include_quiet_hours, include_theme_lang, include_quick_tags, include_subnets]):
        flash(t("FLASH_CONFIG_SNAPSHOT_NOTHING_SELECTED"), "danger")
        return redirect(url_for("config_eggscan"))

    try:
        snapshot = build_config_snapshot(
            include_general=include_general,
            include_notifications=include_notifications,
            include_quiet_hours=include_quiet_hours,
            include_theme_lang=include_theme_lang,
            include_quick_tags=include_quick_tags,
            include_subnets=include_subnets,
        )
        payload = json.dumps(snapshot, indent=2, ensure_ascii=False).encode("utf-8")
    except Exception as e:
        flash(tf("FLASH_CONFIG_SNAPSHOT_EXPORT_FAILED", error=str(e)), "danger")
        return redirect(url_for("config_eggscan"))

    fname = f"eggscan_config_snapshot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return send_file(
        io.BytesIO(payload),
        as_attachment=True,
        download_name=fname,
        mimetype="application/json"
    )


@app.route("/import_config_snapshot", methods=["POST"])
@login_required
def import_config_snapshot():
    if not current_user.is_admin:
        flash(t("FLASH_STATUS_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))

    upload = request.files.get("snapshot_file")
    if upload is None or not str(upload.filename or "").strip():
        flash(t("FLASH_CONFIG_SNAPSHOT_FILE_MISSING"), "danger")
        return redirect(url_for("config_eggscan"))

    try:
        raw = upload.read()
        if not raw:
            raise ValueError("empty file")
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        flash(t("FLASH_CONFIG_SNAPSHOT_INVALID_JSON"), "danger")
        return redirect(url_for("config_eggscan"))

    try:
        if not isinstance(data, dict):
            raise ValueError("payload must be an object")

        settings_in = data.get("settings", {})
        subnets_in = data.get("subnets", [])
        included_sections_raw = data.get("included_sections", [])

        if not isinstance(settings_in, dict):
            raise ValueError("settings must be an object")
        if not isinstance(subnets_in, list):
            raise ValueError("subnets must be a list")

        sections = set()
        if isinstance(included_sections_raw, list):
            for part in included_sections_raw:
                v = str(part or "").strip().lower()
                if v:
                    sections.add(v)

        has_declared_sections = bool(sections)

        import_general = ("general" in sections) if has_declared_sections else bool(settings_in)
        import_notifications = ("notifications" in sections) if has_declared_sections else bool(settings_in)
        import_quiet_hours = ("quiet_hours" in sections) if has_declared_sections else bool(settings_in)
        import_theme_lang = ("theme_lang" in sections) if has_declared_sections else bool(settings_in)
        import_quick_tags = ("quick_tags" in sections) if has_declared_sections else bool(settings_in)
        import_subnets = ("subnets" in sections) if has_declared_sections else bool(subnets_in)

        if not any([import_general, import_notifications, import_quiet_hours, import_theme_lang, import_quick_tags, import_subnets]):
            flash(t("FLASH_CONFIG_SNAPSHOT_NOTHING_SELECTED"), "danger")
            return redirect(url_for("config_eggscan"))

        settings_updates = {}
        for key_raw, value_raw in settings_in.items():
            key = str(key_raw or "").strip()
            if not key or key in SNAPSHOT_EXCLUDED_SETTING_KEYS:
                continue
            is_categorized = key in SNAPSHOT_CATEGORIZED_SETTING_KEYS
            include_key = False

            if key in SNAPSHOT_NOTIFICATION_SETTING_KEYS and import_notifications:
                include_key = True
            elif key in SNAPSHOT_QUIET_SETTING_KEYS and import_quiet_hours:
                include_key = True
            elif key in SNAPSHOT_THEME_LANG_SETTING_KEYS and import_theme_lang:
                include_key = True
            elif key in SNAPSHOT_QUICK_TAG_SETTING_KEYS and import_quick_tags:
                include_key = True
            elif import_general and not is_categorized:
                include_key = True

            if include_key:
                settings_updates[key] = str(value_raw or "")

        parsed_subnets = []
        seen_cidrs = set()
        for idx, item in enumerate(subnets_in):
            if not isinstance(item, dict):
                continue

            cidr_raw = str(item.get("cidr", "")).strip()
            if not cidr_raw:
                continue

            try:
                cidr_norm = str(ipaddress.ip_network(cidr_raw, strict=False))
            except Exception:
                continue

            if cidr_norm in seen_cidrs:
                continue
            seen_cidrs.add(cidr_norm)

            label_raw = str(item.get("label", "")).strip()
            parsed_subnets.append({
                "cidr": cidr_norm,
                "label": label_raw if label_raw else None,
                "sort_order": idx,
            })

        for key, value in settings_updates.items():
            row = Settings.query.filter_by(key=key).first()
            if row:
                row.value = value
            else:
                db.session.add(Settings(key=key, value=value))

        if import_subnets:
            DeviceSubnetSeen.query.delete()
            Device.query.update({Device.last_subnet_id: None}, synchronize_session=False)
            SubNetwork.query.delete()

            for idx, sn in enumerate(parsed_subnets):
                db.session.add(SubNetwork(
                    cidr=sn["cidr"],
                    label=sn["label"],
                    sort_order=idx
                ))

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(tf("FLASH_CONFIG_SNAPSHOT_IMPORT_FAILED", error=str(e)), "danger")
        return redirect(url_for("config_eggscan"))

    flash(t("FLASH_CONFIG_SNAPSHOT_IMPORTED"), "success")
    return redirect(url_for("config_eggscan"))


@app.route("/ping_device/<int:device_id>", methods=["POST"])
@login_required
def ping_device(device_id):
    dev = Device.query.get(device_id)
    if not dev or dev.ip_address == "-":
        flash(t("FLASH_CANNOT_PING_OFFLINE"), "warning")
        return redirect(url_for("index"))

    ip = dev.ip_address
    ip_to_ping = ip.split(",")[0].strip()

    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip_to_ping],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            flash(tf("FLASH_PING_OK", ip=ip_to_ping), "success")
        else:
            flash(tf("FLASH_PING_FAIL", ip=ip_to_ping), "danger")
    except Exception as e:
        flash(tf("FLASH_PING_ERROR", error=e), "danger")

    return redirect(url_for("index"))


@app.route("/manual_ping", methods=["POST"])
@login_required
def manual_ping():
    ip = request.form.get("ip", "").strip()
    is_ipv6 = ("ipv6" in request.form)

    if not ip:
        flash(t("FLASH_MANUAL_PING_IP_REQUIRED"), "warning")
        return redirect(url_for("index"))

    cmd = ["ping", "-c", "1", "-W", "2", ip]
    if is_ipv6:
        cmd = ["ping", "-6", "-c", "1", "-W", "2", ip]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            flash(tf("FLASH_PING_OK", ip=ip), "success")
        else:
            flash(tf("FLASH_PING_FAIL", ip=ip), "danger")
    except Exception as e:
        flash(tf("FLASH_MANUAL_PING_ERROR", ip=ip, error=e), "danger")

    return redirect(url_for("index"))


@app.route("/delete_device/<int:device_id>", methods=["POST"])
@login_required
def delete_device(device_id):
    if not current_user.is_admin:
        flash(t("FLASH_DELETE_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))

    dev = Device.query.get(device_id)
    if dev:
        mac = (dev.mac_address or "").strip().lower()

        db.session.delete(dev)
        db.session.commit()

        if mac:
            try:
                AlertLog.query.filter(
                    AlertLog.mac_address == mac,
                    AlertLog.alert_type.in_(["new_device", "new_device_subnet"])
                ).delete(synchronize_session=False)
                db.session.commit()
            except Exception:
                db.session.rollback()

        flash(t("FLASH_DEVICE_DELETED"), "success")
    else:
        flash(t("FLASH_DEVICE_NOT_FOUND"), "warning")

    return redirect(url_for("index"))


@app.route("/manage_users", methods=["GET", "POST"])
@login_required
def manage_users():
    if not current_user.is_admin:
        return redirect(url_for("index"))

    if request.method == "POST":
        action = request.form.get("action")
        username = request.form.get("username")
        password = request.form.get("password")
        user_id = request.form.get("user_id")

        if action == "add" and username and password:
            hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
            new_user = User(username=username, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash(t("FLASH_USER_ADDED"), "success")

        elif action == "delete" and user_id:
            usr = User.query.get(int(user_id))
            if usr and not usr.is_admin:
                db.session.delete(usr)
                db.session.commit()
                flash(t("FLASH_USER_DELETED"), "success")
            else:
                flash(t("FLASH_USER_DELETE_FAIL"), "warning")

    users = User.query.all()
    lang = get_language()
    theme = get_theme()
    return render_template("manage_users.html", users=users, t=t, lang=lang, version=APP_VERSION, theme=theme)


@app.route("/config_eggscan", methods=["GET", "POST"])
@login_required
def config_eggscan():
    if not current_user.is_admin:
        return redirect(url_for("index"))

    if request.method == "POST":
        action = request.form.get("action")

        if action == "add_subnet":
            cidr = request.form.get("cidr", "").strip()
            if cidr:
                ex = SubNetwork.query.filter_by(cidr=cidr).first()
                if not ex:
                    sn = SubNetwork(cidr=cidr)
                    db.session.add(sn)
                    db.session.commit()
                    flash(tf("FLASH_SUBNET_ADDED", cidr=cidr), "success")
                else:
                    flash(tf("FLASH_SUBNET_EXISTS", cidr=cidr), "warning")

        elif action == "delete_subnet":
            subnet_id = request.form.get("subnet_id")
            if subnet_id and subnet_id.isdigit():
                sn = SubNetwork.query.get(int(subnet_id))
                if sn:
                    cidr = sn.cidr
                    db.session.delete(sn)
                    db.session.commit()
                    flash(tf("FLASH_SUBNET_DELETED", cidr=cidr), "success")
                else:
                    flash(t("FLASH_SUBNET_NOT_FOUND"), "warning")
            else:
                flash(t("FLASH_SUBNET_ID_INVALID"), "danger")

        elif action == "guess":
            guessed = guess_network_range()
            if guessed:
                ex = SubNetwork.query.filter_by(cidr=guessed).first()
                if not ex:
                    new_sn = SubNetwork(cidr=guessed)
                    db.session.add(new_sn)
                    db.session.commit()
                    flash(tf("FLASH_GUESSED_SUBNET_ADDED", cidr=guessed), "success")
                else:
                    flash(tf("FLASH_GUESSED_SUBNET_EXISTS", cidr=guessed), "warning")

        elif action == "update_settings":
            ipv6 = (request.form.get("ipv6") == "on")
            scan_interval = request.form.get("scan_interval", "5").strip()
            highlight_new = (request.form.get("highlight_new") == "on")
            ipv6_utils = request.form.get("ipv6_utils", "").strip()

            display_timezone = request.form.get("display_timezone", "").strip()

            language = request.form.get("language", "").strip()
            view_mode = request.form.get("subnet_view_mode", "column").strip().lower()

            notify_provider = request.form.get("notify_provider", "discord").strip().lower()
            allowed_providers = {"discord", "telegram", "slack", "email", "teams", "pushover", "gotify", "custom"}
            if notify_provider not in allowed_providers:
                notify_provider = "discord"

            notify_enabled = (request.form.get("notify_enabled") == "on")

            def form_value(name: str, default_value: str) -> str:
                val = request.form.get(name)
                if val is None:
                    return default_value
                return val.strip()

            discord_webhook_url = form_value(
                "discord_webhook_url",
                str(get_setting("discord_webhook_url", "")).strip()
            )
            telegram_bot_token = form_value(
                "telegram_bot_token",
                str(get_setting("telegram_bot_token", "")).strip()
            )
            telegram_chat_id = form_value(
                "telegram_chat_id",
                str(get_setting("telegram_chat_id", "")).strip()
            )
            slack_webhook_url = form_value(
                "slack_webhook_url",
                str(get_setting("slack_webhook_url", "")).strip()
            )
            teams_webhook_url = form_value(
                "teams_webhook_url",
                str(get_setting("teams_webhook_url", "")).strip()
            )
            email_url = form_value(
                "email_url",
                str(get_setting("email_url", "")).strip()
            )
            pushover_user = form_value(
                "pushover_user",
                str(get_setting("pushover_user", "")).strip()
            )
            pushover_token = form_value(
                "pushover_token",
                str(get_setting("pushover_token", "")).strip()
            )
            pushover_device = form_value(
                "pushover_device",
                str(get_setting("pushover_device", "")).strip()
            )
            gotify_host = form_value(
                "gotify_host",
                str(get_setting("gotify_host", "")).strip()
            )
            gotify_token = form_value(
                "gotify_token",
                str(get_setting("gotify_token", "")).strip()
            )
            gotify_https_existing = (str(get_setting("gotify_https", "true")).strip().lower() == "true")
            gotify_https = gotify_https_existing
            if request.form.get("gotify_https") is not None:
                gotify_https = (request.form.get("gotify_https") == "on")
            custom_url = form_value(
                "custom_url",
                str(get_setting("custom_url", "")).strip()
            )

            quiet_enabled = (request.form.get("quiet_enabled") == "on")
            quiet_start = parse_time_str(request.form.get("quiet_start", "22:00"), "22:00")
            quiet_end = parse_time_str(request.form.get("quiet_end", "07:00"), "07:00")
            quiet_days_list = request.form.getlist("quiet_days")
            quiet_days = []
            for d in quiet_days_list:
                d = str(d).strip()
                if not d:
                    continue
                try:
                    v = int(d)
                    if 0 <= v <= 6:
                        quiet_days.append(v)
                except Exception:
                    pass
            if not quiet_days:
                quiet_days = [0, 1, 2, 3, 4, 5, 6]

            fields = {
                "discord_webhook_url": discord_webhook_url,
                "telegram_bot_token": telegram_bot_token,
                "telegram_chat_id": telegram_chat_id,
                "slack_webhook_url": slack_webhook_url,
                "teams_webhook_url": teams_webhook_url,
                "email_url": email_url,
                "pushover_user": pushover_user,
                "pushover_token": pushover_token,
                "pushover_device": pushover_device,
                "gotify_host": gotify_host,
                "gotify_token": gotify_token,
                "gotify_https": "true" if gotify_https else "false",
                "custom_url": custom_url,
            }
            notify_url = build_apprise_url(notify_provider, fields)

            offline_threshold_minutes = request.form.get("offline_threshold_minutes", "60").strip()

            alert_scope = request.form.get("alert_scope", "all").strip().lower()
            if alert_scope not in ("all", "selected"):
                alert_scope = "all"

            new_device_alert_mode = request.form.get("new_device_alert_mode", "both").strip().lower()
            if new_device_alert_mode not in ("off", "global", "subnets", "both"):
                new_device_alert_mode = "both"

            selected_subnets = request.form.getlist("new_device_alert_subnets")
            subnet_ids = []
            for sid in selected_subnets:
                sid = str(sid).strip()
                if not sid:
                    continue
                try:
                    subnet_ids.append(int(sid))
                except Exception:
                    pass

            if not scan_interval.isdigit() or int(scan_interval) <= 0:
                flash(t("FLASH_SCAN_INTERVAL_INVALID"), "danger")
                return redirect(url_for("config_eggscan"))

            if view_mode not in ("column", "grouped"):
                view_mode = "column"

            if not offline_threshold_minutes.isdigit() or int(offline_threshold_minutes) <= 0:
                offline_threshold_minutes = "60"

            if display_timezone:
                try:
                    ZoneInfo(display_timezone)
                except Exception:
                    display_timezone = ""

            settings_updates = {
                "ipv6_enabled": "true" if ipv6 else "false",
                "scan_interval": scan_interval,
                "highlight_new": "true" if highlight_new else "false",
                "ipv6_utils": ipv6_utils,
                "subnet_view_mode": view_mode,
                "notify_provider": notify_provider,
                "notify_enabled": "true" if notify_enabled else "false",
                "notify_url": notify_url,
                "discord_webhook_url": discord_webhook_url,
                "telegram_bot_token": telegram_bot_token,
                "telegram_chat_id": telegram_chat_id,
                "slack_webhook_url": slack_webhook_url,
                "teams_webhook_url": teams_webhook_url,
                "email_url": email_url,
                "pushover_user": pushover_user,
                "pushover_token": pushover_token,
                "pushover_device": pushover_device,
                "gotify_host": gotify_host,
                "gotify_token": gotify_token,
                "gotify_https": "true" if gotify_https else "false",
                "custom_url": custom_url,
                "quiet_enabled": "true" if quiet_enabled else "false",
                "quiet_start": quiet_start,
                "quiet_end": quiet_end,
                "quiet_days": ",".join([str(x) for x in sorted(set(quiet_days))]),
                "offline_threshold_minutes": offline_threshold_minutes,
                "alert_scope": alert_scope,
                "display_timezone": display_timezone,
                "new_device_alert_mode": new_device_alert_mode,
                "new_device_alert_subnets": ",".join([str(x) for x in sorted(set(subnet_ids))]),
            }

            if language in ("sv", "en"):
                settings_updates["language"] = language

            for key, value in settings_updates.items():
                row = Settings.query.filter_by(key=key).first()
                if not row:
                    db.session.add(Settings(key=key, value=str(value)))
                else:
                    row.value = str(value)

            subnets = SubNetwork.query.order_by(SubNetwork.sort_order.asc(), SubNetwork.id.asc()).all()
            for sn in subnets:
                key = f"label_{sn.id}"
                new_label = request.form.get(key, "")
                if new_label is None:
                    continue
                new_label = new_label.strip()
                sn.label = new_label if new_label else None

            if alert_scope == "selected":
                enabled_ids = set()
                all_devices = Device.query.all()
                for d in all_devices:
                    if request.form.get(f"alert_dev_{d.id}") == "on":
                        enabled_ids.add(d.id)

                existing = {r.device_id: r for r in DeviceAlert.query.all()}

                for d in all_devices:
                    should_enable = (d.id in enabled_ids)
                    repeat_enabled = (
                        should_enable
                        and request.form.get(f"alert_repeat_{d.id}") == "on"
                    )
                    repeat_raw = str(request.form.get(f"alert_repeat_minutes_{d.id}", "")).strip()
                    try:
                        repeat_minutes = int(repeat_raw)
                    except Exception:
                        repeat_minutes = 60
                    if repeat_minutes <= 0:
                        repeat_minutes = 60

                    if d.id in existing:
                        existing[d.id].enabled = should_enable
                        existing[d.id].repeat_enabled = repeat_enabled
                        existing[d.id].repeat_interval_minutes = repeat_minutes if repeat_enabled else None
                        existing[d.id].updated_at = utc_now()
                    else:
                        if should_enable:
                            db.session.add(DeviceAlert(
                                device_id=d.id,
                                enabled=True,
                                repeat_enabled=repeat_enabled,
                                repeat_interval_minutes=repeat_minutes if repeat_enabled else None
                            ))

                for did, row in list(existing.items()):
                    if not row.enabled:
                        db.session.delete(row)

                db.session.commit()
            else:
                db.session.commit()

            flash(t("FLASH_SETTINGS_UPDATED"), "success")

        return redirect(url_for("config_eggscan"))

    subnets = SubNetwork.query.order_by(SubNetwork.sort_order.asc(), SubNetwork.id.asc()).all()
    ipv6_enable = (get_setting("ipv6_enabled", "false") == "true")
    scan_interval = get_setting("scan_interval", "5")
    highlight_new = (get_setting("highlight_new", "false") == "true")
    ipv6_utils = get_setting("ipv6_utils", "")
    lang = get_language()
    active_scan_interval = get_setting("scan_interval_active", scan_interval)
    theme = get_theme()
    subnet_view_mode = get_subnet_view_mode()

    display_tz = get_display_timezone()

    notify_provider = get_notify_provider()
    notify_enabled = get_notify_enabled()
    notify_url = get_notify_url()

    discord_webhook_url = get_setting("discord_webhook_url", "")
    telegram_bot_token = get_setting("telegram_bot_token", "")
    telegram_chat_id = get_setting("telegram_chat_id", "")
    slack_webhook_url = get_setting("slack_webhook_url", "")
    teams_webhook_url = get_setting("teams_webhook_url", "")
    email_url = get_setting("email_url", "")
    pushover_user = get_setting("pushover_user", "")
    pushover_token = get_setting("pushover_token", "")
    pushover_device = get_setting("pushover_device", "")
    gotify_host = get_setting("gotify_host", "")
    gotify_token = get_setting("gotify_token", "")
    gotify_https = (str(get_setting("gotify_https", "true")).strip().lower() == "true")
    custom_url = get_setting("custom_url", "")
    quiet_enabled = (get_setting("quiet_enabled", "false") == "true")
    quiet_start = get_setting("quiet_start", "22:00")
    quiet_end = get_setting("quiet_end", "07:00")
    quiet_days_raw = str(get_setting("quiet_days", "0,1,2,3,4,5,6")).strip()
    quiet_days = set()
    for part in quiet_days_raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            v = int(part)
            if 0 <= v <= 6:
                quiet_days.add(v)
        except Exception:
            pass
    if not quiet_days:
        quiet_days = {0, 1, 2, 3, 4, 5, 6}
    offline_threshold_minutes = get_setting("offline_threshold_minutes", "60")
    alert_scope = get_alert_scope()

    all_devices = Device.query.order_by(
        case((Device.alias.is_(None), 1), else_=0),
        Device.alias.asc(),
        Device.mac_address.asc()
    ).all()

    alert_rows = DeviceAlert.query.all()
    alert_map = {r.device_id: r for r in alert_rows}
    timezones = sorted(available_timezones())

    new_device_alert_mode = get_new_device_alert_mode()
    new_device_alert_subnets = get_new_device_alert_subnet_ids()

    return render_template(
        "config.html",
        subnets=subnets,
        ipv6=ipv6_enable,
        scan_interval=scan_interval,
        highlight_new=highlight_new,
        ipv6_utils=ipv6_utils,
        active_scan_interval=active_scan_interval,
        subnet_view_mode=subnet_view_mode,
        t=t,
        lang=lang,
        version=APP_VERSION,
        theme=theme,
        notify_provider=notify_provider,
        notify_enabled=notify_enabled,
        notify_url=notify_url,
        discord_webhook_url=discord_webhook_url,
        telegram_bot_token=telegram_bot_token,
        telegram_chat_id=telegram_chat_id,
        slack_webhook_url=slack_webhook_url,
        teams_webhook_url=teams_webhook_url,
        email_url=email_url,
        pushover_user=pushover_user,
        pushover_token=pushover_token,
        pushover_device=pushover_device,
        gotify_host=gotify_host,
        gotify_token=gotify_token,
        gotify_https=gotify_https,
        custom_url=custom_url,
        quiet_enabled=quiet_enabled,
        quiet_start=quiet_start,
        quiet_end=quiet_end,
        quiet_days=quiet_days,
        offline_threshold_minutes=offline_threshold_minutes,
        alert_scope=alert_scope,
        all_devices=all_devices,
        alert_map=alert_map,
        display_tz=display_tz,
        format_local=format_local,
        timezones=timezones,
        new_device_alert_mode=new_device_alert_mode,
        new_device_alert_subnets=new_device_alert_subnets,
    )


@app.route("/update_theme", methods=["POST"])
@login_required
def update_theme():
    if not current_user.is_admin:
        return redirect(url_for("index"))

    theme = request.form.get("theme", "").strip().lower()

    allowed = {"default", "dark", "light", "cosmos", "uplink"}
    if theme not in allowed:
        theme = "default"

    set_setting("theme", theme)
    return redirect(url_for("config_eggscan"))


@app.route("/update_subnet_order", methods=["POST"])
@login_required
def update_subnet_order():
    if not current_user.is_admin:
        return jsonify({"ok": False}), 403

    data = request.get_json()
    if not data or "order" not in data:
        return jsonify({"ok": False}), 400

    order = data["order"]

    for idx, subnet_id in enumerate(order):
        sn = SubNetwork.query.get(int(subnet_id))
        if sn:
            sn.sort_order = idx

    db.session.commit()
    return jsonify({"ok": True})


@app.route("/test_alert", methods=["POST"])
@login_required
def test_alert():
    if not current_user.is_admin:
        return redirect(url_for("index"))

    provider = get_notify_provider()
    enabled = get_notify_enabled()
    notify_url = get_notify_url()

    if not enabled or not notify_url:
        flash(t("ALERTS_TEST_FAIL").format(error="Alerts not enabled or settings missing"), "warning")
        return redirect(url_for("config_eggscan"))

    try:
        send_apprise_notification(notify_url, "✅ EggScan test alert: notification is working.")
        log_alert("test", provider, "sent", device=None, details={"message": "test"})
        flash(t("ALERTS_TEST_SENT"), "success")
    except Exception as e:
        err = str(e)
        try:
            log_alert("test", provider, "failed", device=None, details={"message": "test"}, error=err, dedupe_key=None)
        except Exception:
            db.session.rollback()
        flash(tf("ALERTS_TEST_FAIL", error=err), "danger")

    return redirect(url_for("config_eggscan"))


@app.route("/test_discord", methods=["POST"])
@login_required
def test_discord():
    return test_alert()


# ---------------------------
#       STARTUP
# ---------------------------

def main():
    parser = argparse.ArgumentParser(prog="eggscan")
    parser.add_argument(
        "mode",
        nargs="?",
        default="web-dev",
        choices=["web-dev", "scan-worker"],
        help="web-dev = Flask dev server (for local testing). scan-worker = scanning loop (for systemd)."
    )
    args = parser.parse_args()

    if args.mode == "scan-worker":
        run_scan_worker()
        return

    # web-dev (endast för test). I prod kör systemd gunicorn.
    app.run(host="0.0.0.0", port=5000, debug=False)


if __name__ == "__main__":
    main()
