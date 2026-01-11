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
import json
import secrets
import urllib.request
import urllib.error
import argparse
import tempfile

from flask import (
    Flask, render_template, redirect, url_for, request, flash,
    jsonify, has_request_context
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

        try:
            db.session.execute(text("SELECT 1 FROM device_alert LIMIT 1;"))
        except Exception:
            db.session.rollback()
            db.create_all()

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
        "CONFIRM_DELETE": "Är du säker?",
        "YES": "Ja",
        "NO": "Nej",
        "VERSION_LABEL": "Version",

        "INDEX_TITLE": "EggScan",
        "LOGGED_IN_AS": "Inloggad som:",
        "MANUAL_PING_PLACEHOLDER": "Ange IP att testa",
        "MANUAL_PING_BUTTON": "Testa adress",
        "FILTER_LABEL": "Filter:",
        "FILTER_BOTH": "Båda",
        "FILTER_ONLINE": "Endast online",
        "FILTER_OFFLINE": "Endast offline",
        "SEARCH_PLACEHOLDER": "Sök IP/MAC/Alias",
        "SEARCH_FILTER_BUTTON": "Sök/Filtrera",
        "SORT_LABEL": "Sortera:",
        "SORT_IP": "IP",
        "SORT_MAC": "MAC",
        "SORT_ALIAS": "Alias",
        "SORT_MANUFACTURER": "Tillverkare",
        "SORT_UPDATED": "Uppdaterad",
        "SCAN_NOW": "Skanna nu",
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
        "DELETE": "Ta bort",
        "ALIAS_MODAL_TITLE": "Uppdatera Alias",
        "ALIAS_LABEL": "Alias",
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

        "FLASH_MANUFACTURER_ADMIN_ONLY": "Endast admin kan ändra tillverkare!",
        "FLASH_MANUFACTURER_UPDATED": "Tillverkare uppdaterad!",

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
        "ALERTS_DISCORD_ENABLE": "Aktivera Discord webhook",
        "ALERTS_DISCORD_WEBHOOK": "Discord webhook URL",
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
        "ALERTS_DISCORD_WEBHOOK_PLACEHOLDER": "https://discord.com/api/webhooks/...",
        "ALERTS_NEW_DEVICE_TITLE": "Nya enheter (Discord)",
        "ALERTS_NEW_DEVICE_OFF": "Av",
        "ALERTS_NEW_DEVICE_GLOBAL": "Globalt (endast helt ny enhet)",
        "ALERTS_NEW_DEVICE_SUBNETS": "Endast valda subnät",
        "ALERTS_NEW_DEVICE_BOTH": "Båda (globalt + subnät)",
        "ALERTS_NEW_DEVICE_HINT": "Globalt triggar bara när en enhet skapas första gången (ny MAC). Subnät triggar bara första gången en enhet syns i ett subnät.",
        "ALERTS_NEW_DEVICE_SUBNET_PICKER_TITLE": "Subnät som ska trigga subnäts-larm",
        "DISCORD_NEW_DEVICE_GLOBAL_TITLE": "🆕 EggScan: Ny enhet upptäckt!",
        "DISCORD_NEW_DEVICE_SUBNET_TITLE": "🆕 EggScan: Ny enhet i subnät!",
        "DISCORD_LABEL_NAME": "Namn",
        "DISCORD_LABEL_MAC": "MAC",
        "DISCORD_LABEL_IP": "IP",
        "DISCORD_LABEL_SUBNET": "Subnät",


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
        "CONFIRM_DELETE": "Are you sure?",
        "YES": "Yes",
        "NO": "No",
        "VERSION_LABEL": "Version",

        "INDEX_TITLE": "EggScan",
        "LOGGED_IN_AS": "Logged in as:",
        "MANUAL_PING_PLACEHOLDER": "Enter IP to test",
        "MANUAL_PING_BUTTON": "Test address",
        "FILTER_LABEL": "Filter:",
        "FILTER_BOTH": "Both",
        "FILTER_ONLINE": "Online only",
        "FILTER_OFFLINE": "Offline only",
        "SEARCH_PLACEHOLDER": "Search IP/MAC/Alias",
        "SEARCH_FILTER_BUTTON": "Search/Filter",
        "SORT_LABEL": "Sort:",
        "SORT_IP": "IP",
        "SORT_MAC": "MAC",
        "SORT_ALIAS": "Alias",
        "SORT_MANUFACTURER": "Manufacturer",
        "SORT_UPDATED": "Updated",
        "SCAN_NOW": "Scan now",
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
        "DELETE": "Delete",
        "ALIAS_MODAL_TITLE": "Update Alias",
        "ALIAS_LABEL": "Alias",
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

        "FLASH_MANUFACTURER_ADMIN_ONLY": "Only admin can change manufacturer!",
        "FLASH_MANUFACTURER_UPDATED": "Manufacturer updated!",

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
        "ALERTS_DISCORD_ENABLE": "Enable Discord webhook",
        "ALERTS_DISCORD_WEBHOOK": "Discord webhook URL",
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
        "ALERTS_NEW_DEVICE_SUBNET_HINT": "Leave empty to treat subnet alerts as “all subnets”. If you select subnets, only those will trigger new-device alerts.",
        "ALERTS_NEW_DEVICE_TITLE": "New devices (Discord)",
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
        "ALERTS_DISCORD_WEBHOOK_PLACEHOLDER": "https://discord.com/api/webhooks/...",
        "DISCORD_NEW_DEVICE_GLOBAL_TITLE": "🆕 EggScan: New device detected!",
        "DISCORD_NEW_DEVICE_SUBNET_TITLE": "🆕 EggScan: New device in subnet!",
        "DISCORD_LABEL_NAME": "Name",
        "DISCORD_LABEL_MAC": "MAC",
        "DISCORD_LABEL_IP": "IP",
        "DISCORD_LABEL_SUBNET": "Subnet",

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

def set_settings_bulk(pairs: dict[str, str]) -> None:
    if not pairs:
        return

    with app.app_context():
        try:
            db.session.execute(text("BEGIN IMMEDIATE;"))
            for k, v in pairs.items():
                db.session.execute(
                    text("""
                        INSERT INTO settings (key, value)
                        VALUES (:k, :v)
                        ON CONFLICT(key) DO UPDATE SET value=excluded.value;
                    """),
                    {"k": str(k), "v": str(v)}
                )
            db.session.commit()
        except Exception:
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


def get_language():
    lang = get_setting("language", "sv")
    if lang not in ("sv", "en"):
        lang = "sv"
    return lang


def get_theme():
    theme = get_setting("theme", "default")
    if not theme:
        theme = "default"

    allowed = {"default", "dark", "light", "cosmos"}
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


# ---------------------------
#   HELPERS
# ---------------------------

SCAN_LOCK_KEY = "scan_lock_token"
SCAN_LOCK_UNTIL_KEY = "scan_lock_until_utc"
SCAN_REQUEST_KEY = "scan_requested"
SCAN_REQUEST_ID_KEY = "scan_request_id"
SCAN_REQUEST_AT_KEY = "scan_request_at_utc"


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

            # UPSERT token
            db.session.execute(
                text("""
                    INSERT INTO settings (key, value)
                    VALUES (:k, :v)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value;
                """),
                {"k": SCAN_LOCK_KEY, "v": token}
            )

            # UPSERT until
            db.session.execute(
                text("""
                    INSERT INTO settings (key, value)
                    VALUES (:k, :v)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value;
                """),
                {"k": SCAN_LOCK_UNTIL_KEY, "v": until_iso}
            )

            db.session.commit()
            return token

        except Exception:
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
                db.session.execute(
                    text("""
                        INSERT INTO settings (key, value)
                        VALUES (:k, :v)
                        ON CONFLICT(key) DO UPDATE SET value=excluded.value;
                    """),
                    {"k": SCAN_LOCK_KEY, "v": ""}
                )
                db.session.execute(
                    text("""
                        INSERT INTO settings (key, value)
                        VALUES (:k, :v)
                        ON CONFLICT(key) DO UPDATE SET value=excluded.value;
                    """),
                    {"k": SCAN_LOCK_UNTIL_KEY, "v": ""}
                )

            db.session.commit()

        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass


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


def send_discord_webhook(webhook_url: str, content: str) -> None:
    webhook_url = (webhook_url or "").strip()
    if not webhook_url:
        raise Exception("Missing webhook URL")

    payload_obj = {"content": content}
    payload = json.dumps(payload_obj).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "EggScan/1.0 (+local)",
        "Accept": "application/json",
    }

    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers=headers,
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            _ = resp.read()
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        raise Exception(f"HTTP {e.code} {e.reason} | body={body}") from None
    except urllib.error.URLError as e:
        raise Exception(f"URL error: {e}") from None


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


def make_offline_dedupe_key(dev: Device) -> str:
    if dev.last_seen_at:
        ts = dev.last_seen_at.replace(microsecond=0).isoformat()
    else:
        ts = "unknown"
    return f"offline:{dev.id}:{ts}"


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
    discord_enabled = get_bool_setting("discord_enabled", default=False)
    webhook_url = str(get_setting("discord_webhook_url", "")).strip()
    if not discord_enabled or not webhook_url:
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
        if not (already and already.status == "sent"):
            subnet_label = "-"
            subnet_cidr = "-"
            if subnet:
                subnet_cidr = subnet.cidr or "-"
                subnet_label = (subnet.label.strip() if subnet.label and subnet.label.strip() else "-")
            msg = (
                f"{t('DISCORD_NEW_DEVICE_GLOBAL_TITLE')}\n"
                f"{t('DISCORD_LABEL_NAME')}: {device_display_name(dev)}\n"
                f"{t('DISCORD_LABEL_MAC')}: {mac_lower}\n"
                f"{t('DISCORD_LABEL_IP')}: {dev.ip_address or '-'}\n"
                f"{t('DISCORD_LABEL_SUBNET')}: {subnet_label} ({subnet_cidr})"
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
                send_discord_webhook(webhook_url, msg)
                log_alert("new_device", "discord", "sent", device=dev, details=details, dedupe_key=dedupe_key)
            except Exception as e:
                err = str(e)
                try:
                    log_alert("new_device", "discord", "failed", device=dev, details=details, error=err, dedupe_key=dedupe_key)
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
        if already and already.status == "sent":
            return

        subnet_label = (subnet.label.strip() if subnet.label and subnet.label.strip() else subnet.cidr)

        msg = (
            f"{t('DISCORD_NEW_DEVICE_SUBNET_TITLE')}\n"
            f"{t('DISCORD_LABEL_SUBNET')}: {subnet_label}\n"
            f"{t('DISCORD_LABEL_NAME')}: {device_display_name(dev)}\n"
            f"{t('DISCORD_LABEL_MAC')}: {mac_lower}\n"
            f"{t('DISCORD_LABEL_IP')}: {dev.ip_address or '-'}"
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
            send_discord_webhook(webhook_url, msg)
            log_alert("new_device_subnet", "discord", "sent", device=dev, details=details, dedupe_key=dedupe_key)
        except Exception as e:
            err = str(e)
            try:
                log_alert("new_device_subnet", "discord", "failed", device=dev, details=details, error=err, dedupe_key=dedupe_key)
            except Exception:
                db.session.rollback()


def evaluate_offline_alerts(current_scan_id: str):
    discord_enabled = get_bool_setting("discord_enabled", default=False)
    webhook_url = str(get_setting("discord_webhook_url", "")).strip()
    if not discord_enabled or not webhook_url:
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

        already = AlertLog.query.filter_by(dedupe_key=dedupe_key).first()
        if already and already.status == "sent":
            continue

        msg = f"🔴 EggScan alert: {device_display_name(dev)} is offline "

        details = {
            "device_id": dev.id,
            "alias": dev.alias,
            "mac": dev.mac_address,
            "ip": dev.ip_address,
            "last_seen_at_utc": dev.last_seen_at.replace(microsecond=0).isoformat() if dev.last_seen_at else None,
            "offline_minutes": offline_minutes,
            "threshold_minutes": threshold
        }

        try:
            send_discord_webhook(webhook_url, msg)
            log_alert("offline", "discord", "sent", device=dev, details=details, dedupe_key=dedupe_key)
        except Exception as e:
            err = str(e)
            try:
                log_alert("offline", "discord", "failed", device=dev, details=details, error=err, dedupe_key=dedupe_key)
            except Exception:
                db.session.rollback()


def evaluate_online_recovery_alerts(current_scan_id: str):
    discord_enabled = get_bool_setting("discord_enabled", default=False)
    webhook_url = str(get_setting("discord_webhook_url", "")).strip()
    if not discord_enabled or not webhook_url:
        return

    now_utc = utc_now()
    online_devices = Device.query.filter(Device.last_seen_scan == current_scan_id).all()

    for dev in online_devices:
        if not is_device_alert_enabled(dev):
            continue

        last_offline = (
            AlertLog.query
            .filter_by(alert_type="offline", device_id=dev.id, status="sent")
            .order_by(AlertLog.created_at.desc())
            .first()
        )
        if not last_offline:
            continue

        offline_dedupe_key = last_offline.dedupe_key or ""
        online_dedupe_key = make_online_recovery_dedupe_key(dev, offline_dedupe_key)

        already = AlertLog.query.filter_by(dedupe_key=online_dedupe_key).first()
        if already and already.status == "sent":
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
            send_discord_webhook(webhook_url, msg)
            log_alert(
                "online_back",
                "discord",
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
                    "discord",
                    "failed",
                    device=dev,
                    details=details,
                    error=err,
                    dedupe_key=online_dedupe_key
                )
            except Exception:
                db.session.rollback()


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
                scan_output = nm.scan(hosts=cidr, arguments="-sn")
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
    next_run = utc_now()

    while True:
        with app.app_context():
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


@app.route("/logout")
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


@app.route("/")
@login_required
def index():
    scan_status = get_setting("scan_status", "done")
    last_scan_id = get_setting("last_scan_id", "")
    highlight_new = (get_setting("highlight_new", "false") == "true")

    filter_mode = request.args.get("filter", "both")
    search_q = request.args.get("search", "").strip()
    sort_field = request.args.get("sort", "ip")
    sort_dir = request.args.get("dir", "asc")

    q = Device.query

    if search_q:
        pattern = f"%{search_q}%"
        q = q.filter(
            db.or_(
                Device.ip_address.ilike(pattern),
                Device.mac_address.ilike(pattern),
                Device.alias.ilike(pattern),
                Device.manufacturer.ilike(pattern)
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
        ipv6_enabled=ipv6_enabled,
        last_scan_time=last_scan_time_local,
        configured_scan_interval=configured_scan_interval,
        active_scan_interval=active_scan_interval,
        subnet_map=subnet_map,
        has_named_subnets=has_named_subnets,
        subnet_view_mode=subnet_view_mode,
        display_tz=display_tz,
        format_local=format_local,
        t=t,
        lang=lang,
        version=APP_VERSION,
        theme=theme
    )


@app.route("/scan_status", methods=["GET"])
def get_scan_status():
    status = get_setting("scan_status", "done")
    return jsonify({"status": status})


@app.route("/force_scan", methods=["POST"])
@login_required
def force_scan():
    request_scan_now()
    return redirect(url_for("index"))


@app.route("/update_alias", methods=["POST"])
@login_required
def update_alias():
    if not current_user.is_admin:
        flash(t("FLASH_ALIAS_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))

    mac = request.form.get("mac")
    alias = request.form.get("alias", "").strip()

    if mac:
        dev = Device.query.filter_by(mac_address=mac.lower()).first()
        if dev:
            dev.alias = alias
            if dev.is_new:
                dev.is_new = False
            db.session.commit()
            flash(t("FLASH_ALIAS_UPDATED"), "success")

    return redirect(url_for("index"))


@app.route("/update_manufacturer", methods=["POST"])
@login_required
def update_manufacturer():
    if not current_user.is_admin:
        flash(t("FLASH_MANUFACTURER_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))

    mac = request.form.get("mac")
    manufacturer = request.form.get("manufacturer", "").strip()

    if mac:
        dev = Device.query.filter_by(mac_address=mac.lower()).first()
        if dev:
            dev.manufacturer = manufacturer if manufacturer else None
            db.session.commit()
            flash(t("FLASH_MANUFACTURER_UPDATED"), "success")

    return redirect(url_for("index"))


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

            discord_enabled = (request.form.get("discord_enabled") == "on")
            discord_webhook_url = request.form.get("discord_webhook_url", "").strip()
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

            set_setting("ipv6_enabled", "true" if ipv6 else "false")
            set_setting("scan_interval", scan_interval)
            set_setting("highlight_new", "true" if highlight_new else "false")
            set_setting("ipv6_utils", ipv6_utils)
            set_setting("subnet_view_mode", view_mode)

            set_setting("discord_enabled", "true" if discord_enabled else "false")
            set_setting("discord_webhook_url", discord_webhook_url)
            set_setting("offline_threshold_minutes", offline_threshold_minutes)
            set_setting("alert_scope", alert_scope)

            set_setting("display_timezone", display_timezone)

            set_setting("new_device_alert_mode", new_device_alert_mode)
            set_setting("new_device_alert_subnets", ",".join([str(x) for x in sorted(set(subnet_ids))]))

            if language in ("sv", "en"):
                set_setting("language", language)

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
                    if d.id in existing:
                        existing[d.id].enabled = should_enable
                        existing[d.id].updated_at = utc_now()
                    else:
                        if should_enable:
                            db.session.add(DeviceAlert(device_id=d.id, enabled=True))

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

    discord_enabled = (get_setting("discord_enabled", "false") == "true")
    discord_webhook_url = get_setting("discord_webhook_url", "")
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
        discord_enabled=discord_enabled,
        discord_webhook_url=discord_webhook_url,
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

    allowed = {"default", "dark", "light", "cosmos"}
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


@app.route("/test_discord", methods=["POST"])
@login_required
def test_discord():
    if not current_user.is_admin:
        return redirect(url_for("index"))

    discord_enabled = get_bool_setting("discord_enabled", default=False)
    webhook_url = str(get_setting("discord_webhook_url", "")).strip()

    if not discord_enabled or not webhook_url:
        flash(t("ALERTS_TEST_FAIL").format(error="Discord not enabled or webhook URL missing"), "warning")
        return redirect(url_for("config_eggscan"))

    try:
        send_discord_webhook(webhook_url, "✅ EggScan test alert: Discord webhook is working.")
        log_alert("test", "discord", "sent", device=None, details={"message": "test"})
        flash(t("ALERTS_TEST_SENT"), "success")
    except Exception as e:
        err = str(e)
        try:
            log_alert("test", "discord", "failed", device=None, details={"message": "test"}, error=err, dedupe_key=None)
        except Exception:
            db.session.rollback()
        flash(tf("ALERTS_TEST_FAIL", error=err), "danger")

    return redirect(url_for("config_eggscan"))


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
