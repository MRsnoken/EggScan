import threading
import time
import ipaddress
import uuid
import datetime
import subprocess
import os
import json
import secrets

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
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    last_seen_scan = db.Column(db.String(36), nullable=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)
    is_new = db.Column(db.Boolean, default=False)


class SubNetwork(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cidr = db.Column(db.String(50), unique=True, nullable=False)


with app.app_context():
    db.create_all()


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
    },
}


def get_setting(key, default_value=None):
    s = Settings.query.filter_by(key=key).first()
    return s.value if s else default_value


def set_setting(key, value):
    s = Settings.query.filter_by(key=key).first()
    if not s:
        s = Settings(key=key, value=value)
        db.session.add(s)
    else:
        s.value = value
    db.session.commit()


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

def t(key):
    lang = get_language()
    return TRANSLATIONS.get(lang, TRANSLATIONS["sv"]).get(key, key)


def tf(key, **kwargs):
    text = t(key)
    try:
        return text.format(**kwargs)
    except Exception:
        return text


# ---------------------------
#   HELPERS
# ---------------------------

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
    ipv6_utils = get_setting("ipv6_utils", "").strip()

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


def nmap_scan_and_save():
    subnets = SubNetwork.query.all()
    if not subnets:
        set_setting("scan_status", "done")
        return

    set_setting("scan_status", "running")
    current_scan_id = str(uuid.uuid4())
    set_setting("last_scan_id", current_scan_id)

    nm = nmap.PortScanner()
    existing_devices = {d.mac_address.lower(): d for d in Device.query.all()}
    ipv6_enabled = (get_setting("ipv6_enabled", "false") == "true")
    scan_ips_per_mac = {}

    for sn in subnets:
        cidr = sn.cidr.strip()
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.version != 4:
                continue

            scan_output = nm.scan(hosts=cidr, arguments="-sn")
            for host, info in scan_output.get("scan", {}).items():
                mac = info.get("addresses", {}).get("mac", None)
                if not mac:
                    continue

                mac_lower = mac.lower()
                manufacturer = info.get("vendor", {}).get(mac, None)

                scan_ips_per_mac.setdefault(mac_lower, set()).add(host)

                if mac_lower in existing_devices:
                    dev = existing_devices[mac_lower]
                    if manufacturer:
                        dev.manufacturer = manufacturer
                    dev.last_seen_scan = current_scan_id
                    dev.last_seen_at = datetime.datetime.now()
                else:
                    new_dev = Device(
                        ip_address=host,
                        mac_address=mac,
                        manufacturer=manufacturer,
                        last_seen_scan=current_scan_id,
                        last_seen_at=datetime.datetime.now(),
                        is_new=True
                    )
                    db.session.add(new_dev)
                    existing_devices[mac_lower] = new_dev

        except Exception as e:
            print(f"Scan error for {cidr}: {e}")

    db.session.commit()

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
                dev.last_seen_at = datetime.datetime.now()
            else:
                new_dev = Device(
                    ip_address=",".join(ipv6_list),
                    mac_address=mac_lower,
                    manufacturer=None,
                    last_seen_scan=current_scan_id,
                    last_seen_at=datetime.datetime.now(),
                    is_new=True
                )
                db.session.add(new_dev)
                existing_devices[mac_lower] = new_dev

        db.session.commit()

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
    db.session.commit()

    offline_devs = Device.query.filter(Device.last_seen_scan != current_scan_id).all()
    for d in offline_devs:
        d.ip_address = "-"
    db.session.commit()

    if not ipv6_enabled:
        all_devs = Device.query.all()
        for d in all_devs:
            if d.ip_address and d.ip_address != "-":
                addresses = [x.strip() for x in d.ip_address.split(",")]
                keep_only_v4 = []
                for addr in addresses:
                    try:
                        ip_obj = ipaddress.ip_address(addr)
                        if ip_obj.version == 4:
                            keep_only_v4.append(addr)
                    except Exception:
                        pass
                d.ip_address = ",".join(keep_only_v4) if keep_only_v4 else "-"
        db.session.commit()

    set_setting("last_scan_time", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    set_setting("scan_status", "done")


def run_periodic_scan():
    while True:
        with app.app_context():
            interval_str = get_setting("scan_interval", "5")
            try:
                interval_minutes = int(interval_str)
            except Exception:
                interval_minutes = 5

            set_setting("scan_interval_active", str(interval_minutes))
            nmap_scan_and_save()

        time.sleep(interval_minutes * 60)


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

    total_devices = len(devices)
    online_devices = 0
    new_devices = 0

    for dev in devices:
        if dev.last_seen_scan == last_scan_id:
            online_devices += 1
        if dev.is_new:
            new_devices += 1

    offline_devices = total_devices - online_devices

    def none_str(x):
        return x if x else ""

    if sort_field == "ip":
        def ip_key(dev):
            if dev.ip_address == "-" or not dev.ip_address:
                return (999, ipaddress.ip_address("255.255.255.255"))
            first_ip = dev.ip_address.split(",")[0].strip()
            try:
                ip_obj = ipaddress.ip_address(first_ip)
                return (ip_obj.version, ip_obj)
            except Exception:
                return (999, ipaddress.ip_address("255.255.255.255"))
        devices.sort(key=ip_key, reverse=(sort_dir == "desc"))

    elif sort_field == "mac":
        devices.sort(key=lambda d: none_str(d.mac_address).lower(), reverse=(sort_dir == "desc"))
    elif sort_field == "alias":
        devices.sort(key=lambda d: none_str(d.alias).lower(), reverse=(sort_dir == "desc"))
    elif sort_field == "manufacturer":
        devices.sort(key=lambda d: none_str(d.manufacturer).lower(), reverse=(sort_dir == "desc"))
    elif sort_field == "updated":
        def updated_key(d):
            return d.updated_at if d.updated_at else datetime.datetime(1970, 1, 1)
        devices.sort(key=updated_key, reverse=(sort_dir == "desc"))

    lang = get_language()
    theme = get_theme()
    ipv6_enabled = (get_setting("ipv6_enabled", "false") == "true")
    last_scan_time = get_setting("last_scan_time", "")

    configured_scan_interval = get_setting("scan_interval", "5")
    active_scan_interval = get_setting("scan_interval_active", configured_scan_interval)

    return render_template(
        "index.html",
        devices=devices,
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
        last_scan_time=last_scan_time,
        configured_scan_interval=configured_scan_interval,
        active_scan_interval=active_scan_interval,
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
    def do_scan_now():
        with app.app_context():
            nmap_scan_and_save()

    t_thread = threading.Thread(target=do_scan_now, daemon=True)
    t_thread.start()
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
        dev = Device.query.filter_by(mac_address=mac).first()
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
        dev = Device.query.filter_by(mac_address=mac).first()
        if dev:
            dev.manufacturer = manufacturer if manufacturer else None
            db.session.commit()
            flash(t("FLASH_MANUFACTURER_UPDATED"), "success")

    return redirect(url_for("index"))


@app.route("/mark_known/<int:device_id>", methods=["POST"])
@login_required
def mark_known(device_id):
    if not current_user.is_admin:
        flash(t("FLASH_STATUS_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))

    dev = Device.query.get(device_id)
    if dev and dev.is_new:
        dev.is_new = False
        db.session.commit()
        flash(t("FLASH_DEVICE_MARKED_KNOWN"), "success")

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
        db.session.delete(dev)
        db.session.commit()
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
            language = request.form.get("language", "").strip()

            if not scan_interval.isdigit() or int(scan_interval) <= 0:
                flash(t("FLASH_SCAN_INTERVAL_INVALID"), "danger")
                return redirect(url_for("config_eggscan"))

            set_setting("ipv6_enabled", "true" if ipv6 else "false")
            set_setting("scan_interval", scan_interval)
            set_setting("highlight_new", "true" if highlight_new else "false")
            set_setting("ipv6_utils", ipv6_utils)
            if language in ("sv", "en"):
                set_setting("language", language)

            flash(t("FLASH_SETTINGS_UPDATED"), "success")

        return redirect(url_for("config_eggscan"))

    subnets = SubNetwork.query.all()
    ipv6_enable = (get_setting("ipv6_enabled", "false") == "true")
    scan_interval = get_setting("scan_interval", "5")
    highlight_new = (get_setting("highlight_new", "false") == "true")
    ipv6_utils = get_setting("ipv6_utils", "")
    lang = get_language()
    active_scan_interval = get_setting("scan_interval_active", scan_interval)
    theme = get_theme()

    return render_template(
        "config.html",
        subnets=subnets,
        ipv6=ipv6_enable,
        scan_interval=scan_interval,
        highlight_new=highlight_new,
        ipv6_utils=ipv6_utils,
        active_scan_interval=active_scan_interval,
        t=t,
        lang=lang,
        version=APP_VERSION,
        theme=theme
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

# ---------------------------
#       STARTUP
# ---------------------------

if __name__ == "__main__":
    t_thread = threading.Thread(target=run_periodic_scan, daemon=True)
    t_thread.start()
    app.run(host="0.0.0.0", port=5000, debug=False)
