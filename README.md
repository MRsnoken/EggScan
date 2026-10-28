# EggScan

**Discover, organize and monitor devices on your local network.**

![Latest release](https://img.shields.io/github/v/release/MRsnoken/EggScan?label=version)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

**EggScan** is a lightweight, self-hosted LAN monitoring tool for home networks,
homelabs and small private environments.

EggScan automatically discovers devices on your configured local networks and
provides a web dashboard where you can identify devices, monitor their
availability and track changes over time.

<img width="1890" height="1162" alt="EggScan dashboard showing discovered devices and their online/offline status" src="https://github.com/user-attachments/assets/f4b02944-aae2-4a4f-937a-42b8497d3fca" />

Beyond basic network scanning, EggScan helps you organize your device inventory,
receive notifications when something changes, and optionally keep a history of
when known devices were observed online or offline.

Scan results are stored in a local database. No cloud account, subscription or
external service is required for core network discovery and monitoring.
Optional notification integrations send alerts to the services you configure.

**Official repository:** https://github.com/MRsnoken/EggScan  
*For security and update safety, always download and install EggScan from the official repository.*

---

## Key features

- **Automatic network discovery** — Discover devices on configured local networks using ARP and Nmap, with IPv6 address discovery via the local neighbor table.
- **Device monitoring** — See which devices are online, offline or newly discovered, including their IP and MAC addresses, vendor information and when they were last seen.
- **Notifications and alerts** — Receive alerts for new devices and selected online/offline changes through Discord, Telegram, email and other supported services. Quiet hours and digest summaries help reduce interruptions.
- **Device organization** — Assign custom names, notes and tags to devices. Label subnets and group or filter devices to make your network easier to navigate.
- **Presence history** — Optionally track observed online/offline periods for known devices, with configurable history retention.
- **Automatic cleanup and review** — Optionally remove stale unknown devices automatically, preview cleanup candidates, or review known devices that have been offline for an extended period.
- **Local administration** — Manage devices, users and settings through the web interface, export the filtered device list as CSV, and download database backups with an admin account.

---

## Who is EggScan for?

EggScan is designed for people who want a clear view of their local network
without running a large or complex monitoring platform.

It is particularly useful for:

- **Home networks** — See which devices are connected and notice unfamiliar arrivals.
- **Homelabs and home servers** — Keep track of your equipment and receive alerts when selected devices become unavailable.
- **Raspberry Pi setups** — Run a self-hosted network dashboard on a small local machine.
- **Small private networks** — Organize devices across configured subnets and review changes in one place.

EggScan focuses on straightforward network visibility and device monitoring.
It is not intended to replace enterprise monitoring platforms or dedicated
network security systems, or to monitor large-scale or distributed networks.

**Designed for trusted local networks. Do not expose EggScan directly to the public internet.**
See the [Security Notice](#-security-notice) before setting up remote access.

---

<details>
<summary><strong> Screenshots </strong> ⬇</summary>

<strong>Setup Admin</strong>

<img width="2138" height="970" alt="SetupAdmin" src="https://github.com/user-attachments/assets/cd8741bd-fcfd-4721-9481-85c070a62855" />

<br><br>

<strong>Login</strong>

<img width="2134" height="968" alt="Login" src="https://github.com/user-attachments/assets/d8de2db6-b0e1-44a4-ac2f-99d089a3701a" />

<br><br>

<strong>Settings </strong>

<img width="1891" height="1152" alt="Settings" src="https://github.com/user-attachments/assets/aeb89dae-9ea4-490a-9709-abd133279b74" />


<br><br>

<strong> Manage Users </strong>

<img width="1681" height="613" alt="Manage user" src="https://github.com/user-attachments/assets/5a0b5e94-9f02-44a6-a2a4-bc886acf5e5c" />




<br><br>

<strong>Password </strong>

<img width="1884" height="539" alt="Password" src="https://github.com/user-attachments/assets/06330a44-c7a8-4229-b955-84f78e882eb7" />


<br><br>

<strong>About </strong>
<img width="1414" height="583" alt="About" src="https://github.com/user-attachments/assets/2d98d7ce-0e0a-4c6d-a88f-db82d4fd5b7a" />

<br><br>
<strong> Darkmode</strong>

<img width="1874" height="1047" alt="Darkmode" src="https://github.com/user-attachments/assets/6a4e5664-c876-4c31-8464-dcddfe7f9193" />
<br><br>
<strong> Lightmode </strong>

<img width="1886" height="1048" alt="Lightmode" src="https://github.com/user-attachments/assets/f214f692-af4d-4636-b442-35fed858317c" />
<br><br>
<strong> Cosmos </strong>
<img width="1884" height="1066" alt="Cosmosmode" src="https://github.com/user-attachments/assets/d17eb776-612a-4714-9b41-b006d3bbac8f" />
<br><br>
<strong> Uplink </strong>

<img width="1414" height="660" alt="uplink" src="https://github.com/user-attachments/assets/138dfddf-90c5-4d39-b77c-6291e6fc5a65" />

</details>

---

<details>
<summary><strong> Detailed features and technical overview </strong> ⬇</summary>

- Fast local network scanning (ARP + Nmap)
- Web interface built with Flask
- Device list with IP, MAC and vendor lookup
- IPv4 device discovery and IPv6 address discovery via the local neighbor table
- Alias naming for devices
- Online / offline / new device indicators
- SQLite database storage
- Runs as two systemd services (web + scan worker)
- Versioning via `version.json`
- Local README and changelog viewer on the About page
- Local scan-result storage with no cloud backend required; optional notifications use configured services
- Multi-channel notifications via Apprise (Discord, Telegram, Slack, Email, Teams, Pushover, Gotify, custom URL)
- Quiet hours with digest summary after quiet period ends
- Optional subnet labeling (e.g. Home, Guest, Lab)
- Subnet-aware device display:
  - Subnet shown as a column in the device table, or
  - Devices grouped into subnet sections
- Accurate handling of devices present in multiple subnets
- Subnet display reflects actual scan results (no guessed or historical placement)
- Upgrade-safe installer with automatic database schema checks<br>
- Settings search to quickly filter configuration sections
- One-click admin action to mark all new devices as known
- New-devices dashboard counter opens a compact review modal with individual and bulk admin actions
- Optional automatic cleanup of stale unknown devices, disabled by default, with a non-destructive candidate preview
- Optional admin review queue for known devices that have been offline for a chosen period
- Optional presence history for known devices with observed online/offline periods and configurable retention
- Admin CSV export for the currently filtered device view
- Database backup download from the Settings page (admin only)
- Separated scan worker and web UI for improved stability
- Production-ready web serving via Gunicorn (systemd or Docker)

</details>

---

## Design goals

EggScan is built with the following principles in mind:

- Fully local operation – all data is stored locally, with no cloud backend or required external services
- Predictable behavior over real-time complexity
- Clear and inspectable state after each scan
- Simple deployment and maintenance
- Readable code over clever abstractions

EggScan is not intended to compete with enterprise monitoring solutions.
It focuses on clarity and control for private LAN environments.


---

## Installation

For Docker, see the [Docker installation instructions](docker/README.md).

The automatic installer supports **Debian, Ubuntu, Linux Mint, Raspberry Pi OS
and Fedora**, plus compatible **RHEL-family systems using DNF**, including
Rocky Linux, AlmaLinux and CentOS Stream. Other compatible Debian- or DNF-based
derivatives may also work.

Automatic installation requires **systemd and Python 3.10 or newer**.
Other Linux distributions require manual installation and manual updates.
Expand the instructions below for your installation method.

<details>
<summary><strong> Installation instructions (APT / DNF systems) </strong> ⬇</summary>

The installer automatically selects `apt-get` or `dnf`, installs the appropriate package names and verifies that Python 3.10 or newer is available. The About page web updater supports the same system families when systemd is available. Other Linux distributions require manual installation and manual updates.

Run:

  ```bash
git clone https://github.com/MRsnoken/EggScan.git
cd EggScan
chmod +x install_eggscan.sh
sudo ./install_eggscan.sh
 ```
The installer will:

- Check system requirements
- Install required system packages
- Create a Python virtual environment
- Install Python dependencies inside the venv
- Copy application files to /opt/eggscan
- Create the dedicated `eggscan` system user and group
- Create the main systemd services (`eggscan-web.service` and `eggscan-scan.service`)
- Install the manual updater service (`eggscan-update.service`, not enabled at boot)
- Apply restricted file permissions and scan-worker network capabilities
- Start EggScan automatically


After installation, open:
```bash
http://<your_local_ip>:5000
```
</details>
<details>
<summary><strong> Python dependencies </strong> ⬇</summary>
Listed in requirements.txt:

- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-Bcrypt
- python-nmap
- gunicorn
- apprise

</details>
<details>
<summary><strong> Install Python dependencies manually </strong> ⬇</summary>

These commands only create a Python virtual environment and install Python
dependencies. They do not install system packages, configure permissions or
set up EggScan services. Run them from the EggScan source directory.

For a complete installation on supported systems, use the installer above.
```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade 'pip>=26.2' 'setuptools>=84.1.0'
pip install --upgrade --upgrade-strategy eager -r requirements.txt
python -m pip check
```
</details>
<details>
<summary><strong> Installation on other Linux distributions </strong> ⬇</summary>
No automatic installer is provided outside the supported APT/DNF system families.

The About page web updater is disabled outside supported APT/DNF systems using systemd.


You must manually install:

- Python 3
- python3-venv (or equivalent)
- pip
- nmap
- iproute2 / net-tools
- Python dependencies from requirements.txt

You must also manually create:

- a virtual environment
- an `eggscan` system user and group
- a directory structure under `/opt/eggscan`
- file permissions that allow the `eggscan` user to write the local database and generated secrets
- two systemd service files (web + scan worker), normally running as the `eggscan` user/group
- scan-worker network capabilities equivalent to `CAP_NET_RAW` / `CAP_NET_ADMIN` if you want privileged nmap discovery while running as a non-root user
- optional distro-specific updater helper/service if you intentionally adapt the built-in update flow

For advanced users only.
</details>
<details>
<summary><strong> Uninstallation </strong> ⬇</summary>
To remove EggScan completely, stop and disable the services first:

```bash
sudo systemctl stop eggscan-web.service eggscan-scan.service eggscan-update.service eggscan.service 2>/dev/null || true
sudo systemctl disable eggscan-web.service eggscan-scan.service eggscan.service 2>/dev/null || true
```

If you may want to restore EggScan later, back up these files before deleting `/opt/eggscan`:

```bash
/opt/eggscan/secret_key.txt
/opt/eggscan/eggscan.db
```

Then remove the application, service files and updater helper:

```bash
sudo rm -rf /opt/eggscan/
sudo rm -f /lib/systemd/system/eggscan-web.service
sudo rm -f /lib/systemd/system/eggscan-scan.service
sudo rm -f /lib/systemd/system/eggscan-update.service
sudo rm -f /lib/systemd/system/eggscan.service
sudo rm -f /usr/lib/systemd/system/eggscan-web.service
sudo rm -f /usr/lib/systemd/system/eggscan-scan.service
sudo rm -f /usr/lib/systemd/system/eggscan-update.service
sudo rm -f /usr/lib/systemd/system/eggscan.service
sudo rm -f /etc/systemd/system/eggscan-web.service
sudo rm -f /etc/systemd/system/eggscan-scan.service
sudo rm -f /etc/systemd/system/eggscan-update.service
sudo rm -f /etc/systemd/system/eggscan.service
sudo rm -f /usr/local/sbin/eggscan-update
sudo rm -f /etc/sudoers.d/eggscan-update
sudo rm -f /var/log/eggscan-update.log
sudo rm -f /var/log/eggscan-update-latest.log
sudo rm -rf /var/lib/eggscan/
sudo rm -f /run/eggscan-update.lock
sudo systemctl daemon-reload
sudo systemctl reset-failed
```

If the dedicated system user/group exists and you no longer need it:

```bash
sudo userdel eggscan 2>/dev/null || true
sudo groupdel eggscan 2>/dev/null || true
```

</details>


---

## 🔐 Security Notice

EggScan is intended for **trusted local networks only**.

It does not currently include:

- Hardened or enterprise-grade authentication
- HTTPS / TLS by default

EggScan **does include CSRF protection** for POST actions, but it is still a local‑only tool.
Notification integrations are optional and only used if you explicitly configure them.

For remote access, EggScan must be placed behind:

- a reverse proxy (Nginx, Caddy, Traefik, etc.)
- proper authentication
- HTTPS / TLS termination

**Do not expose EggScan directly to the public internet.**


## 🗺️ Roadmap (non-binding)

Planned or considered improvements:

- Additional notification workflows and templates
- Improved device history and presence tracking
- UI refinements and accessibility improvements

This roadmap is **informational only** and may change over time.

---

## 📜 License

EggScan is released under the **GNU General Public License v3.0 (GPL-3.0)**.

In summary:

- You may use, study, modify and share the project under the terms of GPLv3.
- You may make and use private modifications without publishing them.
- If you distribute a modified version, you must license the covered work as a whole under GPLv3 and make the corresponding source code available to recipients as the license requires.
- When distributing copies, preserve the required copyright, license and warranty notices, include the license, and clearly identify modifications and their dates.
- GPL-covered versions may not be redistributed under proprietary terms that remove recipients' GPL rights.

This is a short overview, not a replacement for the full [license text](LICENSE).
See also the [GNU FAQ on private modifications and source distribution](https://www.gnu.org/licenses/gpl-faq.en.html#GPLRequireSourcePostedPublic).

---

## ⚠️ Disclaimer

EggScan is provided **as is**, without warranty of any kind.  
Use at your own risk.

---

## 👤 Credits

Created by **MRsnoken**.  
Network discovery powered by **Nmap** and public **OUI data**.

---

## 🤝 Contributing

Want to help improve EggScan?

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening issues or pull requests.

