# EggScan

<img width="1890" height="1162" alt="Mainside" src="https://github.com/user-attachments/assets/f4b02944-aae2-4a4f-937a-42b8497d3fca" />

<br><br>

Local-first LAN monitoring with a clean, inspectable web interface.
<br><br>
![Latest release](https://img.shields.io/github/v/release/MRsnoken/EggScan?label=version)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

**EggScan** is a lightweight, self-hosted LAN device monitoring tool designed for
home networks, labs and small private environments.

It continuously scans your local network and presents discovered devices in a
clean web dashboard, showing IP addresses, MAC addresses, vendor information,
online/offline status and discovery history.

EggScan is intentionally simple, fully local and dependency-light.
There is no cloud backend, no external services and no hidden telemetry.

EggScan acts as a local network scanner that continuously discovers and tracks
devices on your LAN, maintaining a clear and inspectable state after each scan.

**Official repository:** https://github.com/MRsnoken/EggScan  
*For security and update safety, always download and install EggScan from the official repository.*

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

## Intended audience

EggScan is suitable for:

- Home labs
- Small private networks
- Learning and experimentation
- Users who want visibility into their LAN without running heavy platforms

EggScan is **not** intended for:

- Enterprise environments
- Security-critical monitoring
- Large-scale or distributed networks

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
<strong> Uplink<img width="1414" height="660" alt="uplink" src="https://github.com/user-attachments/assets/138dfddf-90c5-4d39-b77c-6291e6fc5a65" />
 </strong>

</details>

---

<details>
<summary><strong> Features </strong> ⬇</summary>

- Fast local network scanning (ARP + Nmap)
- Web interface built with Flask
- Device list with IP, MAC and vendor lookup
- IPv4 and IPv6 address discovery (via neighbor scans)
- Alias naming for devices
- Online / offline / new device indicators
- SQLite database storage
- Runs as two systemd services (web + scan worker)
- Versioning via `version.json`
- No cloud backend – all scan data stays on your LAN
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
- New-devices dashboard counter opens a compact review modal with admin actions
- Database backup download from the Settings page (admin only)
- Separated scan worker and web UI for improved stability
 - Production-ready web serving via Gunicorn (systemd)

</details>

---

<details>
<summary><strong> Installation (Debian / Ubuntu) </strong> ⬇</summary>
<br>
Supported Debian-based systems:

- Debian
- Ubuntu
- Linux Mint
- Raspberry Pi OS
- Other Debian derivatives

The installer and the About page web updater are intended for Debian-based systems with systemd. Other Linux distributions require manual installation and manual updates.

Run:

  ```bash
chmod +x install_eggscan.sh
sudo ./install_eggscan.sh
 ```
The installer will:

- Check system requirements
- Install required system packages
- Create a Python virtual environment
- Install Python dependencies inside the venv
- Copy application files to /opt/eggscan
- Create the main systemd services (`eggscan-web.service` and `eggscan-scan.service`)
- Install the manual updater service (`eggscan-update.service`, not enabled at boot)
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
<summary><strong> Development / Python environment </strong> ⬇</summary>

This only installs the Python dependencies for development/testing. It does not create services, users, permissions or the updater.

  ```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
</details>
<details>
<summary><strong> Installation on other Linux distributions) </strong> ⬇</summary>
No automatic installer is provided.

The About page web updater is disabled outside Debian-based systemd systems.


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
sudo systemctl stop eggscan-web.service eggscan-scan.service eggscan-update.service 2>/dev/null || true
sudo systemctl disable eggscan-web.service eggscan-scan.service 2>/dev/null || true
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
sudo rm -f /etc/systemd/system/eggscan-web.service
sudo rm -f /etc/systemd/system/eggscan-scan.service
sudo rm -f /etc/systemd/system/eggscan-update.service
sudo rm -f /usr/local/sbin/eggscan-update
sudo rm -f /var/log/eggscan-update.log
sudo rm -rf /var/lib/eggscan/
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

This means:

- You may use, study, modify, and share the project
- Modified versions must remain under GPL-3.0
- Copyright and attribution must be preserved
- The project may not be closed-source or redistributed as proprietary software

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
