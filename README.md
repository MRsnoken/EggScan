# EggScan

![Latest release](https://img.shields.io/github/v/release/MRsnoken/EggScan?label=version)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

**EggScan** is a lightweight, self-hosted LAN device monitoring tool designed for
home networks, labs and small private environments.

It continuously scans your local network and presents discovered devices in a
clean web dashboard, showing IP addresses, MAC addresses, vendor information,
online/offline status and discovery history.

EggScan is intentionally simple, fully local and dependency-light.
There is no cloud backend, no external services and no hidden telemetry.

**Official repository:** https://github.com/MRsnoken/EggScan  
*For security and update safety, always download and install EggScan from the official repository.*

---

## Design goals

EggScan is built with the following principles in mind:

- Fully local operation – no cloud, no external dependencies
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

<strong>Dashboard</strong>

<img width="1680" height="1010" alt="DeviceDashboard" src="https://github.com/user-attachments/assets/b13ce9d3-a3ee-4f92-b7ea-f0069c45d093" />

<br><br>

<strong>Update Alias</strong>

<img width="492" height="247" alt="Alias" src="https://github.com/user-attachments/assets/8028fe28-12fb-4967-917d-9aa98d8de705" />

<br><br>

<strong>Network</strong>

<img width="1112" height="753" alt="NetworkSettings" src="https://github.com/user-attachments/assets/c423cf77-8305-48bb-b6ed-184981f301b5" />

<br><br>

<strong>Manage Users</strong>

<img width="691" height="277" alt="Manage Users" src="https://github.com/user-attachments/assets/0ec37e1b-476c-46c0-b599-f1cf816b61e2" />

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
- Runs as a systemd service
- Versioning via `version.json`
- No cloud backend – all scan data stays on your LAN

</details>

---

<details>
<summary><strong> Installation (Debian / Ubuntu) </strong> ⬇</summary>

Supported Debian-based systems:

- Ubuntu
- Raspberry Pi OS
- Debian
- Linux Mint
- Other Debian derivatives

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
- Create a systemd service
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

</details>
<details>
<summary><strong> Manual installation </strong> ⬇</summary>

  ```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
</details>
<details>
<summary><strong> Installation on other Linux systems </strong> ⬇</summary>
No automatic installer is provided.


You must manually install:

- Python 3
- python3-venv (or equivalent)
- pip
- nmap
- iproute2 / net-tools
- Python dependencies from requirements.txt

You must also manually create:

- a virtual environment
- a systemd service file
- a directory structure under /opt/eggscan

For advanced users only.
</details>
<details>
<summary><strong> Uninstallation </strong> ⬇</summary>
To remove EggScan manually, delete:

```bash
/opt/eggscan/
/lib/systemd/system/eggscan.service   (or /etc/systemd/system/)
```
Optional data files:

```bash
/opt/eggscan/secret_key.txt
eggscan.db
```
Then run:

```bash
sudo systemctl stop eggscan.service
sudo systemctl disable eggscan.service
sudo systemctl daemon-reload
```

</details>


---

## 🔐 Security Notice

EggScan is intended for **trusted local networks only**.

It does not currently include:

- CSRF protection
- Hardened or enterprise-grade authentication
- HTTPS / TLS by default

For remote access, EggScan must be placed behind:

- a reverse proxy (Nginx, Caddy, Traefik, etc.)
- proper authentication
- HTTPS / TLS termination

**Do not expose EggScan directly to the public internet.**

---

## 🗺️ Roadmap (non-binding)

Planned or considered improvements:

- Optional notification hooks (Discord / generic webhooks)
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
