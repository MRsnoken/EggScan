EggScan

![Latest release](https://img.shields.io/github/v/release/MRsnoken/EggScan?label=version)

Self-hosted LAN device monitor. Shows IP, MAC, vendor and online status via a simple web dashboard.

EggScan is a lightweight Flask-based web application that scans your local network, shows connected devices, and provides details such as IP, MAC, vendor, ping status, and discovery events.
It is designed for private LAN environments only and installs through a simple one-command installer script.

 **Official repository:** https://github.com/MRsnoken/EggScan  
*For security and update safety, please download and install EggScan only from the official repository.*

EGGSCAN IS A HOBBY PROJECT. NOT INTENDED FOR ENTERPRISE OR SECURITY-CRITICAL USE.
DO NOT EXPOSE EGGSCAN TO THE PUBLIC INTERNET.
NO HARDENING, NO HTTPS, NO PRODUCTION-GRADE AUTH.


<details>

<summary><strong> Screenshots </strong> ⬇</summary>
<strong>Setup Admin </strong>

<img width="2138" height="970" alt="SetupAdmin" src="https://github.com/user-attachments/assets/cd8741bd-fcfd-4721-9481-85c070a62855" />

<br> <br>
<strong> Login </strong>
<img width="2134" height="968" alt="Login" src="https://github.com/user-attachments/assets/d8de2db6-b0e1-44a4-ac2f-99d089a3701a" />
<br><br>
<strong>Dashboard</strong>
<img width="1680" height="1010" alt="DeviceDashboard" src="https://github.com/user-attachments/assets/b13ce9d3-a3ee-4f92-b7ea-f0069c45d093" />
<br><br>
<strong>Update Alias</strong>


<img width="492" height="247" alt="Alias" src="https://github.com/user-attachments/assets/8028fe28-12fb-4967-917d-9aa98d8de705" />

<br><br> 
  <strong>  Network </strong> 
<img width="1112" height="753" alt="NetworkSettings" src="https://github.com/user-attachments/assets/c423cf77-8305-48bb-b6ed-184981f301b5" />
<br><br>
   <strong>   Manage Users </strong>

<img width="691" height="277" alt="Manage Users" src="https://github.com/user-attachments/assets/0ec37e1b-476c-46c0-b599-f1cf816b61e2" />



</details>

<details>
  
<summary><strong> Features </strong> ⬇</summary>

- Fast local network scanning (ARP + Nmap)
- Web interface (Flask)
- Device list with IP, MAC, vendor lookup
- IPv4 and IPv6 address discovery (via neighbor scans)
- Alias naming for devices
- Online/offline/new indicators
- SQLite database storage
- Runs as a systemd service
- Versioning via version.json
- No cloud backend – all scan data stays on your LAN

</details>

<details>
<summary><strong> Installation (Debian/Ubuntu) </strong> ⬇</summary>

Supported Debian-based systems:
Ubuntu
Raspberry Pi OS
Debian
Linux Mint
Other Debian derivatives

Run:
```
chmod +x install_eggscan.sh
sudo ./install_eggscan.sh
```
The installer will:

Check system requirements
Install required system packages
Create a Python virtual environment
Install Python dependencies inside the venv
Copy eggscan.py to /opt/eggscan
Copy version.json
Create a systemd service
Start EggScan automatically

After installation, open:

http://<your_local_ip>:5000

</details>

<details>
<summary><strong> Python dependencies </strong> ⬇</summary>

Listed in requirements.txt:
Flask
Flask-SQLAlchemy
Flask-Login
Flask-Bcrypt
python-nmap

</details>
<details>
<summary><strong> Manual install </strong> ⬇</summary>

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

</details>

<details>
<summary><strong> Installation on other Linux systems (Arch, Fedora, etc.) </strong> ⬇</summary>


No automatic installer is provided.

You must manually install:

Python 3
python3-venv (or equivalent)
pip
nmap
iproute2 / net-tools
Python dependencies from requirements.txt

You must also manually create:

a virtual environment
a systemd service file
a directory structure under /opt/eggscan

For advanced users only.
</details>

<details>
<summary><strong> Uninstallation </strong> ⬇</summary>


To remove EggScan manually, delete:

/opt/eggscan/
/lib/systemd/system/eggscan.service (or /etc/systemd/system/)
/opt/eggscan/secret_key.txt
eggscan.db (if present)

Then run:

sudo systemctl stop eggscan.service
sudo systemctl disable eggscan.service
sudo systemctl daemon-reload

</details>
<details>
<summary><strong> Security Notes </strong> ⬇</summary>


EggScan is intended for home LAN usage only.

It does not include:

CSRF protection
Hardened authentication
Multi-user model
HTTPS/TLS

For remote access, you must place it behind:

a reverse proxy (Nginx, Caddy, Traefik, etc)
proper authentication
HTTPS/TLS

Do not expose EggScan directly to the internet.

</details>

<details>
<summary><strong> License </strong> ⬇</summary>

EggScan is released under the GNU General Public License version 3 (GPL-3.0).

This means:

You may use, study, modify and share the project
Modified versions must remain under GPL-3.0
You must keep copyright and attribution
You may not close the source and sell it as proprietary software

</details>
<details>
<summary><strong> Disclaimer </strong> ⬇</summary>

EggScan is provided as is, without warranty.
Use at your own risk.

</details>
<details>
<summary><strong> Credits </strong> ⬇</summary>

Created by MRsnoken.
Network discovery powered by Nmap and public OUI data.
</details>

## Contributing

Want to help improve EggScan?  
Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening issues or pull requests.
