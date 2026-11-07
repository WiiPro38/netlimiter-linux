# NetLimiter-Linux

NetLimiter-Linux is a transparent, local-first network monitoring and management tool designed for Linux distributions. 

This repository is published openly so that users can inspect the complete source code, verify its safety, and review how it works under the hood.

---

## ✨ Key Features

* **Per-Application Bandwidth Control:**
  Manage download and upload speeds per application via `nftables` and Traffic Control (`tc`).
* **Auto-Block & Interactive Alerts:**
  Automatically blocks any new application attempting to access the internet for the first time and triggers a real-time interactive notification allowing you to instantly **Allow**, **Block**, or set a **Speed Limit**.
* **100% Local Processing:**
  Runs entirely on your local machine with zero telemetry, background logging, or external data sharing.
* **Full Transparency:**
  Open-source code available for complete community review and security auditing.
* **GTK4 / Libadwaita UI:**
  Modern, eye-friendly native Linux user interface seamlessly integrated with System Tray support.
* **Timer Control (Pause/Resume):**
  Effortlessly pause and resume bandwidth limits and rules with a single click.
* **IP & Domain Lookup:**
  Built-in functionality to search and resolve IP addresses and domain names directly inside the app.
* **Multi-Language Support:**
  Fully localized interface tailored for multiple languages and regional locale settings.

---

## 🛡️ License & Non-Commercial Rights

**© Maamar Nachef. All Rights Reserved.**

### Intellectual Property & Commercial Restriction
This software and its source code (`NetLimiter-Linux`) are the exclusive intellectual property of the developer. **Commercial use, redistribution, modification for commercial purposes, reselling, or incorporating this software into any paid commercial product is strictly prohibited** without prior explicit written permission from the owner. 

This project is released strictly for personal, educational, and non-profit open-source use.

---

## 📦 Supported Distributions & Packages

NetLimiter-Linux officially supports both major Linux distribution families through dedicated native packages available in the releases:

* **Red Hat Family (.rpm):**
  Fedora, RHEL, AlmaLinux, Rocky Linux, and derivative distributions.
* **Debian / Ubuntu Family (.deb):**
  Debian, Ubuntu, Kubuntu, Linux Mint, and derivative distributions.

---

## ⚙️ System Dependencies & Requirements

To ensure full functionality (including Packet Socket traffic monitoring, `nftables` firewall rules, `tc` bandwidth shaping, and GTK4/System Tray integration), install the required dependencies for your distribution family:

### 1. Red Hat Family (Fedora / RHEL / AlmaLinux)
sudo dnf install nftables iproute iproute-tc python3 python3-gobject libayatana-appindicator procps-ng -y

### 2. Debian Family (Debian / Ubuntu / Kubuntu / Linux Mint)
sudo apt update && sudo apt install nftables iproute2 python3 python3-gi python3-ayatana-appindicator procps -y

---

## 📥 Installation from Pre-built Releases

If you downloaded the ready-to-install packages from the Releases page:

### For Fedora / RHEL (RPM)
sudo dnf install ./netlimiter-0.2.0-1.*.rpm

### For Debian / Ubuntu (DEB)
sudo apt install ./netlimiter_0.2.0-1_amd64.deb

### Enable & Start the Background Service
sudo systemctl daemon-reload
sudo systemctl enable --now netlimiter-daemon.service

---

## 🚀 Building from Source

For developers or advanced users who wish to build both package formats (`.rpm` and `.deb`) natively from source:

1. **Build All Packages:**
   make packages

2. **Install the Built Package:**
   * **On Fedora / RPM:**
     sudo dnf install ~/rpmbuild/RPMS/x86_64/netlimiter-0.2.0-1.*.rpm
   * **On Debian / Ubuntu:**
     sudo apt install ./dist/netlimiter_0.2.0-1_amd64.deb

3. **Start the Background Service:**
   sudo systemctl daemon-reload
   sudo systemctl enable --now netlimiter-daemon.service
