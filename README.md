# NetLimiter Linux

**NetLimiter Linux** is a transparent, local-first network monitoring and management tool designed for Linux distributions. 

This repository is published openly so that users can inspect the complete source code, verify its safety, and review how it works under the hood.

## ✨ Features
- **Per-Application Bandwidth Control:** Manage download and upload speeds per application via `nftables`.
- **100% Local Processing:** Runs entirely on your local machine with zero telemetry, background logging, or external data sharing.
- **Full Transparency:** Open-source code available for complete community review and security auditing.
- **GTK4 / Libadwaita UI:** Modern native Linux interface.

---

## 📦 Installation & Packaging

### For Fedora / RHEL (RPM)
```bash
make rpm
sudo dnf install ~/rpmbuild/RPMS/x86_64/netlimiter-0.2.0-1.*.rpm
