# WickedPortal

**WickedPortal — educational captive-portal simulator**

WickedPortal is an educational tool that simulates a malicious captive portal and open Wi‑Fi environment to demonstrate common vulnerabilities in captive portals, DHCP/DNS-based attacks, and unsecured wireless networks. It runs on a host with two NICs (one connected to an upstream router for Internet access, the other to an AP) and provides NAT/masquerade, DHCP, DNS and a customizable captive portal page that requests **fictitious** registration data for demonstration purposes only.

---

## Table of Contents

* [Key features](#key-features)
* [How it works (high level)](#how-it-works-high-level)
* [Requirements](#requirements)
* [Quickstart](#quickstart)
* [Configuration](#configuration)
* [Security, ethics & legal notice](#security-ethics--legal-notice)
* [Contributing](#contributing)
* [License](#license)

---

## Key features

* Lightweight captive-portal emulator that intercepts and demonstrates HTTP/redirect captive flows.
* Local DHCP and DNS services to control client addressing and captive behavior.
* NAT/masquerade routing between the AP-facing NIC and the upstream Internet NIC.
* Configurable portal page (HTML form) for simulated credential collection (demo data only).
* Logging and simple analytics to illustrate attack vectors, user exposure and common pitfalls.
* Designed for classroom labs, red-team demos, and security training in controlled environments.

---

## How it works (high level)

1. Host uses two network interfaces: **WAN** (connected to upstream router/Internet) and **AP** (connected to an access point).
2. WickedPortal runs DHCP and DNS on the AP interface to assign client IPs and resolve DNS queries locally.
3. DNS/DHCP and routing rules are used to steer clients into the captive flow: HTTP requests are redirected to the local portal page.
4. The host applies NAT/masquerade to forward permitted traffic from the AP to the WAN while handling portal interactions locally.
5. The portal collects only **fictitious/demo information** for demonstration; the project does not store or exfiltrate real credentials.

---

## Requirements

* Linux host with two NICs (one to upstream router/internet, one to AP).
* Root privileges to manage networking (ip/iptables/nft), DHCP and DNS services.
* Basic webserver/runtime (bundled or configurable) to serve the portal page.
* Optional: an AP configured to bridge clients to the AP-facing NIC.

---

## Quickstart

> The steps below assume a prepared build or bundled binary called `wickedportal` (adjust names/paths to your installation).

1. Connect `eth0` (or NIC-A) to your upstream router (Internet) and `eth1` (or NIC-B) to the AP.
2. Configure the AP to bridge/route clients to the host's AP interface.
3. Start the service (example):

```bash
sudo ./wickedportal start --wan eth0 --ap eth1
```

4. The software will bring up DHCP/DNS on the AP interface, apply NAT on the WAN interface, and launch the local captive portal web UI.
5. Connect a test client to the AP and observe the captive redirect and demo logs.

*Note:* exact flags and service names depend on the packaged distribution — see `docs/INSTALL.md` or the `--help` output for details.

---

## Configuration

* Portal HTML is customizable: replace the template in `portal/` to tailor the look and the demo form fields.
* DHCP and DNS options are configured via `config/` (subnet, lease times, DNS rules, forced redirect rules).
* Logging level and storage path are configurable; logs are preserved for classroom analysis.

---

## Security, ethics & legal notice

WickedPortal is strictly for **authorized** educational, research, and security-training use in controlled environments. Do **not** deploy this software against networks, devices, or users without explicit permission. Unauthorized or malicious use may be illegal and unethical. By using this software you accept responsibility for ensuring all testing is lawful and properly authorized.

---

## Contributing

Contributions are welcome: bug reports, documentation improvements, example lab scenarios, and safe feature enhancements. Please open issues or pull requests and follow the code of conduct and contribution guidelines in `CONTRIBUTING.md`.

---

## License

Recommend including a permissive license (e.g., MIT) and an explicit `NO MALICIOUS USE` clause in the repo description. See `LICENSE` for details.

---

*This README is intended for educational demonstration and lab use only.*
