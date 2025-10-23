#WickedPortal (educational captive-portal simulator)

WickedPortal is an educational tool that simulates a malicious captive portal and open Wi-Fi environment to demonstrate common vulnerabilities in captive portals, DHCP/DNS-based attacks, and unsecured wireless networks. It runs on a host with two NICs (one connected to an upstream router for Internet access, the other to an AP) and provides NAT/masquerade, DHCP, DNS and a customizable captive portal page that requests fictitious registration data for demonstration purposes only.

Key features

Lightweight captive-portal emulator that intercepts HTTP(S) redirection flows.

Local DHCP and DNS services to control client networking and captive behavior.

NAT/masquerade routing between the AP-facing NIC and the upstream Internet NIC.

Configurable portal page (HTML form) for simulated credential collection.

Logging and simple analytics for educational demonstration of attacker techniques and user exposure.

Intended for red-team / classroom labs, security training, and vulnerability demonstrations.

How it works (high level)

Host has two network interfaces: WAN (to upstream router) and AP (to access point).

The software runs DHCP and DNS on the AP interface to assign IPs and resolve client queries.

DNS/DHCP rules and routing force clients into the captive portal flow; HTTP requests are redirected to the local portal.

The host performs NAT/masquerade to forward permitted traffic to the upstream router while inspecing captive flows.

Portal collects only fictitious/demo data; no attempt is made to reuse or exfiltrate real credentials.

Requirements

Linux host with two NICs (one to upstream router, one to AP).

Root privileges to manage networking, iptables/nft, DHCP/DNS services.

Basic webserver runtime (included or configurable).

(Optional) AP device configured to bridge/serve clients to the AP-facing NIC.

Quickstart

Connect NIC A to upstream router (Internet) and NIC B to the AP.

Configure AP to use the host (NIC B) as its network uplink.

Start the software: it will bring up DHCP and DNS on NIC B, apply NAT on NIC A, and launch the captive portal web interface.

Connect a test client to the AP and observe captive behavior and demo logs.

Ethics & legal notice

This project is strictly for educational, research, and authorized security testing in controlled environments. Do not deploy against networks or users without explicit permission. Misuse may be illegal and unethical. By using this software you accept responsibility for ensuring all testing is lawful and authorized.

Disclaimer

WickedPortal is provided "as-is" for educative purposes. It is not intended for malicious use. The authors are not responsible for misuse or legal consequences resulting from unauthorized deployment.
