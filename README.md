---

# Spoofers
This repository is a collection of spoofing tools, focusing on Layer 2 and Layer 3 spoofing techniques. The ARP spoofer poisons the Address Resolution Protocol (ARP) at Layer 2 (the Data Link Layer in the OSI model), while the DNS spoofer manipulates DNS records in the `/etc/hosts` file on Linux systems. **These tools are designed for use on Linux systems only.**

---

## Features
This collection is intended for performing **Man-in-the-Middle (MITM) attacks** to assist in network penetration testing and vulnerability assessment. It helps identify potential loopholes within network configurations.

---

## Requirements
- **Python 3**
- **pip** package manager
- Additional Python packages:
  - `scapy`
  - `os`
  - `argparse`
  - `time`
  - `winreg` (for Windows systems specifically)
  - `netfilterqueue`

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/grayshader3020/Spoofers
   ```
2. Navigate into the repository:
   ```bash
   cd Spoofers
   ```
3. Install dependencies:
   ```bash
   ./requirement.sh
   ```
4. Run the spoofing tools:
   ```bash
   sudo python3 arp_spoofer.py
   sudo python3 dns_spoofer.py
   ```

**Note**: To start DNS spoofing, ensure ARP spoofing is running first.

---

## Disclaimer
**This project is in its early stages and may contain bugs.** Please use it responsibly and report any issues on [GitHub](https://github.com/grayshader3020/Spoofers). Your feedback and contributions are highly appreciated!

---
