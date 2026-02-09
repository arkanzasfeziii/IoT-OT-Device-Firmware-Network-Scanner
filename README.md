# 🔍 IoT/OT Device Firmware & Network Scanner

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security Tool](https://img.shields.io/badge/Security-IoT%2FOT%20Scanner-red)](https://github.com/arkanzasfeziii/iotot-scanner)

A comprehensive, single-file security scanner for discovering, fingerprinting, and assessing vulnerabilities in IoT (Internet of Things) and OT (Operational Technology) devices across industrial and smart environments.

> ⚠️ **LEGAL NOTICE**: This tool is designed **strictly for authorized security testing**. You must have explicit written permission to scan any network or device. Unauthorized scanning may violate laws in your jurisdiction and could result in criminal prosecution. The author assumes no liability for misuse.

## ✨ Key Features

- 🔎 **Network Discovery**: ARP scanning (local networks) and ICMP ping for host detection
- 📡 **Industrial Protocol Support**: Modbus (502), BACnet (47808), Siemens S7 (102), DNP3 (20000)
- 🆔 **Device Fingerprinting**: 
  - MAC OUI vendor identification
  - Service/banner detection
  - Automatic device type classification (Raspberry Pi, ESP32, cameras, PLCs, etc.)
- 🛡️ **Vulnerability Assessment**:
  - Mirai botnet exposure (default Telnet credentials)
  - Unauthenticated web interfaces
  - Exposed UPnP services
  - Insecure protocols (Telnet, HTTP, SNMPv1/v2)
  - Industrial protocol exposure risks
- 🌐 **HTTP Probing**: Server headers, titles, authentication requirements
- 📊 **Risk Scoring**: 0-100 risk score per device based on exposure and vulnerabilities
- 📈 **Multiple Output Formats**: Console (rich UI), JSON, HTML reports
- ⚡ **Performance**: Multi-threaded scanning with configurable concurrency

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Root/Administrator privileges (required for ARP scanning and aggressive modes)

### Installation
```bash
# Clone repository
git clone https://github.com/arkanzasfeziii/iotot-scanner.git
cd iotot-scanner
```
Basic Usage
```bash
# Scan single device with default ports
python iototscanner.py 192.168.1.1

# Scan entire subnet
python iototscanner.py 192.168.1.0/24

# Scan with custom ports (industrial focus)
python iototscanner.py 10.0.0.0/24 --ports 502,47808,102,20000,161

# Aggressive scan (HTTP probing, UPnP discovery) - requires root
sudo python iototscanner.py 192.168.1.0/24 --aggressive --i-understand-legal-responsibilities

# Save results to JSON
python iototscanner.py 192.168.1.0/24 --output json --file scan_20260209.json

# Save results to HTML report
python iototscanner.py 192.168.1.0/24 --output html --file report.html
```
Advanced Options
```bash
# Show all options
python iototscanner.py --help

# Verbose logging for debugging
python iototscanner.py 192.168.1.1 --verbose

# Custom timeout and thread count
python iototscanner.py 192.168.1.0/24 --timeout 5 --threads 20

# Usage examples
python iototscanner.py --examples
```
