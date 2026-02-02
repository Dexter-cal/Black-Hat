# OmniStrike Elite

OmniStrike Elite is a high-performance, modular adversary emulation and red team automation framework. It is designed to simulate sophisticated threat actor behaviors at scale.

## Features

- **Advanced Reconnaissance**: Intelligent discovery, port scanning, and OS fingerprinting.
- **Smart Exploitation**: Automated credential auditing with REAL proxy rotation and rate-limit evasion.
- **Persistent Footholds**: Automated deployment of persistence mechanisms (e.g., SSH authorized keys).
- **Remote Execution**: Post-exploitation command execution across all compromised infrastructure.
- **Vulnerability Research**: Automated identification and verification of high-impact vulnerabilities.
- **Cloud & Web Auditing**: Dedicated modules for cloud storage (S3/Azure/GCP) and deep web surface discovery.
- **Professional Reporting**: Detailed JSON data and sanitized HTML reports with remediation intelligence.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Audit a target domain or IP:
```bash
python3 main.py example.com
```

Automated run with proxy list and custom wordlist:
```bash
python3 main.py example.com -p proxies.txt -w wordlist.txt
```

## Ethical Use

This tool is for authorized red teaming and adversary emulation only. Always obtain explicit permission before use.
