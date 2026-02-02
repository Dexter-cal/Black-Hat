# OmniScan

OmniScan is a high-performance, modular security auditing and reconnaissance framework. It is designed to provide deep visibility into network infrastructure and help security researchers and administrators identify potential weaknesses.

## Features

- **Modular Plugin System**: Easily extend the framework with new auditing modules.
- **Asynchronous Execution**: Built with `asyncio` for high performance and scalability.
- **Smart Discovery**: Subdomain enumeration and DNS resolution.
- **Port Scanning**: Fast, non-blocking port scanning with service banner grabbing.
- **Vulnerability Mapping**: Automated identification of potential security issues based on service signatures.

## Installation

1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run a scan on a target domain or IP:
```bash
python3 main.py example.com
```

Save results to a JSON file:
```bash
python3 main.py example.com -o results.json
```

## Architecture

OmniScan uses a plugin-based architecture managed by a central engine:

- `omniscan/core.py`: The engine that loads and executes plugins.
- `omniscan/plugins/base.py`: The abstract base class for all plugins.
- `omniscan/plugins/`: Directory containing various auditing modules.
  - `discovery.py`: DNS and subdomain enumeration.
  - `scanner.py`: Port scanning and service fingerprinting.
  - `vuln.py`: Vulnerability analysis based on discovered services.

## Ethical Use

This tool is intended for legitimate security auditing and educational purposes only. Always obtain proper authorization before scanning any network infrastructure.
