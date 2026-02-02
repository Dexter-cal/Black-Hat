# SecAudit Elite

SecAudit Elite is a high-performance, modular security auditing and reconnaissance framework. It is designed to provide security professionals with deep visibility into network infrastructure and host security posture.

## Features

- **Modular Plugin System**: Easily extend the framework with new auditing and discovery modules.
- **Asynchronous Execution**: Built with `asyncio` for high performance and scalability.
- **Advanced Reconnaissance**: Intelligent subdomain enumeration, DNS resolution, and OS fingerprinting.
- **Service & Vulnerability Mapping**: Automated identification of services and potential security issues via banner analysis.
- **Credential Strength Auditing**: Smart, rate-limit aware auditing of credential strength for common services (e.g., SSH).
- **Compromise Detection**: Modules for auditing host systems to identify indicators of compromise (IoCs).
- **Vulnerability Verification**: Safe, non-destructive verification of high-impact vulnerabilities.
- **Professional Reporting**: Detailed JSON and sanitized HTML reporting for audit documentation.

## Installation

1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run an audit on a target domain or IP:
```bash
python3 main.py example.com
```

Use a configuration file and proxies:
```bash
python3 main.py -c config.yaml -p proxies.txt
```

Generate an HTML report:
```bash
python3 generate_report.py results.json report.html
```

## Architecture

SecAudit uses a plugin-based architecture managed by a central engine:

- `secaudit/core.py`: The engine that loads and executes plugins.
- `secaudit/plugins/base.py`: The abstract base class for all plugins.
- `secaudit/plugins/`: Directory containing auditing modules.
  - `discovery.py`: DNS and subdomain enumeration.
  - `scanner.py`: Port scanning, service fingerprinting, and OS detection.
  - `credaudit.py`: Credential strength auditing with proxy rotation.
  - `exploit_scanner.py`: Web misconfiguration and sensitive file exposure scanner.
  - `persistence.py`: Host-based persistence mechanism auditor.

## Ethical Use

This tool is intended for legitimate security auditing, compliance verification, and educational purposes only. Always obtain proper authorization before scanning any network infrastructure. The authors are not responsible for any misuse of this tool.
