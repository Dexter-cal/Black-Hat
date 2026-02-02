import asyncio
import sys
import argparse
import json
import yaml
from omniscan.core import Engine

BANNER = r"""
  ____  __  __ _   _ ___ ____   ____    _    _   _
 / __ \|  \/  | \ | |_ _/ ___| / ___|  / \  | \ | |
| |  | | |\/| |  \| || |\___ \| |     / _ \ |  \| |
| |__| | |  | | |\  || | ___) | |___ / ___ \| |\  |
 \____/|_|  |_|_| \_|___|____/ \____/_/   \_\_| \_|

      Advanced Security Auditing Framework
      v2.0 - Automation & Exploit Discovery
"""

async def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="OmniScan - Advanced Security Auditing Framework")
    parser.add_argument("target", nargs="?", help="The target domain or IP to audit")
    parser.add_argument("-c", "--config", help="Configuration file (YAML)")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    if not args.target and not args.config:
        parser.print_help()
        return

    config = {}
    if args.config:
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)

    target = args.target or config.get('target')
    if not target:
        print("[!] No target specified.")
        return

    engine = Engine()
    engine.load_plugins()

    # We could pass config to plugins here if we wanted to

    print(f"[*] Initializing scan on {target}...")
    results = await engine.run(target)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"[*] Results saved to {args.output}")
    else:
        print_summary(results)

def print_summary(results):
    print("\n" + "="*60)
    print("                    SCAN SUMMARY")
    print("="*60)
    print(f"Target: {results.get('target')}")

    subdomains = results.get('subdomains', {})
    if subdomains:
        print(f"\n[+] Subdomains Found: {len(subdomains)}")
        for sub, ips in subdomains.items():
            print(f"    - {sub} ({', '.join(ips)})")

    open_ports = results.get('open_ports', {})
    if open_ports:
        print("\n[+] Open Ports & Services:")
        for ip, ports in open_ports.items():
            print(f"    Target IP: {ip}")
            for port, banner in ports.items():
                banner_str = f" -> {banner}" if banner else ""
                print(f"      - Port {port}{banner_str}")

    vulnerabilities = results.get('vulnerabilities', {})
    if vulnerabilities:
        print("\n[!] Potential Vulnerabilities Found:")
        for ip, vulns in vulnerabilities.items():
            print(f"    Target IP: {ip}")
            for v in vulns:
                print(f"      - Port {v['port']}: {v['finding']}")

    creds = results.get('credentials_found', {})
    if creds:
        print("\n[!!!] WEAK CREDENTIALS DISCOVERED:")
        for ip, c_list in creds.items():
            print(f"    Target IP: {ip}")
            for c in c_list:
                print(f"      - [{c['service']}] {c['username']}:{c['password']}")

    exploits = results.get('exploit_findings', {})
    if exploits:
        print("\n[!!!] EXPLOITABLE MISCONFIGURATIONS:")
        for ip, findings in exploits.items():
            print(f"    Target IP: {ip}")
            for f in findings:
                print(f"      - {f['finding']} ({f['url']})")

    persistence = results.get('persistence_findings', {})
    if persistence:
        print("\n[!] PERSISTENCE ENTRIES DETECTED:")
        for ip, findings in persistence.items():
            print(f"    Target IP: {ip}")
            for f in findings:
                print(f"      - {f['check']}: {f['output_snippet'].strip()}")

    print("\n" + "="*60)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)
