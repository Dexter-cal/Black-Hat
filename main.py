import asyncio
import sys
import argparse
import json
from omniscan.core import Engine

BANNER = r"""
  ____  __  __ _   _ ___ ____   ____    _    _   _
 / __ \|  \/  | \ | |_ _/ ___| / ___|  / \  | \ | |
| |  | | |\/| |  \| || |\___ \| |     / _ \ |  \| |
| |__| | |  | | |\  || | ___) | |___ / ___ \| |\  |
 \____/|_|  |_|_| \_|___|____/ \____/_/   \_\_| \_|

      Advanced Security Auditing Framework
"""

async def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="OmniScan - Advanced Security Auditing Framework")
    parser.add_argument("target", help="The target domain or IP to audit")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    engine = Engine()
    engine.load_plugins()

    print(f"[*] Initializing scan on {args.target}...")
    results = await engine.run(args.target)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"[*] Results saved to {args.output}")
    else:
        print("\n" + "="*50)
        print("                SCAN SUMMARY")
        print("="*50)
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
        else:
            print("\n[+] No common vulnerabilities identified via banner analysis.")

        print("="*50)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)
