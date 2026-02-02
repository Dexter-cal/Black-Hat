import asyncio
import sys
import argparse
import json
import yaml
from omnistrike.core import Engine

BANNER = r"""
   ____                 _  _____ _        _ _
  / __ \               (_)/ ____| |      (_) |
 | |  | |_ __ ___  _ __  _| (___ | |_ _ __ _| | _____
 | |  | | '_ ` _ \| '_ \| |\___ \| __| '__| | |/ / _ \
 | |__| | | | | | | | | | |____) | |_| |  | |   <  __/
  \____/|_| |_| |_|_| |_|_|_____/ \__|_|  |_|_|\_\___|

      Advanced Adversary Emulation Framework
      Automated Red Team Operations v3.0
"""

async def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="OmniStrike - Advanced Security Auditing Framework")
    parser.add_argument("target", nargs="?", help="The target domain or IP to audit")
    parser.add_argument("-c", "--config", help="Configuration file (YAML)")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-p", "--proxies", help="File containing proxy URLs (one per line)")
    parser.add_argument("-w", "--wordlist", help="Credential wordlist for auditing (user:pass format)")
    parser.add_argument("-f", "--front", help="Domain to use for domain fronting (e.g., cdn.microsoft.com)")
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

    proxies = []
    if args.proxies:
        with open(args.proxies, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
    elif config.get('proxies'):
        proxies = config.get('proxies')

    engine = Engine(proxies=proxies, front_domain=args.front or config.get('front_domain'))
    engine.load_plugins()

    if args.wordlist:
        with open(args.wordlist, 'r') as f:
            engine.data['audit_wordlist'] = [line.strip().split(':') for line in f if ':' in line]

    print(f"[*] Initializing operation on {target}...")
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
    fingerprints = results.get('fingerprints', {})
    if open_ports:
        print("\n[+] Open Ports & Services:")
        for ip, ports in open_ports.items():
            fp = fingerprints.get(ip, "Unknown")
            print(f"    Target IP: {ip} (OS: {fp})")
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

    spider = results.get('spider_findings', {})
    if spider:
        print("\n[+] Web Surfaces Discovered (Spider):")
        for ip, sdata in spider.items():
            print(f"    Target IP: {ip}")
            print(f"      - URLs found: {len(sdata['urls'])}")
            print(f"      - Forms found: {len(sdata['forms'])}")

    verification = results.get('verification_results', {})
    if verification:
        print("\n[!!!] VULNERABILITY VERIFICATION SUCCESSFUL:")
        for r in verification:
            print(f"      - {r['verifier']} on {r['target']}: {r['finding']} (Severity: {r['severity']})")

    system_audit = results.get('persistence_findings', {})
    if system_audit:
        print("\n[!] SYSTEM AUDIT FINDINGS:")
        for ip, findings in system_audit.items():
            print(f"    Target IP: {ip}")
            for f in findings:
                print(f"      - {f['check']}: {f['output_snippet'].strip()}")

    adv_sim = results.get('adversary_simulation', {})
    if adv_sim:
        print("\n[!] ADVERSARY SIMULATION LOG:")
        for ip, findings in adv_sim.items():
            print(f"    Target IP: {ip}")
            for f in findings:
                print(f"      - {f['technique']}: {f['status']}")

    fuzzing = results.get('fuzzing_findings', {})
    if fuzzing:
        print("\n[!!!] WEB FUZZING VULNERABILITIES DETECTED:")
        for ip, findings in fuzzing.items():
            print(f"    Target IP: {ip}")
            for f in findings:
                print(f"      - {f['finding']} at {f['url']} (Payload: {f['payload']})")

    protocol = results.get('protocol_audit', {})
    if protocol:
        print("\n[!] PROTOCOL SECURITY ISSUES:")
        for ip, findings in protocol.items():
            print(f"    Target IP: {ip}")
            for f in findings:
                print(f"      - Port {f['port']}: {f['finding']} (Severity: {f['severity']})")

    cloud = results.get('cloud_storage', [])
    if cloud:
        print("\n[+] CLOUD STORAGE DISCOVERED:")
        for c in cloud:
            print(f"      - {c['status']}: {c['url']}")

    takeovers = results.get('subdomain_takeovers', [])
    if takeovers:
        print("\n[!!!] SUBDOMAIN TAKEOVER VULNERABILITIES:")
        for t in takeovers:
            print(f"      - {t['subdomain']} -> {t['service']}")

    leaks = results.get('data_leaks', [])
    if leaks:
        print("\n[!!!] DATA LEAKAGE DETECTED:")
        for l in leaks:
            print(f"      - [{l['type']}] {l['source']} (Severity: {l['severity']})")

    messaging = results.get('messaging_artifacts', {})
    if messaging:
        print("\n[+] SECURE MESSAGING ARTIFACTS DISCOVERED:")
        for ip, findings in messaging.items():
            print(f"    Target IP: {ip}")
            for f in findings:
                print(f"      - {f['app']} ({f['storage_type']}) at {f['path']}")

    triggers = results.get('triggered_operations', {})
    if triggers:
        print("\n[+] AUTONOMOUS CONTEXT TRIGGERS ACTIVATED:")
        for ip, t_list in triggers.items():
            print(f"    Target IP: {ip}")
            for t in t_list:
                print(f"      - {t['rule']} ({t['status']})")

    memory = results.get('memory_indicators', {})
    if memory:
        print("\n[!!!] MEMORY-ONLY EXECUTION DETECTED:")
        for ip, indicators in memory.items():
            print(f"    Target IP: {ip}")
            for ind in indicators:
                print(f"      - {ind['indicator']} (PID: {ind['pid']})")

    ai = results.get('ai_orchestration', {})
    if ai:
        print("\n[!!!] BEHAVIORAL AI ORCHESTRATION:")
        print(f"      - MODE: {ai['mode']}")
        print(f"      - INTENSITY: {ai['intensity_score']}")

    steg = results.get('stegano_status', '')
    if steg:
        print(f"\n[!!!] STEGANOGRAPHIC CHANNEL: {steg}")
        print(f"      - DECODED SAMPLE: {results.get('stegano_decoded_sample')}")

    print("\n" + "="*60)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)
