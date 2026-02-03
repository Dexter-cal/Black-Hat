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
      Automated Red Team Operations v4.0 (APEX)
"""

def parse_args():
    parser = argparse.ArgumentParser(description="OmniStrike Apex - Advanced Adversary Emulation Framework")

    # 1-4: Operation Modes
    parser.add_argument("--mode", choices=['1', '2', '3', '4', 'implant', 'exploit', 'generate', 'c2'],
                        help="Operation Mode: 1:implant, 2:exploit, 3:generate, 4:c2")

    # 5: Target
    parser.add_argument("-t", "--target", help="Target device, IP, or application")

    # 6-8: Profiles
    parser.add_argument("--profile", choices=['1', '2', '3', 'stealth', 'aggressive', 'research'],
                        help="Behavior Profile: 1:stealth, 2:aggressive, 3:research")

    # 9: Timeout
    parser.add_argument("--timeout", type=int, default=300, help="Operation timeout in seconds")

    # Arguments for various plugins
    parser.add_argument("-c", "--config", help="Configuration file (YAML)")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-p", "--proxies", help="Proxy list file")
    parser.add_argument("-w", "--wordlist", help="Credential wordlist")
    parser.add_argument("-f", "--front", help="Domain fronting host")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    # Red-Team Specific Options (Flags)
    parser.add_argument("--zero-click", action="store_true", help="10: Prefer zero-click vectors")
    parser.add_argument("--one-click", action="store_true", help="11: Allow one-click vectors")
    parser.add_argument("--risk", choices=['1', '2', '3'], help="14-16: Risk Level (1:Low, 2:Med, 3:High)")
    parser.add_argument("--kernel-mode", action="store_true", help="17: Attempt kernel-level escalation")
    parser.add_argument("--stealth", action="store_true", help="29: Maximize stealth operation")
    parser.add_argument("--memory-only", action="store_true", help="31: Memory-resident operation only")
    parser.add_argument("--burn-phase", action="store_true", help="33: Self-destruct triggers enabled")

    return parser.parse_args()

async def main():
    print(BANNER)
    args = parse_args()

    if not args.target and not args.config:
        print("[!] No target or configuration specified.")
        return

    config = {}
    if args.config:
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)

    target = args.target or config.get('target')
    if not target:
        print("[!] No target specified.")
        return

    # Map numbered modes/profiles
    mode = args.mode or config.get('mode', '2')
    profile = args.profile or config.get('profile', '3')

    # Configure plugin selection based on mode
    # Mode 1: Implant (Shadow surveillance)
    # Mode 2: Exploit (Infiltration & Pivot)
    # Mode 3: Generate (Weaponization research)
    # Mode 4: C2 (Exfiltration & Orchestration)

    mode_plugins = {
        '1': ['behavioral_ai', 'memory_phantom', 'context_trigger', 'system_auditor', 'av_evasion', 'messaging_auditor', 'stealth_orchestrator'],
        '2': ['discovery', 'scanner', 'credaudit', 'exploit_scanner', 'vuln_verifier', 'lateral_pivoter', 'kernel_auditor', 'supply_chain_auditor', 'foothold', 'remote_exec', 'exploit_intelligence', 'zeroclick_auditor'],
        '3': ['polymorphic_plugin', 'stegano_plugin', 'polyglot_plugin'],
        '4': ['stealth_c2', 'leak_auditor', 'spider', 'web_fuzzer', 'protocol_auditor', 'phishing_auditor']
    }

    mode_plugins['implant'] = mode_plugins['1']
    mode_plugins['exploit'] = mode_plugins['2']
    mode_plugins['generate'] = mode_plugins['3']
    mode_plugins['c2'] = mode_plugins['4']

    selected_plugins = mode_plugins.get(mode, mode_plugins['2'])

    proxies = []
    if args.proxies:
        with open(args.proxies, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
    elif config.get('proxies'):
        proxies = config.get('proxies')

    engine = Engine(proxies=proxies, front_domain=args.front or config.get('front_domain'))
    engine.load_plugins()

    # Filter engine plugins based on selected mode
    engine.plugins = [p for p in engine.plugins if p.__class__.__module__.split('.')[-1] in selected_plugins]

    if args.wordlist:
        with open(args.wordlist, 'r') as f:
            engine.data['audit_wordlist'] = [line.strip().split(':') for line in f if ':' in line]

    # Add profile/risk data
    engine.data['operation_profile'] = profile
    engine.data['risk_level'] = args.risk or '2'
    engine.data['stealth_mode'] = args.stealth
    engine.data['memory_resident'] = args.memory_only

    print(f"[*] Initializing APEX operation on {target} [Mode:{mode} Profile:{profile}]...")
    results = await engine.run(target)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"[*] Results saved to {args.output}")
    else:
        from omnistrike.core import print_summary # We'll move it there for cleanliness
        print_summary(results)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by operator.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Critical failure: {e}")
