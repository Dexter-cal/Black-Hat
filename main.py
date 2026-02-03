import asyncio
import sys
import argparse
import json
import yaml
from omnistrike.core import Engine
from omnistrike.installer import DependencyInstaller

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

    # Auto-install dependencies
    DependencyInstaller.check_and_install()

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
        '1': ['behavioral_ai', 'memory_phantom', 'context_trigger', 'system_auditor', 'av_evasion', 'messaging_auditor', 'stealth_orchestrator', 'consensus_ai'],
        '2': ['discovery', 'scanner', 'credaudit', 'exploit_scanner', 'vuln_verifier', 'lateral_pivoter', 'kernel_auditor', 'supply_chain_auditor', 'foothold', 'remote_exec', 'exploit_intelligence', 'zeroclick_auditor', 'swarm_orchestrator', 'vuln_intel', 'attack_lab'],
        '3': ['polymorphic_plugin', 'stegano_plugin', 'polyglot_plugin', 'delivery_suite'],
        '4': ['stealth_c2', 'leak_auditor', 'spider', 'web_fuzzer', 'protocol_auditor', 'phishing_auditor', 'osint_master']
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
        from omnistrike.core import print_summary
        print_summary(results)

    # Enter Interactive Session Shell if sessions exist
    if engine.session_manager.sessions:
        await session_shell(engine.session_manager)

async def session_shell(session_manager):
    print("\n[!] ENTERING SOVEREIGN SESSION CONSOLE")
    print("[*] Command Summary: sessions -l, use <id>, ai <prompt>, exit")

    while True:
        try:
            line = await asyncio.get_event_loop().run_in_executor(None, input, "sovereign> ")
            parts = line.strip().split()
            if not parts: continue

            cmd = parts[0]
            if cmd == 'exit':
                break
            elif cmd == 'sessions':
                if len(parts) > 1 and parts[1] == '-l':
                    print("\n--- SOVEREIGN ASSETS: ACTIVE SESSIONS ---")
                    for s in session_manager.list_sessions():
                        print(f"[{s.id}] {s.target} - {s.info.get('user', 'unknown')}@{s.target} ({s.status})")
                else:
                    print("[*] Usage: sessions -l")
            elif cmd == 'use':
                if len(parts) > 1:
                    sid = parts[1]
                    session = session_manager.get_session(sid)
                    if session:
                        await interact(session)
                    else:
                        print(f"[!] Asset {sid} not found.")
                else:
                    print("[*] Usage: use <id>")
            elif cmd == 'ai':
                prompt = " ".join(parts[1:])
                # In a real shell, we'd have access to the engine's AI engine
                print(f"[*] AI (SIMULATED): Analysis for '{prompt}' initiated.")
            elif cmd == 'swarm':
                if len(parts) > 1:
                    swarm_cmd = " ".join(parts[1:])
                    print(f"[*] Executing Swarm Command: {swarm_cmd}")
                    # This would ideally call the plugin, but for the shell we can just loop
                    for s in session_manager.list_sessions():
                        if s.status == "Active":
                            try:
                                res = await asyncio.get_event_loop().create_task(s.conn.run(swarm_cmd))
                                print(f"--- Session {s.id} ({s.target}) ---\n{res.stdout.strip()}")
                            except Exception as e:
                                print(f"[!] Session {s.id} failed: {e}")
                else:
                    print("[*] Usage: swarm <command>")
            else:
                print(f"[!] Unknown command: {cmd}")
        except EOFError:
            break

async def interact(session):
    print(f"[*] Interacting with Session {session.id} ({session.target})")
    print("[*] Type 'bg' to background, 'info' for system data.")

    while True:
        line = await asyncio.get_event_loop().run_in_executor(None, input, f"session({session.id})> ")
        cmd = line.strip()
        if cmd == 'bg':
            break
        elif cmd == 'info':
            print(f"\n--- SYSTEM INFO: {session.target} ---")
            for k, v in session.info.items():
                print(f"{k.upper()}: {v}")
        else:
            # Here we would execute the command on the remote host
            # For now, we emulate the response or proxy it
            try:
                # Use the active connection (e.g. asyncssh)
                if hasattr(session.conn, 'run'):
                    res = await session.conn.run(cmd)
                    print(res.stdout.strip() or res.stderr.strip())
            except Exception as e:
                print(f"[!] Execution error: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by operator.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Critical failure: {e}")
