import asyncio
import asyncssh
from omniscan.plugins.base import BasePlugin

class PersistenceAuditorPlugin(BasePlugin):
    def __init__(self):
        self.checks = [
            ("ls -la /root/.ssh/authorized_keys", "Check for root authorized keys"),
            ("crontab -l", "Check for user cron jobs"),
            ("ls -la /etc/cron.*", "Check for system-wide cron jobs"),
            ("systemctl list-unit-files --state=enabled", "Check for enabled systemd services"),
            ("cat /etc/passwd", "Audit system users")
        ]

    @property
    def name(self):
        return "PersistenceAuditor"

    @property
    def description(self):
        return "Audits host for common persistence mechanisms using discovered credentials."

    async def run(self, target, data):
        creds_found = data.get('credentials_found', {})
        if not creds_found:
            print("[*] No credentials available. Skipping persistence audit.")
            return

        print(f"[*] Starting persistence audit on {len(creds_found)} IP(s)...")
        persistence_results = {}

        for ip, creds in creds_found.items():
            for cred in creds:
                if cred['service'] == 'ssh':
                    print(f"[*] Auditing persistence on {ip} as {cred['username']}...")
                    findings = []
                    try:
                        async with asyncssh.connect(ip, username=cred['username'], password=cred['password'], known_hosts=None) as conn:
                            for cmd, desc in self.checks:
                                result = await conn.run(cmd)
                                if result.stdout:
                                    findings.append({
                                        "check": desc,
                                        "output_snippet": result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout
                                    })
                        if findings:
                            persistence_results[ip] = findings
                            break # Found for one user, move to next IP
                    except Exception as e:
                        print(f"[!] Persistence audit failed for {ip}: {e}")

        data['persistence_findings'] = persistence_results
        if persistence_results:
             print(f"[*] Persistence audit complete. Found entries on {len(persistence_results)} IP(s).")
        else:
             print(f"[*] Persistence audit complete. No suspicious entries found.")
