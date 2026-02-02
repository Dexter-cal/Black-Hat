import asyncio
import asyncssh
import re
from omnistrike.plugins.base import BasePlugin

class KernelEscalationAuditorPlugin(BasePlugin):
    def __init__(self):
        # Known vulnerable kernel patterns (simplified)
        self.vuln_kernels = [
            (r"linux version 4\.1[0-5]\.", "Dirty Pipe susceptibility (CVE-2022-0847)"),
            (r"linux version 5\.8\.", "Potential PwnKit/Polkit escalation"),
            (r"linux version 2\.6\.", "Legacy kernel with multiple known escalation vectors")
        ]

    @property
    def name(self):
        return "KernelEscalationAuditor"

    @property
    def description(self):
        return "Audits host kernel and system configuration for privilege escalation risks."

    async def run(self, target, data):
        compromised_hosts = data.get('compromised_hosts', {})
        if not compromised_hosts:
            return

        print(f"[*] Starting KernelEscalationAuditor...")
        escalation_risks = {}

        for ip, creds in compromised_hosts.items():
            for cred in creds:
                if cred['service'] == 'ssh':
                    print(f"[*] Auditing {ip} for escalation vectors...")
                    risks = []
                    try:
                        async with asyncssh.connect(ip, username=cred['username'], password=cred['password'], known_hosts=None) as conn:
                            # Check kernel version
                            res = await conn.run("cat /proc/version")
                            if res.stdout:
                                ver = res.stdout.lower()
                                for pattern, msg in self.vuln_kernels:
                                    if re.search(pattern, ver):
                                        risks.append({
                                            "type": "Kernel",
                                            "finding": msg,
                                            "details": res.stdout.strip(),
                                            "severity": "CRITICAL"
                                        })

                            # Check for writable /etc/passwd or similar (misconfiguration)
                            res = await conn.run("ls -l /etc/passwd | awk '{print $1}'")
                            if res.stdout and 'w' in res.stdout[7:10]:
                                 risks.append({
                                    "type": "Config",
                                    "finding": "Writable /etc/passwd detected",
                                    "severity": "CRITICAL"
                                })

                        if risks:
                            escalation_risks[ip] = risks
                        break
                    except Exception as e:
                        print(f"[!] KernelAuditor failed on {ip}: {e}")

        data['escalation_risks'] = escalation_risks
