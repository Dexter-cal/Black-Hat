import asyncio
import asyncssh
from omnistrike.plugins.base import BasePlugin

class SecurityBaselineAuditorPlugin(BasePlugin):
    def __init__(self):
        self.checks = [
            ("ls -ld /tmp", "Verify /tmp permissions"),
            ("cat /etc/shadow | grep -v '*' | grep -v '!'", "Identify accounts with set passwords"),
            ("find / -perm -4000 -type f 2>/dev/null", "Identify SUID binaries"),
            ("cat /etc/ssh/sshd_config | grep RootLogin", "Check SSH Root Login configuration"),
            ("ls -la /root/.bash_history", "Check for root bash history"),
            ("sysctl net.ipv4.ip_forward", "Check IP forwarding status"),
            ("dpkg -l | grep rsh", "Check for legacy insecure packages (rsh)"),
            ("cat /etc/pam.d/common-password", "Audit password complexity policy")
        ]

    @property
    def name(self):
        return "SecurityBaselineAuditor"

    @property
    def description(self):
        return "Performs a deep security baseline audit on Linux hosts to identify hardening gaps."

    async def run(self, target, data):
        creds_found = data.get('credentials_found', {})
        if not creds_found:
            return

        print(f"[*] Starting Security Baseline Audit...")
        baseline_results = {}

        for ip, creds in creds_found.items():
            for cred in creds:
                if cred['service'] == 'ssh':
                    print(f"[*] Auditing {ip} baseline...")
                    findings = []
                    try:
                        async with asyncssh.connect(ip, username=cred['username'], password=cred['password'], known_hosts=None) as conn:
                            for cmd, desc in self.checks:
                                res = await conn.run(cmd)
                                findings.append({
                                    "check": desc,
                                    "output": res.stdout[:200].strip()
                                })
                        baseline_results[ip] = findings
                        break
                    except:
                        pass

        data['security_baseline'] = baseline_results
