import asyncio
import asyncssh
from omnistrike.plugins.base import BasePlugin

class SupplyChainAuditorPlugin(BasePlugin):
    def __init__(self):
        # Known vulnerable package versions (simplified database)
        self.vuln_packages = {
            "requests": "2.25.0",
            "django": "3.2.0",
            "log4j": "2.14.0",
            "openssl": "1.1.1"
        }

    @property
    def name(self):
        return "SupplyChainAuditor"

    @property
    def description(self):
        return "Analyzes target manifest files for vulnerable dependencies and supply chain risks."

    async def run(self, target, data):
        compromised_hosts = data.get('compromised_hosts', {})
        if not compromised_hosts:
            return

        print(f"[*] Starting SupplyChainAuditor analysis...")
        vuln_dependencies = {}

        for ip, creds in compromised_hosts.items():
            for cred in creds:
                if cred['service'] == 'ssh':
                    print(f"[*] Auditing manifests on {ip}...")
                    found_vulns = []
                    try:
                        async with asyncssh.connect(ip, username=cred['username'], password=cred['password'], known_hosts=None) as conn:
                            # Search for requirements.txt or similar
                            cmd = "find / -name 'requirements.txt' -maxdepth 4 2>/dev/null | xargs cat 2>/dev/null"
                            res = await conn.run(cmd)
                            if res.stdout:
                                for line in res.stdout.strip().split('\n'):
                                    for pkg, version in self.vuln_packages.items():
                                        if pkg in line.lower():
                                            found_vulns.append({
                                                "package": pkg,
                                                "match": line.strip(),
                                                "severity": "HIGH",
                                                "finding": f"Potentially vulnerable {pkg} version detected in manifest."
                                            })

                        if found_vulns:
                            vuln_dependencies[ip] = found_vulns
                        break
                    except Exception as e:
                        print(f"[!] SupplyChainAuditor failed on {ip}: {e}")

        data['supply_chain_vulns'] = vuln_dependencies
