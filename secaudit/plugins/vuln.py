import asyncio
import re
from secaudit.plugins.base import BasePlugin

class VulnPlugin(BasePlugin):
    def __init__(self):
        # A small demo database of vulnerable versions/patterns
        self.vuln_patterns = [
            (r"OpenSSH_([0-8]\..*)", "Potential legacy OpenSSH version. Check for various CVEs like CVE-2016-10708."),
            (r"Apache/2\.4\.([0-9]|[1-4][0-9])", "Potential legacy Apache 2.4 version. Check for CVE-2021-41773 and others."),
            (r"nginx/1\.1[0-7]\.", "Potential legacy nginx version. Check for recent vulnerabilities."),
            (r"PHP/([5-7]\..*)", "Legacy PHP version detected. Outdated and likely vulnerable.")
        ]

    @property
    def name(self):
        return "VulnerabilityMapper"

    @property
    def description(self):
        return "Maps discovered services to potential vulnerabilities based on banner analysis."

    async def run(self, target, data):
        print(f"[*] Analyzing services for vulnerabilities...")
        open_ports_data = data.get('open_ports', {})
        vulns_found = {}

        for ip, ports in open_ports_data.items():
            ip_vulns = []
            for port, banner in ports.items():
                if not banner:
                    continue

                for pattern, message in self.vuln_patterns:
                    if re.search(pattern, banner):
                        ip_vulns.append({
                            "port": port,
                            "banner": banner,
                            "finding": message
                        })

            if ip_vulns:
                vulns_found[ip] = ip_vulns

        data['vulnerabilities'] = vulns_found
        print(f"[*] Analysis complete. Found {sum(len(v) for v in vulns_found.values())} potential issues.")
