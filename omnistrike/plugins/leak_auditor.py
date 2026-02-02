import re
from omnistrike.plugins.base import BasePlugin

class DataLeakageAuditorPlugin(BasePlugin):
    def __init__(self):
        self.patterns = {
            "AWS API Key": r"AKIA[0-9A-Z]{16}",
            "Generic Secret": r"secret[_-]?key['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z]{32,45}['\"]?",
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
            "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "Internal IP": r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
        }

    @property
    def name(self):
        return "DataLeakageAuditor"

    @property
    def description(self):
        return "Scans discovered data for sensitive patterns and potential data leakage."

    async def run(self, target, data):
        # We can scan banners, spidered content, etc.
        # For now, let's scan banners and any findings collected.
        print(f"[*] Starting Data Leakage Audit...")
        leaks = []

        # Scan banners
        open_ports = data.get('open_ports', {})
        for ip, ports in open_ports.items():
            for port, banner in ports.items():
                if banner:
                    for name, pattern in self.patterns.items():
                        if re.search(pattern, banner):
                            leaks.append({
                                "source": f"{ip}:{port} (Banner)",
                                "type": name,
                                "severity": "HIGH"
                            })

        # Scan spidered URLs (simplified, we'd normally scan content)
        spider = data.get('spider_findings', {})
        for ip, sdata in spider.items():
            for url in sdata.get('urls', []):
                for name, pattern in self.patterns.items():
                    if re.search(pattern, url):
                        leaks.append({
                            "source": url,
                            "type": name,
                            "severity": "MEDIUM"
                        })

        data['data_leaks'] = leaks
        if leaks:
            print(f"[*] Data leakage audit complete. Found {len(leaks)} potential leaks.")
        else:
            print(f"[*] Data leakage audit complete. No sensitive patterns detected.")
