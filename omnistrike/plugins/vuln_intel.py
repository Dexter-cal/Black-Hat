from omnistrike.plugins.base import BasePlugin
import re

class VulnerabilityIntelligencePlugin(BasePlugin):
    @property
    def name(self):
        return "VulnerabilityIntelligence"

    @property
    def description(self):
        return "Deep-dive analysis of banners and content to identify sophisticated vulnerabilities like SSRF, XXE, and Deserialization."

    async def run(self, target, data):
        print(f"[*] Starting deep VulnerabilityIntelligence analysis...")

        findings = []
        open_ports = data.get('open_ports', {})

        for ip, ports in open_ports.items():
            for port, banner in ports.items():
                if not banner: continue

                # 1. Deserialization Indicators
                if any(x in banner.lower() for x in ['pickle', 'java', 'serialization', 'object']):
                    findings.append({
                        "ip": ip, "port": port, "type": "Potential Insecure Deserialization",
                        "severity": "HIGH", "confidence": 0.7, "recommendation": "Audit object serialization endpoints."
                    })

                # 2. XXE Indicators
                if any(x in banner.lower() for x in ['xml', 'soap', 'rest']):
                    findings.append({
                        "ip": ip, "port": port, "type": "Potential XML External Entity (XXE)",
                        "severity": "HIGH", "confidence": 0.6, "recommendation": "Disable external entity processing in XML parsers."
                    })

                # 3. SSRF Indicators
                if any(x in banner.lower() for x in ['proxy', 'webhook', 'gateway', 'fetch']):
                    findings.append({
                        "ip": ip, "port": port, "type": "Potential Server-Side Request Forgery (SSRF)",
                        "severity": "MEDIUM", "confidence": 0.5, "recommendation": "Implement strict whitelisting for outbound requests."
                    })

        data['deep_vulnerabilities'] = findings
        print(f"[*] Deep analysis complete. Found {len(findings)} sophisticated vulnerability indicators.")
