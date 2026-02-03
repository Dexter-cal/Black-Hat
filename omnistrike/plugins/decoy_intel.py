from omnistrike.plugins.base import BasePlugin
import os
import re

class DecoyIntelligencePlugin(BasePlugin):
    """
    Identifies honeytokens, canary tokens, and security decoys to avoid detection.
    """
    @property
    def name(self):
        return "DecoyIntelligence"

    @property
    def description(self):
        return "Detects security decoys and honeytokens to prevent triggering alerts."

    async def run(self, target, data):
        print(f"[*] Analyzing {target} for security decoys and honeytokens...")

        findings = []

        # 1. DNS Canary Detection (Simulated DNS query check)
        # Often canary tokens use long, unique subdomains like <unique>.canarytokens.com
        if re.search(r'[a-zA-Z0-9-]{30,}\.(canarytokens|thinkst|dnslog)\.', target):
            findings.append({
                "type": "DNS_CANARY",
                "indicator": target,
                "confidence": "HIGH",
                "risk": "IMMEDIATE_ALERT_ON_LOOKUP"
            })

        # 2. Web Fingerprinting for Decoys
        # Some honeypots use specific headers or content signatures
        if 'http_headers' in data:
            headers = data['http_headers']
            if 'X-Honey' in headers or 'Server' in headers and 'Kippo' in headers['Server']:
                 findings.append({
                    "type": "WEB_HONEYPOT",
                    "indicator": f"Header: {headers.get('Server', 'Unknown')}",
                    "confidence": "HIGH",
                    "risk": "INTERACTION_LOGGED_BY_SEC_TEAM"
                })

        # 3. File Metadata Analysis (if files were harvested)
        # Identifying Thinkst Canary or other token authors
        if 'harvested_files' in data:
            for file_info in data['harvested_files']:
                author = file_info.get('metadata', {}).get('Author', '')
                if 'Thinkst' in author or 'Canary' in author:
                    findings.append({
                        "type": "FILE_CANARY",
                        "indicator": file_info['path'],
                        "confidence": "CRITICAL",
                        "risk": "OPENING_FILE_TRIGGERS_ALARM"
                    })

        # 4. Process-based Decoy Detection (Post-exploitation)
        # EDRs often inject decoy processes
        if 'system_processes' in data:
            for proc in data['system_processes']:
                if 'trap' in proc.lower() or 'honey' in proc.lower() or 'decoy' in proc.lower():
                     findings.append({
                        "type": "EDR_DECOY_PROCESS",
                        "indicator": proc,
                        "confidence": "MEDIUM",
                        "risk": "INTERACTING_WITH_PROCESS_ALERTS_EDR"
                    })

        if findings:
            data['decoy_intelligence'] = findings
            print(f"[!] WARNING: {len(findings)} decoys/honeytokens detected on {target}!")
            for f in findings:
                print(f"    - {f['type']}: {f['indicator']} (Risk: {f['risk']})")
        else:
            print("[*] No obvious decoys detected.")

        return data
