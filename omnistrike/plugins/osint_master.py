import asyncio
import aiohttp
import re
from omnistrike.plugins.base import BasePlugin

class OSINTMasterPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.common_emails = ['admin', 'info', 'contact', 'support', 'sales', 'hr', 'tech']

    @property
    def name(self):
        return "OSINTMaster"

    @property
    def description(self):
        return "Advanced OSINT and reconnaissance: email harvesting, technology detection, and social profiling."

    async def run(self, target, data):
        print(f"[*] Starting OSINTMaster reconnaissance on {target}...")

        # 1. AI-Guided Strategy
        strategy = await self.ai_engine.query(f"Recommend an OSINT strategy for the domain {target}")
        data['osint_strategy'] = strategy
        print(f"[*] AI Strategy: {strategy[:100]}...")

        # 2. Email Harvesting (Simplified heuristic)
        discovered_emails = [f"{e}@{target}" for e in self.common_emails]
        data['emails'] = discovered_emails

        # 3. Technology Detection (via StealthClient)
        tech_findings = []
        try:
            async with self.stealth_client.get_session() as session:
                url = f"http://{target}"
                masked_url, host = self.stealth_client.mask_url(url)
                headers = {'Host': host} if host else {}
                async with session.get(masked_url, headers=headers, timeout=5.0) as resp:
                    server = resp.headers.get('Server', 'Unknown')
                    powered_by = resp.headers.get('X-Powered-By', 'Unknown')
                    tech_findings.append(f"Web Server: {server}")
                    if powered_by != 'Unknown':
                        tech_findings.append(f"Powered By: {powered_by}")
        except:
            pass

        data['technologies'] = tech_findings
        print(f"[*] OSINT complete. Harvested {len(discovered_emails)} emails and {len(tech_findings)} tech signatures.")
