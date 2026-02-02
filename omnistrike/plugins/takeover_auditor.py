import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector
from omnistrike.plugins.base import BasePlugin

class SubdomainTakeoverPlugin(BasePlugin):
    def __init__(self):
        self.proxy_manager = None
        # Common service signatures indicating a potential takeover
        self.signatures = {
            "GitHub Pages": "There isn't a GitHub Pages site here.",
            "Heroku": "no such app",
            "S3 Bucket": "The specified bucket does not exist",
            "Shopify": "Sorry, this shop is currently unavailable.",
            "Tumblr": "Whatever you were looking for is not here.",
            "Squarespace": "Squarespace - Page Not Found",
            "Azure": "The resource you are looking for has been removed",
            "Fastly": "Fastly error: unknown domain"
        }

    @property
    def name(self):
        return "SubdomainTakeover"

    @property
    def description(self):
        return "Audits subdomains for potential takeover vulnerabilities (dangling CNAMEs)."

    async def check_takeover(self, session, subdomain):
        url = f"http://{subdomain}"
        try:
            async with session.get(url, timeout=3.0, allow_redirects=True) as resp:
                text = await resp.text()
                for service, signature in self.signatures.items():
                    if signature.lower() in text.lower():
                        return {
                            "subdomain": subdomain,
                            "service": service,
                            "severity": "CRITICAL",
                            "finding": f"Potential subdomain takeover on {service}"
                        }
        except:
            pass
        return None

    async def run(self, target, data):
        subdomains = data.get('subdomains', {})
        if not subdomains:
            print("[*] No subdomains to check for takeover.")
            return

        print(f"[*] Starting subdomain takeover audit for {len(subdomains)} subdomains...")
        takeover_results = []

        proxy_url = self.proxy_manager.get_random_proxy() if self.proxy_manager else None
        connector = ProxyConnector.from_url(proxy_url) if proxy_url else None

        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.check_takeover(session, sub) for sub in subdomains.keys()]
            results = await asyncio.gather(*tasks)
            for r in results:
                if r:
                    takeover_results.append(r)

        data['subdomain_takeovers'] = takeover_results
        if takeover_results:
            print(f"[*] Takeover audit complete. Identified {len(takeover_results)} potential vulnerabilities!")
        else:
            print(f"[*] Takeover audit complete. No dangling subdomains found.")
