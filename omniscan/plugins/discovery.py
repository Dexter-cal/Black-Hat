import asyncio
import aiodns
from omniscan.plugins.base import BasePlugin

class DiscoveryPlugin(BasePlugin):
    def __init__(self):
        self.common_subdomains = ['www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp', 'vpn', 'm', 'shop', 'ftp', 'dev', 'api']

    @property
    def name(self):
        return "Discovery"

    @property
    def description(self):
        return "Performs DNS discovery and subdomain enumeration."

    async def resolve(self, resolver, host):
        try:
            res = await resolver.query(host, 'A')
            return [r.host for r in res]
        except:
            return []

    async def run(self, target, data):
        resolver = aiodns.DNSResolver()
        print(f"[*] Resolving target: {target}")

        target_ips = await self.resolve(resolver, target)
        data['ips'] = target_ips

        if not target.replace('.', '').isdigit(): # If it's a domain
            print(f"[*] Starting subdomain enumeration for {target}...")
            subdomains_found = {}

            tasks = []
            for sub in self.common_subdomains:
                hostname = f"{sub}.{target}"
                tasks.append(self.resolve(resolver, hostname))

            results = await asyncio.gather(*tasks)

            for sub, ips in zip(self.common_subdomains, results):
                if ips:
                    hostname = f"{sub}.{target}"
                    subdomains_found[hostname] = ips

            data['subdomains'] = subdomains_found
            print(f"[*] Found {len(subdomains_found)} subdomains.")
        else:
            print(f"[*] Target appears to be an IP address. Skipping subdomain enumeration.")
