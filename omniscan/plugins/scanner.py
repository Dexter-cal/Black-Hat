import asyncio
from omniscan.plugins.base import BasePlugin

class ScannerPlugin(BasePlugin):
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

    @property
    def name(self):
        return "Scanner"

    @property
    def description(self):
        return "Fast asynchronous port scanner and service discovery."

    async def scan_port(self, ip, port):
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1.0)

            banner = ""
            try:
                # Try to read a banner
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner = banner_data.decode('utf-8', errors='ignore').strip()
            except:
                pass

            writer.close()
            await writer.wait_closed()
            return port, True, banner
        except:
            return port, False, None

    async def run(self, target, data):
        # We use the IPs discovered in the previous step
        ips = data.get('ips', [])
        if not ips:
            # If no IPs found (e.g. target was a domain that didn't resolve or was already an IP)
            # Try treating the target itself as an IP if it looks like one
            if target.replace('.', '').isdigit():
                ips = [target]
            else:
                print(f"[!] No IPs to scan for {target}")
                return

        print(f"[*] Starting port scan for {len(ips)} IP(s)...")
        scan_results = {}

        for ip in ips:
            print(f"[*] Scanning {ip}...")
            open_ports = {}
            tasks = [self.scan_port(ip, port) for port in self.common_ports]
            results = await asyncio.gather(*tasks)

            for port, is_open, banner in results:
                if is_open:
                    open_ports[port] = banner

            scan_results[ip] = open_ports
            print(f"[*] Found {len(open_ports)} open ports on {ip}.")

        data['open_ports'] = scan_results
