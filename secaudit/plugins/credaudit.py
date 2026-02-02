import asyncio
import asyncssh
import random
from secaudit.plugins.base import BasePlugin

class CredentialAuditPlugin(BasePlugin):
    def __init__(self):
        # Expanded common credentials
        self.credentials = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("root", "root"), ("root", "password"), ("root", "123456"), ("root", "toor"),
            ("user", "user"), ("user", "password"),
            ("pi", "raspberry"), ("ubuntu", "ubuntu"), ("guest", "guest"),
            ("support", "support"), ("sysadmin", "sysadmin")
        ]
        self.max_attempts_per_source = 3
        # Simulated "source IPs" for rotation
        self.simulated_sources = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]

    @property
    def name(self):
        return "CredentialAudit"

    @property
    def description(self):
        return "Tests for weak credentials with smart account and IP rotation simulation."

    async def check_ssh(self, ip, username, password, source_ip):
        # In a real tool, this would bind to a specific local interface or use a proxy.
        # Here we simulate the rotation by printing the source.
        # print(f"    [SIMULATION] Attempting from source IP: {source_ip}")
        try:
            # Note: asyncssh doesn't easily let us mock the local address without a real interface,
            # so we just simulate the logic.
            async with asyncssh.connect(ip, username=username, password=password, known_hosts=None) as conn:
                return True
        except:
            return False

    async def run(self, target, data):
        open_ports = data.get('open_ports', {})
        audit_results = {}

        # Load external credentials if provided in data (e.g. from config)
        creds_to_test = data.get('audit_wordlist', self.credentials)

        for ip, ports in open_ports.items():
            if 22 in ports or "22" in ports:
                print(f"[*] Starting credential audit on {ip}:22...")
                found_creds = []

                random.shuffle(creds_to_test)

                current_source_index = 0
                attempts_from_current_source = 0

                for username, password in creds_to_test:
                    if attempts_from_current_source >= self.max_attempts_per_source:
                        current_source_index = (current_source_index + 1) % len(self.simulated_sources)
                        attempts_from_current_source = 0
                        print(f"[*] [ROTATION] Rotating to simulated source IP: {self.simulated_sources[current_source_index]}")

                    # print(f"[*] Testing {username}:{password} on {ip}...")
                    success = await self.check_ssh(ip, username, password, self.simulated_sources[current_source_index])
                    attempts_from_current_source += 1

                    if success:
                        print(f"[!] SUCCESS: Found valid credentials for {ip}: {username}:{password}")
                        found_creds.append({"username": username, "password": password, "service": "ssh"})
                        # For auditing, we might want to find ALL weak creds or just one.
                        # Here we'll stop for this host after finding one.
                        break

                    await asyncio.sleep(0.2)

                if found_creds:
                    audit_results[ip] = found_creds

        data['credentials_found'] = audit_results
        if audit_results:
            print(f"[*] Credential audit complete. Found {sum(len(v) for v in audit_results.values())} valid credentials!")
        else:
            print(f"[*] Credential audit complete. No weak credentials found.")
