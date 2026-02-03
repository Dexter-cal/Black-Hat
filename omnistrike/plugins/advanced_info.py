import asyncio
import asyncssh
from omnistrike.plugins.base import BasePlugin

class AdvancedInfoPlugin(BasePlugin):
    @property
    def name(self):
        return "AdvancedSystemInfo"

    @property
    def description(self):
        return "Performs deep-dive system discovery within active sessions (Kernel, Users, Network, Security)."

    async def run(self, target, data):
        sessions = self.session_manager.list_sessions()
        if not sessions:
            return

        print(f"[*] Starting AdvancedSystemInfo gathering on {len(sessions)} session(s)...")

        for session in sessions:
            if session.status != "Active": continue
            print(f"[*] Deep-diving into Session {session.id} ({session.target})...")

            try:
                # 1. OS & Kernel
                res = await session.conn.run("uname -a")
                session.info['kernel'] = res.stdout.strip()

                # 2. Hostname & Uptime
                res = await session.conn.run("hostname && uptime")
                session.info['uptime'] = res.stdout.strip().replace('\n', ' | ')

                # 3. User & Groups
                res = await session.conn.run("id")
                session.info['identity'] = res.stdout.strip()

                # 4. Network Config
                res = await session.conn.run("ip addr show | grep 'inet ' | awk '{print $2}'")
                session.info['interfaces'] = res.stdout.strip().split('\n')

                # 5. Installed Apps (Heuristic)
                res = await session.conn.run("ls /usr/bin | head -n 20")
                session.info['app_preview'] = res.stdout.strip().replace('\n', ', ')

                # 6. Security Posture
                res = await session.conn.run("ls -d /opt/CrowdStrike /opt/sentinelone 2>/dev/null")
                session.info['security_indicators'] = res.stdout.strip() or "None detected via path probe"

                print(f"    [+] Intelligence profile updated for Session {session.id}")
            except Exception as e:
                print(f"[!] Intelligence gathering failed for Session {session.id}: {e}")

        # Update global results data for reporting
        data['session_intelligence'] = {s.id: s.info for s in sessions}
