import asyncio
import asyncssh
from omnistrike.plugins.base import BasePlugin

class AVEvasionAuditorPlugin(BasePlugin):
    def __init__(self):
        # Known security software signatures (Linux focus)
        self.security_sigs = [
            {"name": "CrowdStrike Falcon", "proc": "falcon-sensor", "path": "/opt/CrowdStrike"},
            {"name": "SentinelOne", "proc": "sentinelctl", "path": "/opt/sentinelone"},
            {"name": "Microsoft Defender", "proc": "mdatp", "path": "/opt/microsoft/mdatp"},
            {"name": "ClamAV", "proc": "clamd", "path": "/etc/clamav"},
            {"name": "Auditd", "proc": "auditd", "path": "/etc/audit"},
            {"name": "SELinux", "cmd": "sestatus", "keyword": "enabled"},
            {"name": "AppArmor", "cmd": "aa-status", "keyword": "profiles loaded"}
        ]

    @property
    def name(self):
        return "AVEvasionAuditor"

    @property
    def description(self):
        return "Detects EDR/AV presence and security monitoring to inform AI-driven evasion strategies."

    async def run(self, target, data):
        compromised_hosts = data.get('compromised_hosts', {})
        if not compromised_hosts:
            return

        print(f"[*] Starting AVEvasionAuditor on {len(compromised_hosts)} host(s)...")
        detection_results = {}

        for ip, creds in compromised_hosts.items():
            for cred in creds:
                if cred['service'] == 'ssh':
                    print(f"[*] Probing security posture on {ip}...")
                    found_software = []
                    try:
                        async with asyncssh.connect(ip, username=cred['username'], password=cred['password'], known_hosts=None) as conn:
                            for sig in self.security_sigs:
                                detected = False
                                if "proc" in sig:
                                    res = await conn.run(f"pgrep -f {sig['proc']}")
                                    if res.stdout:
                                        detected = True
                                elif "path" in sig:
                                    res = await conn.run(f"ls -d {sig['path']} 2>/dev/null")
                                    if res.stdout:
                                        detected = True
                                elif "cmd" in sig:
                                    res = await conn.run(sig['cmd'])
                                    if sig['keyword'].lower() in res.stdout.lower():
                                        detected = True

                                if detected:
                                    print(f"    [!] DETECTED: {sig['name']} on {ip}")
                                    found_software.append(sig['name'])

                        if found_software:
                            detection_results[ip] = found_software
                        break
                    except Exception as e:
                        print(f"[!] AVEvasionAuditor failed on {ip}: {e}")

        data['security_software'] = detection_results

        # Update AI Orchestration intensity if security software is present
        ai_data = data.get('ai_orchestration', {})
        if detection_results:
            print(f"[*] Adjusting Behavioral AI intensity due to detected security software.")
            ai_data['mode'] = "ULTRA_STEALTH: EDR/AV detected. Throttling operations to minimum."
            ai_data['intensity_score'] = min(ai_data.get('intensity_score', 1.0), 0.05)
            data['ai_orchestration'] = ai_data
