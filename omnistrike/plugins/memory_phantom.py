import asyncio
import asyncssh
from omnistrike.plugins.base import BasePlugin

class MemoryPhantomPlugin(BasePlugin):
    @property
    def name(self):
        return "MemoryPhantom"

    @property
    def description(self):
        return "Audits for memory-only execution and emulates stealthy RAM-resident TTPs."

    async def audit_linux_memory(self, conn):
        findings = []
        # Check for processes whose executable has been deleted from disk
        # This is a classic indicator of memory-only execution
        cmd = "ls -al /proc/*/exe 2>/dev/null | grep ' (deleted)'"
        result = await conn.run(cmd)
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                pid = line.split('/')[2]
                findings.append({
                    "indicator": "Process executing from deleted file (Memory-only)",
                    "pid": pid,
                    "details": line
                })

        # Check for memfd_create usage (anonymous memory files)
        cmd = "ls -al /proc/*/fd 2>/dev/null | grep 'memfd:'"
        result = await conn.run(cmd)
        if result.stdout:
             for line in result.stdout.strip().split('\n'):
                pid = line.split('/')[2]
                findings.append({
                    "indicator": "memfd_create usage detected",
                    "pid": pid,
                    "details": line
                })

        return findings

    async def run(self, target, data):
        compromised_hosts = data.get('compromised_hosts', {})
        if not compromised_hosts:
            return

        print(f"[*] Starting MemoryPhantom audit on {len(compromised_hosts)} host(s)...")
        memory_results = {}

        for ip, creds in compromised_hosts.items():
            for cred in creds:
                if cred['service'] == 'ssh':
                    print(f"[*] Auditing RAM for stealth signatures on {ip}...")
                    try:
                        async with asyncssh.connect(ip, username=cred['username'], password=cred['password'], known_hosts=None) as conn:
                            # 1. Audit for memory-only indicators
                            indicators = await self.audit_linux_memory(conn)

                            # 2. Emulation (Simulation of polymorphic/RAM-only behavior)
                            # We simulate the 'load in memory' behavior by using a bash one-liner
                            # that executes a script piped from stdin, leaving no trace on disk.
                            payload = 'echo "Memory-resident audit complete" && hostname'
                            emulation_cmd = f"bash -c 'eval \"$(cat <<EOF\n{payload}\nEOF\n)\"'"
                            await conn.run(emulation_cmd)

                            if indicators:
                                memory_results[ip] = indicators
                                print(f"[!!!] Detected {len(indicators)} memory indicators on {ip}")
                            else:
                                print(f"[*] No suspicious memory signatures found on {ip}")
                            break
                    except Exception as e:
                        print(f"[!] MemoryPhantom failed on {ip}: {e}")

        data['memory_indicators'] = memory_results
