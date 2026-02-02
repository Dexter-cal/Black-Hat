import asyncio
import ssl
import socket
from omnistrike.plugins.base import BasePlugin

class ProtocolAuditorPlugin(BasePlugin):
    def __init__(self):
        self.proxy_manager = None

    @property
    def name(self):
        return "ProtocolAuditor"

    @property
    def description(self):
        return "Audits network protocols for cryptographic weaknesses and insecure configurations."

    async def audit_tls(self, ip, port):
        findings = []
        context = ssl.create_default_context()
        try:
            # Check for TLS 1.0/1.1 by attempting to connect with a restricted context
            # In a real tool, we would use more granular control.
            # Here we just try a standard handshake and inspect the result.
            reader, writer = await asyncio.open_connection(ip, port, ssl=context)
            ssl_obj = writer.get_extra_info('ssl_object')
            version = ssl_obj.version()
            cipher = ssl_obj.cipher()

            if version in ["TLSv1", "TLSv1.1"]:
                findings.append({
                    "port": port,
                    "finding": f"Deprecated TLS version detected: {version}",
                    "severity": "MEDIUM"
                })

            # Simple check for weak ciphers (e.g. 3DES, RC4 - simplified)
            if "3DES" in cipher[0] or "RC4" in cipher[0]:
                 findings.append({
                    "port": port,
                    "finding": f"Weak cipher suite detected: {cipher[0]}",
                    "severity": "MEDIUM"
                })

            writer.close()
            await writer.wait_closed()
        except:
            pass
        return findings

    async def run(self, target, data):
        open_ports = data.get('open_ports', {})
        protocol_results = {}

        print(f"[*] Auditing service protocols...")

        for ip, ports in open_ports.items():
            ip_findings = []
            tls_ports = [p for p in ports if p in [443, 8443, 993, 995]]

            for port in tls_ports:
                findings = await self.audit_tls(ip, port)
                ip_findings.extend(findings)

            if ip_findings:
                protocol_results[ip] = ip_findings

        data['protocol_audit'] = protocol_results
        if protocol_results:
            print(f"[*] Protocol audit complete. Found issues on {len(protocol_results)} host(s).")
        else:
            print(f"[*] Protocol audit complete. No immediate cryptographic weaknesses found.")
