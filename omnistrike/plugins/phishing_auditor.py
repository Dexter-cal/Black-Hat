import asyncio
import aiodns
from omnistrike.plugins.base import BasePlugin

class PhishingSurfaceAuditorPlugin(BasePlugin):
    @property
    def name(self):
        return "PhishingSurfaceAuditor"

    @property
    def description(self):
        return "Audits organizational DNS and web infrastructure for phishing and social engineering susceptibility."

    async def check_dns(self, resolver, target):
        findings = []
        try:
            # Check SPF
            res = await resolver.query(target, 'TXT')
            spf_found = False
            for r in res:
                if 'v=spf1' in r.text.decode():
                    spf_found = True
                    break
            if not spf_found:
                findings.append("Missing SPF record: High susceptibility to email spoofing.")

            # Check DMARC
            res = await resolver.query(f"_dmarc.{target}", 'TXT')
            if not res:
                findings.append("Missing DMARC record: Inability to enforce email security policies.")
        except:
            findings.append("Incomplete email security DNS records (SPF/DMARC) detected.")
        return findings

    async def run(self, target, data):
        print(f"[*] Auditing social engineering surface area for {target}...")
        resolver = aiodns.DNSResolver()

        dns_findings = await self.check_dns(resolver, target)

        # Check spider findings for insecure forms
        form_findings = []
        spider = data.get('spider_findings', {})
        for ip, sdata in spider.items():
            for form in sdata.get('forms', []):
                if 'password' in str(form.get('inputs', [])).lower() and not form['action'].startswith('https'):
                    form_findings.append({
                        "url": form['action'],
                        "issue": "Insecure password form (HTTP)",
                        "severity": "CRITICAL"
                    })

        data['phishing_surface'] = {
            "dns_risks": dns_findings,
            "insecure_forms": form_findings
        }

        if dns_findings or form_findings:
            print(f"[*] Phishing audit complete. Found {len(dns_findings) + len(form_findings)} security gaps.")
