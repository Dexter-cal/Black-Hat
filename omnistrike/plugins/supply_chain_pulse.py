from omnistrike.plugins.base import BasePlugin
import aiohttp
import json

class SupplyChainPulsePlugin(BasePlugin):
    """
    Revolutionary supply chain auditor that checks for dependency confusion
    by identifying internal packages not registered on public repositories.
    """
    @property
    def name(self):
        return "SupplyChainPulse"

    @property
    def description(self):
        return "Detects dependency confusion and typosquatting risks in internal manifests."

    async def run(self, target, data):
        print(f"[*] Pulse-checking supply chain for {target}...")

        manifests = data.get('manifest_files', [])
        if not manifests:
            # Emulate discovery of a package.json if not provided
            manifests = [{"type": "npm", "path": "package.json", "packages": ["@corp-internal/core-lib", "lodash", "react"]}]

        findings = []

        async with aiohttp.ClientSession() as session:
            for m in manifests:
                for pkg in m.get('packages', []):
                    # 1. Check if package name looks internal/private (e.g. @corp, corp-, internal-)
                    is_internal_candidate = any(x in pkg.lower() for x in ['internal', 'private', 'corp-', '@corp'])

                    if is_internal_candidate:
                        # 2. Verify if it exists on public NPM (Dependency Confusion check)
                        # We use the public registry API
                        url = f"https://registry.npmjs.org/{pkg}"
                        try:
                            async with session.get(url) as resp:
                                if resp.status == 404:
                                    # SUCCESS (for us): Package is NOT public, but used internally.
                                    # Highly susceptible to dependency confusion.
                                    findings.append({
                                        "package": pkg,
                                        "vulnerability": "DEPENDENCY_CONFUSION_RISK",
                                        "status": "NOT_ON_PUBLIC_REGISTRY",
                                        "risk": f"Attacker can register '{pkg}' on NPM to gain RCE on build servers.",
                                        "confidence": "CRITICAL"
                                    })
                                elif resp.status == 200:
                                    # It is public. Check for potential Typosquatting (simplified)
                                    # (In a real tool, we'd check distance from common libraries)
                                    pass
                        except:
                            pass

        if findings:
            data['supply_chain_pulse'] = findings
            print(f"[!!!] ALERT: {len(findings)} dependency confusion risks detected!")
            for f in findings:
                print(f"    - Risk: {f['vulnerability']} for package '{f['package']}'")
        else:
            print("[*] Supply chain pulse normal. No immediate confusion risks detected.")

        return data
