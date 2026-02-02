import importlib
import pkgutil
import asyncio
from omnistrike.plugins.base import BasePlugin
from omnistrike.verifiers.base import BaseVerifier

class VulnerabilityVerifierPlugin(BasePlugin):
    def __init__(self):
        self.proxy_manager = None
        self.verifiers = []
        self._load_verifiers()

    @property
    def name(self):
        return "VulnerabilityVerifier"

    @property
    def description(self):
        return "Performs safe, non-destructive verification of high-impact vulnerabilities."

    def _load_verifiers(self):
        import omnistrike.verifiers as verifiers_pkg
        for _, name, is_pkg in pkgutil.iter_modules(verifiers_pkg.__path__):
            if is_pkg or name == 'base':
                continue

            module = importlib.import_module(f'omnistrike.verifiers.{name}')
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, BaseVerifier) and attr is not BaseVerifier:
                    self.verifiers.append(attr())

    async def run(self, target, data):
        if not self.verifiers:
            print("[*] No verifier modules loaded.")
            return

        print(f"[*] Running {len(self.verifiers)} verification check(s)...")
        verification_results = []

        ips = data.get('ips', [])
        if not ips and target.replace('.', '').isdigit():
            ips = [target]

        for ip in ips:
            for verifier in self.verifiers:
                print(f"[*] Executing {verifier.name} on {ip}...")
                result = await verifier.verify(ip, data, self.proxy_manager)
                if result:
                    print(f"[!] VERIFICATION CONFIRMED: {verifier.name} on {ip}")
                    verification_results.append(result)

        data['verification_results'] = verification_results
