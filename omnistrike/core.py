import asyncio
import importlib
import pkgutil
import aiohttp
import random
from omnistrike.plugins.base import BasePlugin
from omnistrike.proxymanager import ProxyManager
from omnistrike.adapters.base import get_adapter
from aiohttp_socks import ProxyConnector

class StealthClient:
    """
    Advanced C2 client with domain fronting and traffic blending capabilities.
    """
    def __init__(self, proxy_manager=None, front_domain=None):
        self.proxy_manager = proxy_manager
        self.front_domain = front_domain or "cdn.microsoft.com"
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]

    def get_session(self):
        """
        Returns a session configured for stealthy communication.
        """
        proxy_url = self.proxy_manager.get_random_proxy() if self.proxy_manager else None
        connector = ProxyConnector.from_url(proxy_url) if proxy_url else None

        headers = {
            'User-Agent': random.choice(self.user_agents)
        }

        # In a real scenario, the connector or a middleware would handle domain fronting.
        # For this implementation, plugins will use this session and we provide a helper
        # to mask the URL.
        return aiohttp.ClientSession(connector=connector, headers=headers)

    def mask_url(self, url):
        """
        Masks the URL for domain fronting.
        """
        if self.front_domain:
            parts = url.split('/')
            if len(parts) > 2:
                target_host = parts[2]
                return url.replace(target_host, self.front_domain), target_host
        return url, None

class Engine:
    def __init__(self, proxies=None, front_domain=None):
        self.plugins = []
        self.data = {}
        self.proxy_manager = ProxyManager(proxies)
        self.stealth_client = StealthClient(self.proxy_manager, front_domain)
        self.adapter = get_adapter()

    def load_plugins(self):
        """Discover and load plugins from the plugins directory."""
        import omnistrike.plugins as plugins_pkg
        for _, name, is_pkg in pkgutil.iter_modules(plugins_pkg.__path__):
            if is_pkg or name == 'base':
                continue

            module = importlib.import_module(f'omnistrike.plugins.{name}')
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr is not BasePlugin:
                    print(f"[*] Loading plugin: {name}")
                    self.plugins.append(attr())

    async def run(self, target):
        print(f"[*] Starting OmniStrike on target: {target}")
        self.data['target'] = target

        # In a real scenario, we might want to define an execution order or dependency graph.
        # For simplicity, we'll run them in the order they are loaded or a predefined order.
        for plugin in self.plugins:
            print(f"[*] Running {plugin.name}...")
            # Pass core components to plugins
            plugin.proxy_manager = self.proxy_manager
            plugin.stealth_client = self.stealth_client
            plugin.adapter = self.adapter
            try:
                await plugin.run(target, self.data)
            except Exception as e:
                print(f"[!] Error in {plugin.name}: {e}")

        print(f"[*] Operation completed for {target}")
        return self.data

def print_summary(results):
    print("\n" + "="*60)
    print("                    APEX OPERATION SUMMARY")
    print("="*60)
    print(f"Target: {results.get('target')}")
    print(f"Profile: {results.get('operation_profile')} | Risk: {results.get('risk_level')}")

    subdomains = results.get('subdomains', {})
    if subdomains:
        print(f"\n[+] Subdomains Found: {len(subdomains)}")
        for sub, ips in subdomains.items():
            print(f"    - {sub} ({', '.join(ips)})")

    open_ports = results.get('open_ports', {})
    fingerprints = results.get('fingerprints', {})
    if open_ports:
        print("\n[+] Open Ports & Services:")
        for ip, ports in open_ports.items():
            fp = fingerprints.get(ip, "Unknown")
            print(f"    Target IP: {ip} (OS: {fp})")
            for port, banner in ports.items():
                banner_str = f" -> {banner}" if banner else ""
                print(f"      - Port {port}{banner_str}")

    vulnerabilities = results.get('vulnerabilities', {})
    if vulnerabilities:
        print("\n[!] Potential Vulnerabilities Found:")
        for ip, vulns in vulnerabilities.items():
            for v in vulns:
                print(f"      - Port {v['port']}: {v['finding']}")

    creds = results.get('credentials_found', {})
    if creds:
        print("\n[!!!] WEAK CREDENTIALS DISCOVERED:")
        for ip, c_list in creds.items():
            for c in c_list:
                print(f"      - [{c['service']}] {c['username']}:{c['password']}")

    exploits = results.get('exploit_findings', {})
    if exploits:
        print("\n[!!!] EXPLOITABLE MISCONFIGURATIONS:")
        for ip, findings in exploits.items():
            for f in findings:
                print(f"      - {f['finding']} ({f['url']})")

    spider = results.get('spider_findings', {})
    if spider:
        print("\n[+] Web Surfaces Discovered (Spider):")
        for ip, sdata in spider.items():
            print(f"      - URLs found: {len(sdata['urls'])}")
            print(f"      - Forms found: {len(sdata['forms'])}")

    verification = results.get('verification_results', {})
    if verification:
        print("\n[!!!] VULNERABILITY VERIFICATION SUCCESSFUL:")
        for r in verification:
            print(f"      - {r['verifier']} on {r['target']}: {r['finding']} (Severity: {r['severity']})")

    system_audit = results.get('persistence_findings', {})
    if system_audit:
        print("\n[!] SYSTEM AUDIT FINDINGS:")
        for ip, findings in system_audit.items():
            for f in findings:
                print(f"      - {f['check']}: {f['output_snippet'].strip()}")

    adv_sim = results.get('adversary_simulation', {})
    if adv_sim:
        print("\n[!] ADVERSARY SIMULATION LOG:")
        for ip, findings in adv_sim.items():
            for f in findings:
                print(f"      - {f['technique']}: {f['status']}")

    fuzzing = results.get('fuzzing_findings', {})
    if fuzzing:
        print("\n[!!!] WEB FUZZING VULNERABILITIES DETECTED:")
        for ip, findings in fuzzing.items():
            for f in findings:
                print(f"      - {f['finding']} at {f['url']} (Payload: {f['payload']})")

    protocol = results.get('protocol_audit', {})
    if protocol:
        print("\n[!] PROTOCOL SECURITY ISSUES:")
        for ip, findings in protocol.items():
            for f in findings:
                print(f"      - Port {f['port']}: {f['finding']} (Severity: {f['severity']})")

    cloud = results.get('cloud_storage', [])
    if cloud:
        print("\n[+] CLOUD STORAGE DISCOVERED:")
        for c in cloud:
            print(f"      - {c['status']}: {c['url']}")

    takeovers = results.get('subdomain_takeovers', [])
    if takeovers:
        print("\n[!!!] SUBDOMAIN TAKEOVER VULNERABILITIES:")
        for t in takeovers:
            print(f"      - {t['subdomain']} -> {t['service']}")

    leaks = results.get('data_leaks', [])
    if leaks:
        print("\n[!!!] DATA LEAKAGE DETECTED:")
        for l in leaks:
            print(f"      - [{l['type']}] {l['source']} (Severity: {l['severity']})")

    intelligence = results.get('exploit_intelligence', [])
    if intelligence:
        print("\n[!] OFFENSIVE BRAIN: EXPLOIT PATH RECOMMENDATIONS:")
        for path in intelligence[:3]:
            print(f"      - {path['target']} via {path['vector']} (Risk: {path['risk_score']} | {path['action']})")

    zeroclick = results.get('zeroclick_surfaces', {})
    if zeroclick:
        print("\n[!!!] ZERO-CLICK ATTACK SURFACES DETECTED:")
        for ip, findings in zeroclick.items():
            for f in findings:
                print(f"      - {ip}:{f['port']} -> {f['service']}")

    phishing = results.get('phishing_surface', {})
    if phishing:
        risks = phishing.get('dns_risks', [])
        if risks:
            print("\n[!] PHISHING SUSCEPTIBILITY (DNS):")
            for r in risks:
                print(f"      - {r}")

    stealth = results.get('stealth_strategy', {})
    if stealth:
        print(f"\n[!!!] STEALTH ORCHESTRATION: {stealth['operational_profile']}")
        print(f"      - ADVICE: {stealth['strategic_advice']}")

    messaging = results.get('messaging_artifacts', {})
    if messaging:
        print("\n[+] SECURE MESSAGING ARTIFACTS DISCOVERED:")
        for ip, findings in messaging.items():
            for f in findings:
                print(f"      - {f['app']} ({f['storage_type']}) at {f['path']}")

    triggers = results.get('triggered_operations', {})
    if triggers:
        print("\n[+] AUTONOMOUS CONTEXT TRIGGERS ACTIVATED:")
        for ip, t_list in triggers.items():
            for t in t_list:
                print(f"      - {t['rule']} ({t['status']})")

    memory = results.get('memory_indicators', {})
    if memory:
        print("\n[!!!] MEMORY-ONLY EXECUTION DETECTED:")
        for ip, indicators in memory.items():
            for ind in indicators:
                print(f"      - {ind['indicator']} (PID: {ind['pid']})")

    ai = results.get('ai_orchestration', {})
    if ai:
        print("\n[!!!] BEHAVIORAL AI ORCHESTRATION:")
        print(f"      - MODE: {ai['mode']}")
        print(f"      - INTENSITY: {ai['intensity_score']}")

    steg = results.get('stegano_status', '')
    if steg:
        print(f"\n[!!!] STEGANOGRAPHIC CHANNEL: {steg}")
        print(f"      - DECODED SAMPLE: {results.get('stegano_decoded_sample')}")

    print("\n" + "="*60)
