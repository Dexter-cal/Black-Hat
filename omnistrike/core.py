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

        print(f"[*] OmniStrike completed for {target}")
        return self.data
