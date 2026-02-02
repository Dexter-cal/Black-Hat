import asyncio
import importlib
import pkgutil
from secaudit.plugins.base import BasePlugin
from secaudit.proxymanager import ProxyManager

class Engine:
    def __init__(self, proxies=None):
        self.plugins = []
        self.data = {}
        self.proxy_manager = ProxyManager(proxies)

    def load_plugins(self):
        """Discover and load plugins from the plugins directory."""
        import secaudit.plugins as plugins_pkg
        for _, name, is_pkg in pkgutil.iter_modules(plugins_pkg.__path__):
            if is_pkg or name == 'base':
                continue

            module = importlib.import_module(f'secaudit.plugins.{name}')
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr is not BasePlugin:
                    print(f"[*] Loading plugin: {name}")
                    self.plugins.append(attr())

    async def run(self, target):
        print(f"[*] Starting SecAudit on target: {target}")
        self.data['target'] = target

        # In a real scenario, we might want to define an execution order or dependency graph.
        # For simplicity, we'll run them in the order they are loaded or a predefined order.
        for plugin in self.plugins:
            print(f"[*] Running {plugin.name}...")
            # Pass proxy manager to plugins that might need it
            plugin.proxy_manager = self.proxy_manager
            try:
                await plugin.run(target, self.data)
            except Exception as e:
                print(f"[!] Error in {plugin.name}: {e}")

        print(f"[*] SecAudit completed for {target}")
        return self.data
