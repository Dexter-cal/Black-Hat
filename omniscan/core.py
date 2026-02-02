import asyncio
import importlib
import pkgutil
from omniscan.plugins.base import BasePlugin

class Engine:
    def __init__(self):
        self.plugins = []
        self.data = {}

    def load_plugins(self):
        """Discover and load plugins from the plugins directory."""
        import omniscan.plugins as plugins_pkg
        for _, name, is_pkg in pkgutil.iter_modules(plugins_pkg.__path__):
            if is_pkg or name == 'base':
                continue

            module = importlib.import_module(f'omniscan.plugins.{name}')
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr is not BasePlugin:
                    print(f"[*] Loading plugin: {name}")
                    self.plugins.append(attr())

    async def run(self, target):
        print(f"[*] Starting OmniScan on target: {target}")
        self.data['target'] = target

        # In a real scenario, we might want to define an execution order or dependency graph.
        # For simplicity, we'll run them in the order they are loaded or a predefined order.
        for plugin in self.plugins:
            print(f"[*] Running {plugin.name}...")
            try:
                await plugin.run(target, self.data)
            except Exception as e:
                print(f"[!] Error in {plugin.name}: {e}")

        print(f"[*] OmniScan completed for {target}")
        return self.data
