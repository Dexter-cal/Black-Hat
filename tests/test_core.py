import unittest
import asyncio
from omnistrike.core import Engine
from omnistrike.plugins.base import BasePlugin

class MockPlugin(BasePlugin):
    @property
    def name(self):
        return "Mock"

    @property
    def description(self):
        return "Mock Description"

    async def run(self, target, data):
        data['mock_run'] = True

class TestEngine(unittest.TestCase):
    def test_load_plugins(self):
        engine = Engine()
        engine.load_plugins()
        # Should have loaded discovery, scanner, and vuln
        self.assertGreaterEqual(len(engine.plugins), 3)

    def test_run_engine(self):
        engine = Engine()
        mock = MockPlugin()
        engine.plugins = [mock]

        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(engine.run("localhost"))

        self.assertTrue(results.get('mock_run'))
        self.assertEqual(results.get('target'), "localhost")

if __name__ == "__main__":
    unittest.main()
