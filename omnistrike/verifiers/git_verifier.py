import aiohttp
from aiohttp_socks import ProxyConnector
from omnistrike.verifiers.base import BaseVerifier

class ExposedGitVerifier(BaseVerifier):
    @property
    def name(self):
        return "ExposedGitRepo"

    @property
    def description(self):
        return "Verifies the presence of an exposed .git directory."

    async def verify(self, target, data, proxy_manager=None):
        proxy_url = proxy_manager.get_random_proxy() if proxy_manager else None
        connector = ProxyConnector.from_url(proxy_url) if proxy_url else None

        async with aiohttp.ClientSession(connector=connector) as session:
            url = f"http://{target}/.git/config"
            try:
                async with session.get(url, timeout=3.0) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if "[core]" in text:
                            return {
                                "verifier": self.name,
                                "target": target,
                                "finding": "Exposed Git repository confirmed",
                                "severity": "HIGH"
                            }
            except:
                pass
        return None
