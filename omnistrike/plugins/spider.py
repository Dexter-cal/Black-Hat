import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from omnistrike.plugins.base import BasePlugin

class SpiderPlugin(BasePlugin):
    def __init__(self):
        self.proxy_manager = None
        self.max_depth = 2
        self.max_pages = 50

    @property
    def name(self):
        return "Spider"

    @property
    def description(self):
        return "Deep recursive web crawler to discover hidden surfaces and parameters."

    async def crawl(self, session, url, depth, visited, discovered):
        if depth > self.max_depth or len(visited) >= self.max_pages or url in visited:
            return

        visited.add(url)
        # print(f"    [*] Crawling: {url}")

        try:
            async with session.get(url, timeout=3.0) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' in content_type:
                        text = await response.text()
                        soup = BeautifulSoup(text, 'html.parser')

                        # Find all links
                        for a in soup.find_all('a', href=True):
                            link = urljoin(url, a['href'])
                            if urlparse(link).netloc == urlparse(url).netloc:
                                await self.crawl(session, link, depth + 1, visited, discovered)

                        # Find forms and inputs (potential injection points)
                        for form in soup.find_all('form'):
                            discovered['forms'].append({
                                'action': urljoin(url, form.get('action')),
                                'method': form.get('method', 'get').upper(),
                                'inputs': [i.get('name') for i in form.find_all('input') if i.get('name')]
                            })

                    discovered['urls'].append(url)
        except:
            pass

    async def run(self, target, data):
        open_ports = data.get('open_ports', {})
        spider_results = {}

        proxy_url = self.proxy_manager.get_random_proxy() if self.proxy_manager else None
        connector = ProxyConnector.from_url(proxy_url) if proxy_url else None

        async with aiohttp.ClientSession(connector=connector) as session:
            for ip, ports in open_ports.items():
                web_ports = [p for p in ports if p in [80, 443, 8080, 8443]]
                if not web_ports:
                    continue

                print(f"[*] Starting spider on {ip}...")
                discovered = {'urls': [], 'forms': []}
                visited = set()

                for port in web_ports:
                    protocol = "https" if port in [443, 8443] else "http"
                    base_url = f"{protocol}://{ip}:{port}"
                    await self.crawl(session, base_url, 0, visited, discovered)

                if discovered['urls']:
                    spider_results[ip] = discovered
                    print(f"[*] Spider complete for {ip}. Discovered {len(discovered['urls'])} URLs and {len(discovered['forms'])} forms.")

        data['spider_findings'] = spider_results
