import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector
from omnistrike.plugins.base import BasePlugin

class CloudStorageAuditorPlugin(BasePlugin):
    def __init__(self):
        self.proxy_manager = None
        self.platforms = {
            "AWS S3": "http://{bucket}.s3.amazonaws.com",
            "Azure Blob": "https://{bucket}.blob.core.windows.net",
            "Google Cloud Storage": "https://storage.googleapis.com/{bucket}"
        }
        self.common_suffixes = ["", "-assets", "-data", "-backup", "-files", "-staging", "-dev", "-public"]

    @property
    def name(self):
        return "CloudStorageAuditor"

    @property
    def description(self):
        return "Discovers and audits exposed cloud storage buckets (S3, Azure, GCP)."

    async def check_bucket(self, session, url):
        try:
            async with session.get(url, timeout=3.0) as resp:
                if resp.status == 200:
                    # Check for "ListBucket" or similar in XML to confirm public listing
                    text = await resp.text()
                    is_public = "ListBucketResult" in text or "ListAllMyBucketsResult" in text or resp.status == 200
                    return {
                        "url": url,
                        "status": "PUBLIC" if is_public else "EXISTS",
                        "severity": "HIGH" if is_public else "INFO"
                    }
        except:
            pass
        return None

    async def run(self, target, data):
        # Target is usually a domain like example.com
        base_name = target.split('.')[0]

        print(f"[*] Starting Cloud Storage Audit for {target}...")
        cloud_results = []

        proxy_url = self.proxy_manager.get_random_proxy() if self.proxy_manager else None
        connector = ProxyConnector.from_url(proxy_url) if proxy_url else None

        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for platform, url_pattern in self.platforms.items():
                for suffix in self.common_suffixes:
                    bucket_name = f"{base_name}{suffix}"
                    url = url_pattern.format(bucket=bucket_name)
                    tasks.append(self.check_bucket(session, url))

            results = await asyncio.gather(*tasks)
            for r in results:
                if r:
                    cloud_results.append(r)

        data['cloud_storage'] = cloud_results
        if cloud_results:
            print(f"[*] Cloud audit complete. Found {len(cloud_results)} potential buckets.")
        else:
            print(f"[*] Cloud audit complete. No buckets discovered.")
