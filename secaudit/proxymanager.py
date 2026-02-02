import random

class ProxyManager:
    def __init__(self, proxies=None):
        """
        :param proxies: A list of proxy URLs, e.g., ["socks5://user:pass@127.0.0.1:1080", "http://1.2.3.4:8080"]
        """
        self.proxies = proxies or []
        self.current_index = 0

    def get_next_proxy(self):
        if not self.proxies:
            return None

        proxy = self.proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        return proxy

    def get_random_proxy(self):
        if not self.proxies:
            return None
        return random.choice(self.proxies)

    @classmethod
    def from_file(cls, filepath):
        with open(filepath, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
        return cls(proxies)
