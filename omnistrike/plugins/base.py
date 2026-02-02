import abc

class BasePlugin(abc.ABC):
    def __init__(self):
        self.proxy_manager = None
        self.stealth_client = None
        self.adapter = None

    @abc.abstractmethod
    async def run(self, target, data):
        """
        Run the plugin logic.
        :param target: The target string (e.g., domain or IP).
        :param data: A shared dictionary for storing results between plugins.
        """
        pass

    @property
    @abc.abstractmethod
    def name(self):
        pass

    @property
    @abc.abstractmethod
    def description(self):
        pass
