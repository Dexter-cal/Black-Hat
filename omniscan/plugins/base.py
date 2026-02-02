import abc

class BasePlugin(abc.ABC):
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
