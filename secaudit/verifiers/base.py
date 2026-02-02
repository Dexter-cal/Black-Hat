class BaseVerifier:
    @property
    def name(self):
        pass

    @property
    def description(self):
        pass

    async def verify(self, target, data, proxy_manager=None):
        """
        Perform a safe, non-destructive verification check.
        :param target: The target string.
        :param data: Shared data.
        :return: Finding dictionary if verified, else None.
        """
        pass
