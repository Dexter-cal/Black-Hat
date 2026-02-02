import yaml
import os

class Config:
    def __init__(self, config_path=None):
        self.settings = {
            'target': None,
            'verbose': False,
            'proxies': [],
            'plugins': [
                'discovery', 'scanner', 'vuln', 'credaudit',
                'exploit_scanner', 'system_auditor', 'spider', 'vuln_verifier'
            ],
            'max_threads': 10,
            'timeout': 5.0
        }
        if config_path and os.path.exists(config_path):
            self.load(config_path)

    def load(self, path):
        with open(path, 'r') as f:
            loaded_settings = yaml.safe_load(f)
            if loaded_settings:
                self.settings.update(loaded_settings)

    def get(self, key, default=None):
        return self.settings.get(key, default)
