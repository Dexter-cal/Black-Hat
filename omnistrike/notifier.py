import os
import json
import urllib.request

class OmniAlert:
    """
    Multi-channel notification system for real-time alerting.
    """
    def __init__(self):
        self.config = {
            'telegram_token': os.getenv('TELEGRAM_TOKEN', ''),
            'telegram_chat_id': os.getenv('TELEGRAM_CHAT_ID', ''),
            'slack_webhook': os.getenv('SLACK_WEBHOOK', ''),
            'discord_webhook': os.getenv('DISCORD_WEBHOOK', '')
        }

    def notify(self, message):
        print(f"🔔 [OmniAlert] {message}")

        # 1. Telegram
        if self.config['telegram_token'] and self.config['telegram_chat_id']:
            self._send_telegram(message)

        # 2. Slack
        if self.config['slack_webhook']:
            self._send_slack(message)

        # 3. Discord
        if self.config['discord_webhook']:
            self._send_discord(message)

    def _send_telegram(self, message):
        url = f"https://api.telegram.org/bot{self.config['telegram_token']}/sendMessage"
        data = {'chat_id': self.config['telegram_chat_id'], 'text': message}
        try:
            req = urllib.request.Request(url, json.dumps(data).encode(), {'Content-Type': 'application/json'})
            urllib.request.urlopen(req)
        except: pass

    def _send_slack(self, message):
        data = {'text': message}
        try:
            req = urllib.request.Request(self.config['slack_webhook'], json.dumps(data).encode(), {'Content-Type': 'application/json'})
            urllib.request.urlopen(req)
        except: pass

    def _send_discord(self, message):
        data = {'content': message}
        try:
            req = urllib.request.Request(self.config['discord_webhook'], json.dumps(data).encode(), {'Content-Type': 'application/json'})
            urllib.request.urlopen(req)
        except: pass
