from omnistrike.plugins.base import BasePlugin
from omnistrike.media_converter import MediaPayloadConverter
import os

class PolyglotGeneratorPlugin(BasePlugin):
    @property
    def name(self):
        return "PolyglotGenerator"

    @property
    def description(self):
        return "Generates polyglot research files and weaponized media carriers."

    async def run(self, target, data):
        carrier = data.get('carrier_file')
        payload = data.get('custom_payload', 'alert("OmniStrike Apex Payload Executed")')

        if not carrier:
            print("[!] No carrier file provided for polyglot generation. Using default hybrid.")
            hybrid_file = "research_hybrid.py.zip"
            with open(hybrid_file, 'wb') as f:
                f.write(b'# This is a Python script\nprint("OmniStrike Hybrid Executed")\n')
            data['polyglot_discovery'] = f"Hybrid file generated: {hybrid_file}"
            return

        print(f"[*] Weaponizing carrier: {carrier}...")
        converter = MediaPayloadConverter()
        try:
            out_path = converter.convert_auto(carrier, payload)
            print(f"[!!!] SUCCESS: Weaponized carrier ready at {out_path}")
            data['polyglot_discovery'] = f"Weaponized carrier: {out_path}"
        except Exception as e:
            print(f"[!] Weaponization failed: {e}")
