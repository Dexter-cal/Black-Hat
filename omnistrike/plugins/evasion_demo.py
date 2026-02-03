from omnistrike.plugins.base import BasePlugin
from omnistrike.crypto import EncryptionEngine, EvasionOrchestrator

class EvasionDemoPlugin(BasePlugin):
    @property
    def name(self):
        return "EvasionDemo"

    @property
    def description(self):
        return "Demonstrates various obfuscation and evasion techniques."

    async def run(self, target, data):
        print("\n--- OMNISTRIKE EVASION DEMONSTRATION ---")
        payload = "whoami && cat /etc/shadow"
        print(f"Original Payload: {payload}")

        # Obfuscation
        print(f"Base64: {EncryptionEngine.base64_encode(payload)}")
        print(f"Hex: {EncryptionEngine.hex_encode(payload)}")
        xor_res = EncryptionEngine.xor_cipher(payload)
        print(f"XOR (key:OMNISTRIKE): {xor_res.hex()}")
        print(f"Multi-Layer: {EncryptionEngine.multi_layer_obfuscate(payload)}")

        # Fragmentation
        fragments = EvasionOrchestrator.fragment_packet(payload)
        print(f"Fragmented (size 4): {fragments}")

        # Timing
        delay = EvasionOrchestrator.get_adaptive_delay(120)
        randomized = EvasionOrchestrator.randomize_timing(delay)
        print(f"Adaptive Delay (Cycle 120): {delay}s")
        print(f"Randomized Timing: {randomized:.2f}s")

        data['evasion_demo_completed'] = True
        return data
