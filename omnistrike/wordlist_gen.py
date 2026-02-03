import random

class WordlistGenerator:
    """
    AI-powered (simulated) targeted wordlist generator.
    """
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.base_terms = target_domain.split('.')[0].capitalize()
        self.years = [str(y) for y in range(2020, 2026)]
        self.specials = ["!", "@", "#", "$", "*"]

    def generate(self, count=500):
        print(f"[*] Generating targeted wordlist for {self.target_domain}...")
        words = set()

        mutations = [
            lambda x: x.lower(),
            lambda x: x.upper(),
            lambda x: x + "123",
            lambda x: x + random.choice(self.years),
            lambda x: x + random.choice(self.specials),
            lambda x: x.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0')
        ]

        base_set = [self.base_terms, "Admin", "Root", "Password", "Secure", "Login"]

        while len(words) < count:
            base = random.choice(base_set)
            mutated = base
            for _ in range(random.randint(1, 3)):
                mutated = random.choice(mutations)(mutated)
            words.add(mutated)

        return list(words)
