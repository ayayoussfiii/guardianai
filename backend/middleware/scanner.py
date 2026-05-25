import re
from typing import TypedDict


class ScanResult(TypedDict):
    flagged: bool
    reason: str | None


class Scanner:
   

    BLACKLIST_PATTERNS = [
        # Prompt injection classiques
        (r"ignore\s+(all\s+)?previous\s+instructions?", "Prompt injection détectée"),
        (r"disregard\s+(your\s+)?instructions?", "Prompt injection détectée"),
        (r"you\s+are\s+now\s+(a\s+)?(?!an?\s+assistant)", "Jailbreak rôle détecté"),
        (r"act\s+as\s+(if\s+you\s+are\s+)?(?!an?\s+assistant)", "Jailbreak rôle détecté"),
        (r"forget\s+(that\s+you\s+are|you\s+are)", "Jailbreak identité détecté"),
        (r"bypass\s+(your\s+)?(safety|filter|restriction)", "Tentative de bypass détectée"),
        (r"jailbreak", "Jailbreak explicite détecté"),
        (r"DAN\s+mode", "Mode DAN détecté"),

        # Tentatives d'extraction système
        (r"reveal\s+(your\s+)?(system\s+prompt|instructions?|prompt)", "Extraction système détectée"),
        (r"show\s+me\s+your\s+(system\s+)?prompt", "Extraction système détectée"),
        (r"what\s+(are|were)\s+your\s+instructions?", "Extraction système détectée"),

        # Injections de commandes
        (r"<\|?(system|im_start|im_end)\|?>", "Injection de token système"),
        (r"\[INST\]|\[\/INST\]", "Injection format instruction"),
    ]

    COMPILED = [(re.compile(p, re.IGNORECASE), reason) for p, reason in BLACKLIST_PATTERNS]

    MAX_LENGTH = 4000  # caractères max par prompt

    def scan(self, prompt: str) -> ScanResult:
        # Vérification longueur
        if len(prompt) > self.MAX_LENGTH:
            return {"flagged": True, "reason": f"Prompt trop long ({len(prompt)} chars > {self.MAX_LENGTH})"}

        # Vérification patterns
        for pattern, reason in self.COMPILED:
            if pattern.search(prompt):
                return {"flagged": True, "reason": reason}

        return {"flagged": False, "reason": None}
