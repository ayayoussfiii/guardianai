"""
filter.py — Filtrage et sanitisation des réponses du LLM
Dernière ligne de défense avant de renvoyer la réponse à l'utilisateur
"""

from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass
class FilterResult:
    is_safe       : bool
    original_text : str
    filtered_text : str
    details       : str


# ── Patterns dangers 

DANGEROUS_OUTPUT_PATTERNS = [
    (r"(?i)here('s| is) how to (make|build|create) (a )?(bomb|weapon|malware|virus)", "instruction dangereuse"),
    (r"(?i)step\s*\d+.*?(hack|exploit|bypass|inject)",                                "guide d'attaque"),
    (r"sk-[a-zA-Z0-9]{48}",                                                           "clé API exposée"),
    (r"AKIA[0-9A-Z]{16}",                                                             "clé AWS exposée"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",                                       "clé privée exposée"),
    (r"(?i)(password|secret|token)\s*[:=]\s*['\"]?\S+['\"]?",                        "credential exposé"),
]

# ── Patterns à masquer (PII dans les réponses) ────────────────────────────────

MASK_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b",                                        "***-**-****"),
    (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",                     "**** **** **** ****"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",          "[email masqué]"),
    (r"\b(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "[téléphone masqué]"),
]


class ResponseFilter:

    def __init__(self):
        self._dangerous = [(re.compile(p), label) for p, label in DANGEROUS_OUTPUT_PATTERNS]
        self._mask      = [(re.compile(p), replacement) for p, replacement in MASK_PATTERNS]

    def filter(self, text: str) -> FilterResult:
        """
        Analyse et nettoie la réponse du LLM.
        - Bloque si contenu dangereux détecté
        - Masque les données sensibles sinon
        """

        # 1. Vérification contenu dangereux → bloquer
        for pattern, label in self._dangerous:
            if pattern.search(text):
                return FilterResult(
                    is_safe=False,
                    original_text=text,
                    filtered_text="[Réponse bloquée par GuardianAI : contenu dangereux détecté]",
                    details=f"Contenu bloqué : {label}",
                )

        # 2. Masquage des donnees sensibles → laisser passer nettoye
        cleaned = text
        masked_items = []

        for pattern, replacement in self._mask:
            new_text, count = pattern.subn(replacement, cleaned)
            if count > 0:
                cleaned = new_text
                masked_items.append(f"{count} occurrence(s) masquée(s)")

        details = "Réponse propre" if not masked_items else " | ".join(masked_items)

        return FilterResult(
            is_safe=True,
            original_text=text,
            filtered_text=cleaned,
            details=details,
        )
