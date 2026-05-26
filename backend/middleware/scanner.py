"""
middleware/scanner.py
─────────────────────
Analyse statique d'un prompt avant tout traitement LLM.

Améliorations vs v1 :
  • Normalisation Unicode (homoglyphes, zero-width chars, encodages alternatifs)
  • Niveaux de sévérité : BLOCK / WARN (warn = logué mais non bloquant, configurable)
  • Rapport complet : toutes les correspondances trouvées, pas seulement la première
  • Patterns organisés par catégorie (dataclass) et facilement extensibles
  • Statistiques d'utilisation (nb scans, nb bloqués) pour observabilité
  • MAX_LENGTH synchronisé avec la validation Pydantic du router
"""

import logging
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import TypedDict

logger = logging.getLogger(__name__)


# ─── Contrats typés ──────────────────────────────────────────────────────────

class Severity(str, Enum):
    BLOCK = "block"   # Requête bloquée immédiatement
    WARN  = "warn"    # Loguée, non bloquante par défaut (configurable)


class Match(TypedDict):
    pattern:  str
    reason:   str
    severity: str


class ScanResult(TypedDict):
    flagged:  bool
    reason:   str | None   # raison principale (premier BLOCK ou premier WARN)
    matches:  list[Match]  # toutes les correspondances trouvées
    severity: str | None   # sévérité la plus haute


# ─── Définition des règles ───────────────────────────────────────────────────

@dataclass(frozen=True)
class Rule:
    pattern:  str
    reason:   str
    severity: Severity = Severity.BLOCK


# Règles groupées par catégorie pour la lisibilité et la maintenance
_RULES: list[Rule] = [

    # ── Prompt injection ──────────────────────────────────────────────────────
    Rule(r"ignore\s+(all\s+)?previous\s+instructions?",         "Prompt injection — previous instructions"),
    Rule(r"disregard\s+(your\s+)?instructions?",                "Prompt injection — disregard"),
    Rule(r"do\s+not\s+follow\s+(your\s+)?instructions?",        "Prompt injection — do not follow"),
    Rule(r"override\s+(your\s+)?(rules?|instructions?)",        "Prompt injection — override"),

    # ── Jailbreak identité / rôle ─────────────────────────────────────────────
    Rule(r"you\s+are\s+now\s+(?!an?\s+(helpful\s+)?assistant)", "Jailbreak — redéfinition de rôle"),
    Rule(r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(?!an?\s+(helpful\s+)?assistant)", "Jailbreak — act as"),
    Rule(r"forget\s+(that\s+you\s+are|you\s+are|your\s+)",      "Jailbreak — oubli d'identité"),
    Rule(r"pretend\s+(you\s+)?(are|have\s+no)",                 "Jailbreak — pretend"),
    Rule(r"you\s+have\s+no\s+(restrictions?|limits?|rules?)",   "Jailbreak — suppression de contraintes"),

    # ── Bypass explicite ──────────────────────────────────────────────────────
    Rule(r"bypass\s+(your\s+)?(safety|filter|restriction|guard|policy)", "Bypass — safety"),
    Rule(r"jailbreak",                                          "Bypass — jailbreak explicite"),
    Rule(r"\bDAN\s+mode\b",                                     "Bypass — mode DAN"),
    Rule(r"without\s+(any\s+)?(restrictions?|censorship|filters?)", "Bypass — sans restrictions"),

    # ── Extraction du prompt système ──────────────────────────────────────────
    Rule(r"reveal\s+(your\s+)?(system\s+prompt|instructions?|prompt)", "Extraction — system prompt"),
    Rule(r"show\s+(me\s+)?(your\s+)?(system\s+)?prompt",        "Extraction — show prompt"),
    Rule(r"what\s+(are|were)\s+your\s+instructions?",           "Extraction — instructions"),
    Rule(r"repeat\s+(the\s+)?(text|words?|content)\s+above",    "Extraction — repeat above"),
    Rule(r"output\s+(your\s+)?initial\s+(prompt|message)",      "Extraction — initial prompt"),

    # ── Injection de tokens / formats ─────────────────────────────────────────
    Rule(r"<\|?\s*(system|im_start|im_end)\s*\|?>",             "Injection — token système"),
    Rule(r"\[INST\]|\[\/INST\]",                                "Injection — format instruction"),
    Rule(r"<<SYS>>|<</SYS>>",                                   "Injection — balise système Llama"),
    Rule(r"###\s*System\s*:",                                    "Injection — header System"),

    # ── Signaux d'alerte (WARN, non bloquants par défaut) ────────────────────
    Rule(r"hypothetically\s+(speaking)?",                       "Signal — hypothetically",   Severity.WARN),
    Rule(r"for\s+(a\s+)?fiction(al)?\s+(story|novel|book)",     "Signal — fiction framing",  Severity.WARN),
    Rule(r"in\s+a\s+(video\s+)?game\s+context",                 "Signal — game framing",     Severity.WARN),
]

# Compilation unique au chargement du module
_COMPILED: list[tuple[re.Pattern, Rule]] = [
    (re.compile(rule.pattern, re.IGNORECASE), rule)
    for rule in _RULES
]


# ─── Normalisation ────────────────────────────────────────────────────────────

# Caractères zero-width et de contrôle Unicode courants dans les injections
_ZERO_WIDTH = re.compile(
    r"[\u200b\u200c\u200d\u2060\ufeff\u00ad"   # zero-width, soft-hyphen
    r"\u202a-\u202e"                            # directional overrides
    r"\u2066-\u2069]"                           # isolates
)

# Table de substitution des homoglyphes courants → ASCII
_HOMOGLYPHS: dict[str, str] = {
    "а": "a", "е": "e", "і": "i", "о": "o", "р": "p",  # cyrillique
    "ⅰ": "i", "ℐ": "i", "ℑ": "i",                        # math
    "０": "0", "１": "1",                                  # fullwidth
}
_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPHS)


def _normalize(text: str) -> str:
    """
    Prépare le texte pour la détection :
    1. NFC → forme canonique Unicode
    2. Suppression des caractères zero-width / directionnels
    3. Substitution des homoglyphes courants
    4. Remplacement des séquences d'espaces multiples par un espace simple
    """
    text = unicodedata.normalize("NFC", text)
    text = _ZERO_WIDTH.sub("", text)
    text = text.translate(_HOMOGLYPH_TABLE)
    text = re.sub(r"\s+", " ", text)
    return text


# ─── Scanner ─────────────────────────────────────────────────────────────────

class Scanner:
    """
    Analyse statique d'un prompt.

    Par défaut, seuls les BLOCK déclenchent `flagged=True`.
    Passer `block_on_warn=True` pour durcir la politique.
    """

    MAX_LENGTH = 8_192   # aligné avec la validation Pydantic du router

    def __init__(self, block_on_warn: bool = False):
        self.block_on_warn = block_on_warn
        self._scan_count  = 0
        self._block_count = 0

    # ── API publique ──────────────────────────────────────────────────────────

    def scan(self, prompt: str) -> ScanResult:
        self._scan_count += 1

        # ① Vérification longueur (avant normalisation pour la perf)
        if len(prompt) > self.MAX_LENGTH:
            self._block_count += 1
            return self._result(
                flagged=True,
                reason=f"Prompt trop long ({len(prompt)} > {self.MAX_LENGTH} chars)",
                severity=Severity.BLOCK,
            )

        normalized = _normalize(prompt)
        matches: list[Match] = []

        # ② Recherche de tous les patterns
        for compiled, rule in _COMPILED:
            if compiled.search(normalized):
                matches.append({
                    "pattern":  rule.pattern,
                    "reason":   rule.reason,
                    "severity": rule.severity.value,
                })

        if not matches:
            return self._result(flagged=False)

        # ③ Décision selon la sévérité la plus haute trouvée
        has_block = any(m["severity"] == Severity.BLOCK for m in matches)
        has_warn  = any(m["severity"] == Severity.WARN  for m in matches)

        if has_block or (has_warn and self.block_on_warn):
            self._block_count += 1
            top = next(m for m in matches if m["severity"] == Severity.BLOCK.value) if has_block else matches[0]
            logger.warning(
                "Prompt bloqué | raison=%s | correspondances=%d",
                top["reason"], len(matches),
            )
            return self._result(
                flagged=True,
                reason=top["reason"],
                severity=Severity.BLOCK if has_block else Severity.WARN,
                matches=matches,
            )

        # WARN uniquement et block_on_warn=False → loggué, non bloqué
        logger.info("Prompt signalé (WARN) | %d correspondance(s)", len(matches))
        return self._result(
            flagged=False,
            reason=matches[0]["reason"],
            severity=Severity.WARN,
            matches=matches,
        )

    @property
    def stats(self) -> dict:
        return {
            "scans":   self._scan_count,
            "blocked": self._block_count,
            "passed":  self._scan_count - self._block_count,
            "block_rate": (
                round(self._block_count / self._scan_count, 4)
                if self._scan_count else 0.0
            ),
        }

    # ── Helper ────────────────────────────────────────────────────────────────

    @staticmethod
    def _result(
        flagged:  bool             = False,
        reason:   str | None       = None,
        severity: Severity | None  = None,
        matches:  list[Match]      = [],
    ) -> ScanResult:
        return {
            "flagged":  flagged,
            "reason":   reason,
            "matches":  matches,
            "severity": severity.value if severity else None,
        }
