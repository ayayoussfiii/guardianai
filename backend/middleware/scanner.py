"""
middleware/scanner.py
─────────────────────
Analyse statique d'un prompt avant tout traitement LLM.

  • Mutable default argument corrigé : _result(matches=[]) → matches=None
  • Compteurs thread-safe via threading.Lock
  • Comparaison de sévérité unifiée (toujours .value, jamais l'Enum brut)
  • _result() reçoit severity: str | None (plus de couplage avec Severity)
  • Règles injectables via le constructeur (testabilité, extensibilité)
"""

import logging
import re
import threading
import unicodedata
from dataclasses import dataclass
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
    severity: str   # toujours une str (Severity.value)


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
DEFAULT_RULES: list[Rule] = [

    # ── Prompt injection ──────────────────────────────────────────────────────
    Rule(r"ignore\s+(all\s+)?previous\s+instructions?",          "Prompt injection — previous instructions"),
    Rule(r"disregard\s+(your\s+)?instructions?",                 "Prompt injection — disregard"),
    Rule(r"do\s+not\s+follow\s+(your\s+)?instructions?",         "Prompt injection — do not follow"),
    Rule(r"override\s+(your\s+)?(rules?|instructions?)",         "Prompt injection — override"),

    # ── Jailbreak identité / rôle ─────────────────────────────────────────────
    Rule(r"you\s+are\s+now\s+(?!an?\s+(helpful\s+)?assistant)",  "Jailbreak — redéfinition de rôle"),
    Rule(r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(?!an?\s+(helpful\s+)?assistant)", "Jailbreak — act as"),
    Rule(r"forget\s+(that\s+you\s+are|you\s+are|your\s+)",       "Jailbreak — oubli d'identité"),
    Rule(r"pretend\s+(you\s+)?(are|have\s+no)",                  "Jailbreak — pretend"),
    Rule(r"you\s+have\s+no\s+(restrictions?|limits?|rules?)",    "Jailbreak — suppression de contraintes"),

    # ── Bypass explicite ──────────────────────────────────────────────────────
    Rule(r"bypass\s+(your\s+)?(safety|filter|restriction|guard|policy)", "Bypass — safety"),
    Rule(r"jailbreak",                                           "Bypass — jailbreak explicite"),
    Rule(r"\bDAN\s+mode\b",                                      "Bypass — mode DAN"),
    Rule(r"without\s+(any\s+)?(restrictions?|censorship|filters?)", "Bypass — sans restrictions"),

    # ── Extraction du prompt système ──────────────────────────────────────────
    Rule(r"reveal\s+(your\s+)?(system\s+prompt|instructions?|prompt)", "Extraction — system prompt"),
    Rule(r"show\s+(me\s+)?(your\s+)?(system\s+)?prompt",         "Extraction — show prompt"),
    Rule(r"what\s+(are|were)\s+your\s+instructions?",            "Extraction — instructions"),
    Rule(r"repeat\s+(the\s+)?(text|words?|content)\s+above",     "Extraction — repeat above"),
    Rule(r"output\s+(your\s+)?initial\s+(prompt|message)",       "Extraction — initial prompt"),

    # ── Injection de tokens / formats ─────────────────────────────────────────
    Rule(r"<\|?\s*(system|im_start|im_end)\s*\|?>",              "Injection — token système"),
    Rule(r"\[INST\]|\[\/INST\]",                                 "Injection — format instruction"),
    Rule(r"<<SYS>>|<</SYS>>",                                    "Injection — balise système Llama"),
    Rule(r"###\s*System\s*:",                                     "Injection — header System"),

    # ── Signaux d'alerte (WARN, non bloquants par défaut) ────────────────────
    Rule(r"hypothetically\s+(speaking)?",                        "Signal — hypothetically",  Severity.WARN),
    Rule(r"for\s+(a\s+)?fiction(al)?\s+(story|novel|book)",      "Signal — fiction framing", Severity.WARN),
    Rule(r"in\s+a\s+(video\s+)?game\s+context",                  "Signal — game framing",    Severity.WARN),
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

# Type interne : règle compilée
_CompiledRule = tuple[re.Pattern[str], Rule]


class Scanner:
    """
    Analyse statique d'un prompt.

    Thread-safe. Les compteurs internes sont protégés par un Lock.

    Par défaut, seuls les BLOCK déclenchent `flagged=True`.
    Passer `block_on_warn=True` pour durcir la politique.

    Paramètres
    ----------
    block_on_warn : bool
        Si True, les règles WARN bloquent aussi la requête.
    rules : list[Rule] | None
        Jeu de règles personnalisé. None = DEFAULT_RULES.
        Permet d'injecter des règles en test sans monkey-patching.
    """

    MAX_LENGTH = 8_192   # aligné avec la validation Pydantic du router

    def __init__(
        self,
        block_on_warn: bool = False,
        rules: list[Rule] | None = None,
    ):
        self.block_on_warn = block_on_warn

        # Compilation des règles à l'instanciation (pas au chargement du module)
        # → chaque instance peut avoir son propre jeu de règles
        effective_rules  = rules if rules is not None else DEFAULT_RULES
        self._compiled: list[_CompiledRule] = [
            (re.compile(rule.pattern, re.IGNORECASE), rule)
            for rule in effective_rules
        ]

        self._lock        = threading.Lock()
        self._scan_count  = 0
        self._block_count = 0

    # ── API publique ──────────────────────────────────────────────────────────

    def scan(self, prompt: str) -> ScanResult:
        # ① Vérification longueur (avant normalisation pour la perf)
        if len(prompt) > self.MAX_LENGTH:
            self._increment(blocked=True)
            return _result(
                flagged=True,
                reason=f"Prompt trop long ({len(prompt)} > {self.MAX_LENGTH} chars)",
                severity=Severity.BLOCK.value,
            )

        normalized = _normalize(prompt)
        matches    = self._find_matches(normalized)

        if not matches:
            self._increment(blocked=False)
            return _result(flagged=False)

        # ② Décision selon la sévérité la plus haute trouvée
        has_block = any(m["severity"] == Severity.BLOCK.value for m in matches)
        has_warn  = any(m["severity"] == Severity.WARN.value  for m in matches)

        if has_block or (has_warn and self.block_on_warn):
            self._increment(blocked=True)
            top_severity = Severity.BLOCK.value if has_block else Severity.WARN.value
            top_match    = next(
                m for m in matches if m["severity"] == top_severity
            )
            logger.warning(
                "Prompt bloqué | raison=%s | correspondances=%d",
                top_match["reason"], len(matches),
            )
            return _result(
                flagged=True,
                reason=top_match["reason"],
                severity=top_severity,
                matches=matches,
            )

        # WARN uniquement et block_on_warn=False → logué, non bloqué
        self._increment(blocked=False)
        logger.info("Prompt signalé (WARN) | %d correspondance(s)", len(matches))
        return _result(
            flagged=False,
            reason=matches[0]["reason"],
            severity=Severity.WARN.value,
            matches=matches,
        )

    @property
    def stats(self) -> dict:
        with self._lock:
            scans   = self._scan_count
            blocked = self._block_count
        return {
            "scans":      scans,
            "blocked":    blocked,
            "passed":     scans - blocked,
            "block_rate": round(blocked / scans, 4) if scans else 0.0,
        }

    # ── Méthodes privées ──────────────────────────────────────────────────────

    def _find_matches(self, normalized: str) -> list[Match]:
        """Retourne toutes les règles qui correspondent au texte normalisé."""
        return [
            {
                "pattern":  rule.pattern,
                "reason":   rule.reason,
                "severity": rule.severity.value,   # toujours str, jamais Enum
            }
            for compiled, rule in self._compiled
            if compiled.search(normalized)
        ]

    def _increment(self, *, blocked: bool) -> None:
        """Mise à jour thread-safe des compteurs."""
        with self._lock:
            self._scan_count += 1
            if blocked:
                self._block_count += 1


# ─── Helper module-level (pas de couplage avec Scanner) ──────────────────────

def _result(
    flagged:  bool            = False,
    reason:   str | None      = None,
    severity: str | None      = None,
    matches:  list[Match] | None = None,   # ✅ None par défaut, jamais []
) -> ScanResult:
    """
    Construit un ScanResult.

    Reçoit severity en str (Severity.value) pour éviter tout couplage
    avec l'Enum à l'intérieur du contrat TypedDict.
    """
    return {
        "flagged":  flagged,
        "reason":   reason,
        "matches":  matches if matches is not None else [],
        "severity": severity,
    }
