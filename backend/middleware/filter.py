"""
middleware/filter.py
────────────────────
Nettoyage du prompt avant envoi au LLM.

  • Thread-safe : _call_count et _total_removed protégés par threading.Lock
  • strip() promu en passe explicite du pipeline (traçable, désactivable)
  • Troncature déplacée en méthode privée _truncate()
  • max_length=0 correctement géré (comparaison is not None)
  • clean_detailed() décomposé en _run_pipeline() + _truncate() + _record_stats()
  • removed calculé de façon cohérente (une seule source de vérité)
"""

import html
import logging
import re
import threading
import unicodedata
from dataclasses import dataclass
from typing import Callable, TypedDict

logger = logging.getLogger(__name__)


# ─── Contrat typé ────────────────────────────────────────────────────────────

class FilterResult(TypedDict):
    cleaned:         str
    original_length: int
    cleaned_length:  int
    transformations: list[str]   # passes ayant modifié le texte


# ─── Passes de nettoyage (fonctions pures) ───────────────────────────────────

def _decode_html_entities(text: str) -> str:
    """Décode &amp; &#x27; etc. avant toute autre passe."""
    return html.unescape(text)


def _strip_html_xml(text: str) -> str:
    """Supprime les balises HTML/XML, attributs inclus."""
    return re.sub(r"<[^>]{0,2048}>", "", text)


_URL_DANGEROUS = re.compile(
    r"(?:javascript|data|vbscript|file)\s*:\s*\S+",
    re.IGNORECASE,
)

def _strip_dangerous_urls(text: str) -> str:
    """Retire les URL javascript:, data:, vbscript:, file:."""
    return _URL_DANGEROUS.sub("[url supprimée]", text)


_ANSI_RE = re.compile(
    r"\x1b(?:"
    r"\[[0-9;?]*[ -/]*[@-~]"              # CSI : ESC [ … lettre finale
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)"    # OSC : ESC ] … BEL ou ST
    r"|[PX^_][^\x1b]*\x1b\\"             # DCS / PM / APC / SOS
    r"|[@-Z\\-_]"                         # séquences Fe à 1 octet
    r")"
)

def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


# Caractères de contrôle hors newline (0x0A) et tab (0x09)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

def _strip_control_chars(text: str) -> str:
    return _CONTROL_RE.sub("", text)


# Caractères zero-width et directionnels (aligné avec scanner.py)
_ZERO_WIDTH_RE = re.compile(
    r"[\u200b-\u200d\u2060\ufeff\u00ad\u202a-\u202e\u2066-\u2069]"
)

def _strip_zero_width(text: str) -> str:
    return _ZERO_WIDTH_RE.sub("", text)


def _normalize_unicode(text: str) -> str:
    """NFC : forme canonique, identique au scanner pour cohérence."""
    return unicodedata.normalize("NFC", text)


def _normalize_whitespace(text: str) -> str:
    """Réduit espaces/tabs multiples et newlines excessifs."""
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


def _strip_surrounding_whitespace(text: str) -> str:
    """
    Supprime les espaces en début et fin de texte.

    Promue en passe explicite (vs un strip() silencieux hors pipeline)
    pour qu'elle apparaisse dans transformations et puisse être désactivée.
    """
    return text.strip()


# ─── Pipeline ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Pass:
    name: str
    fn:   Callable[[str], str]


DEFAULT_PIPELINE: list[Pass] = [
    Pass("decode_html_entities",      _decode_html_entities),
    Pass("strip_html_xml",            _strip_html_xml),
    Pass("strip_dangerous_urls",      _strip_dangerous_urls),
    Pass("strip_ansi",                _strip_ansi),
    Pass("strip_control_chars",       _strip_control_chars),
    Pass("strip_zero_width",          _strip_zero_width),
    Pass("normalize_unicode",         _normalize_unicode),
    Pass("normalize_whitespace",      _normalize_whitespace),
    # ↓ doit rester la dernière passe du pipeline
    Pass("strip_surrounding_whitespace", _strip_surrounding_whitespace),
]


# ─── Filter ──────────────────────────────────────────────────────────────────

class Filter:
    """
    Nettoyage du prompt avant envoi au LLM.

    Thread-safe : les compteurs internes sont protégés par un Lock.

    Paramètres
    ----------
    max_length : int | None
        Tronque le prompt nettoyé à cette longueur (None = pas de troncature).
        Aligner avec MAX_LENGTH du Scanner et la validation Pydantic.
    pipeline : list[Pass] | None
        Passes personnalisées. None = DEFAULT_PIPELINE.
    """

    def __init__(
        self,
        max_length: int | None = 8_192,
        pipeline:   list[Pass] | None = None,
    ):
        self.max_length = max_length
        self.pipeline   = pipeline if pipeline is not None else DEFAULT_PIPELINE

        self._lock          = threading.Lock()
        self._call_count    = 0
        self._total_removed = 0   # caractères supprimés au total

    # ── API publique ──────────────────────────────────────────────────────────

    def clean(self, prompt: str) -> str:
        """Rétrocompatibilité : retourne uniquement le texte nettoyé."""
        return self.clean_detailed(prompt)["cleaned"]

    def clean_detailed(self, prompt: str) -> FilterResult:
        """Retourne le prompt nettoyé et la liste des transformations appliquées."""
        original_length = len(prompt)

        # ① Passes de nettoyage
        cleaned, transformations = self._run_pipeline(prompt)

        # ② Troncature (hors pipeline pour garder une responsabilité claire)
        cleaned, transformations = self._truncate(cleaned, transformations)

        # ③ Stats thread-safe
        removed = original_length - len(cleaned)
        self._record_stats(removed)

        if transformations:
            logger.info(
                "Filter appliqué | passes=%s | supprimé=%d chars",
                transformations, removed,
            )

        return FilterResult(
            cleaned=cleaned,
            original_length=original_length,
            cleaned_length=len(cleaned),
            transformations=transformations,
        )

    @property
    def stats(self) -> dict:
        with self._lock:
            calls         = self._call_count
            total_removed = self._total_removed
        return {
            "calls":         calls,
            "total_removed": total_removed,
            "avg_removed":   (
                round(total_removed / calls, 1) if calls else 0.0
            ),
        }

    # ── Méthodes privées ──────────────────────────────────────────────────────

    def _run_pipeline(self, text: str) -> tuple[str, list[str]]:
        """
        Applique chaque passe du pipeline dans l'ordre.
        Retourne (texte transformé, liste des passes ayant modifié le texte).
        """
        transformations: list[str] = []
        current = text

        for pass_ in self.pipeline:
            result = pass_.fn(current)
            if result != current:
                transformations.append(pass_.name)
                logger.debug(
                    "Filter passe '%s' : %d → %d chars",
                    pass_.name, len(current), len(result),
                )
            current = result

        return current, transformations

    def _truncate(
        self,
        text: str,
        transformations: list[str],
    ) -> tuple[str, list[str]]:
        """
        Tronque le texte si max_length est défini et dépassé.
        Utilise `is not None` pour accepter max_length=0.
        """
        if self.max_length is not None and len(text) > self.max_length:
            text = text[: self.max_length]
            transformations = [*transformations, f"truncated_to_{self.max_length}"]
            logger.warning("Prompt tronqué à %d chars", self.max_length)
        return text, transformations

    def _record_stats(self, removed: int) -> None:
        """Mise à jour thread-safe des compteurs internes."""
        with self._lock:
            self._call_count    += 1
            self._total_removed += removed
