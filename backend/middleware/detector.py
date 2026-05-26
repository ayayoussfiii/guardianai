"""
middleware/detector.py
──────────────────────
Détection des attaques multi-tours avec suivi de session.

Améliorations vs v1 :
  • Thread-safe grâce à threading.Lock (compatible FastAPI sync workers)
  • TTL paresseux (lazy expiry) à chaque accès + nettoyage périodique
  • Score d'escalade cumulatif au lieu d'un booléen binaire
  • Patterns centralisés et extensibles (dataclass + frozenset)
  • Résultat enrichi : score, session_id retourné, gravité
  • Méthode summary() pour l'endpoint GET /sessions/{id}
  • Séparation claire des responsabilités en méthodes privées
"""

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import TypedDict

logger = logging.getLogger(__name__)

# ─── Contrats typés ──────────────────────────────────────────────────────────

class DetectionResult(TypedDict):
    malicious:  bool
    reason:     str | None
    score:      float          # 0.0 → 1.0, facilite le debug et le seuillage
    session_id: str


# ─── Patterns (centralisés, immuables) ───────────────────────────────────────

ROLEPLAY_TRIGGERS: frozenset[str] = frozenset({
    "pretend", "imagine", "rôle", "joue", "play", "scenario",
    "act as", "you are now", "tu es", "fais semblant",
})

ESCALATION_TRIGGERS: frozenset[str] = frozenset({
    "maintenant", "now", "alors", "donc", "et si",
    "what if", "suppose", "hypothetically",
    "just pretend", "let's say", "as a game", "go ahead", "do it",
})

# Mots-clés graves qui augmentent le score même hors contexte multi-tours
HIGH_RISK_KEYWORDS: frozenset[str] = frozenset({
    "ignore previous instructions", "ignore tes instructions",
    "bypass", "override", "jailbreak", "dan mode",
    "without restrictions", "sans restrictions",
})


# ─── Modèle de session ───────────────────────────────────────────────────────

@dataclass
class SessionContext:
    session_id:  str
    created_at:  float             = field(default_factory=time.time)
    last_seen:   float             = field(default_factory=time.time)
    messages:    list[str]         = field(default_factory=list)
    flags:       list[dict]        = field(default_factory=list)   # {reason, score, ts}
    flag_count:  int               = 0
    risk_score:  float             = 0.0   # score cumulatif pondéré

    def touch(self) -> None:
        self.last_seen = time.time()

    def is_expired(self, ttl: float) -> bool:
        return (time.time() - self.last_seen) > ttl

    def add_flag(self, reason: str, score: float) -> None:
        self.flags.append({"reason": reason, "score": score, "ts": time.time()})
        self.flag_count += 1
        self.risk_score = min(1.0, self.risk_score + score)

    def summary(self) -> dict:
        return {
            "session_id":    self.session_id,
            "message_count": len(self.messages),
            "flag_count":    self.flag_count,
            "risk_score":    round(self.risk_score, 3),
            "flags":         self.flags,
            "created_at":    self.created_at,
            "last_seen":     self.last_seen,
        }


# ─── Détecteur principal ─────────────────────────────────────────────────────

class Detector:
    """
    Détection comportementale multi-tours avec suivi de session.

    Thread-safe. Chaque appel à detect() est atomique vis-à-vis du
    dictionnaire de sessions.

    Seuils configurables via le constructeur ou variables d'env.
    """

    def __init__(
        self,
        max_flags:    int   = 3,
        session_ttl:  float = 3_600.0,   # 1 h
        max_sessions: int   = 10_000,
        block_score:  float = 0.8,       # score cumulatif de blocage
    ):
        self.max_flags    = max_flags
        self.session_ttl  = session_ttl
        self.max_sessions = max_sessions
        self.block_score  = block_score

        self._sessions: dict[str, SessionContext] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    # ── API publique ──────────────────────────────────────────────────────────

    def detect(self, prompt: str, session_id: str | None = None) -> DetectionResult:
        """Point d'entrée principal. Retourne un DetectionResult complet."""
        with self._lock:
            self._maybe_cleanup()
            sid, ctx = self._get_or_create(session_id)

        # ① Session déjà blacklistée
        if ctx.flag_count >= self.max_flags or ctx.risk_score >= self.block_score:
            return self._blocked(sid, f"Session bloquée (flags={ctx.flag_count}, score={ctx.risk_score:.2f})")

        score = 0.0
        reason: str | None = None

        # ② Mots-clés à haut risque (indépendants du contexte)
        hr_score, hr_reason = self._check_high_risk(prompt)
        score  += hr_score
        reason  = reason or hr_reason

        # ③ Escalade multi-tours (nécessite un historique)
        if ctx.messages:
            esc_score, esc_reason = self._check_escalation(prompt, ctx)
            score  += esc_score
            reason  = reason or esc_reason

        # ④ Décision
        malicious = score >= 0.5
        if malicious:
            with self._lock:
                ctx.add_flag(reason or "inconnu", score)
            logger.warning("Prompt malveillant | session=%s score=%.2f reason=%s", sid, score, reason)
        else:
            with self._lock:
                ctx.messages.append(prompt)
                ctx.touch()

        return {
            "malicious":  malicious,
            "reason":     reason if malicious else None,
            "score":      round(min(score, 1.0), 3),
            "session_id": sid,
        }

    def get_session(self, session_id: str) -> dict | None:
        with self._lock:
            ctx = self._sessions.get(session_id)
        return ctx.summary() if ctx else None

    def clear_session(self, session_id: str) -> bool:
        with self._lock:
            existed = session_id in self._sessions
            self._sessions.pop(session_id, None)
        return existed

    def active_session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    # ── Logique de détection ──────────────────────────────────────────────────

    def _check_high_risk(self, prompt: str) -> tuple[float, str | None]:
        """Mots-clés universellement suspects, quel que soit le contexte."""
        pl = prompt.lower()
        hits = [kw for kw in HIGH_RISK_KEYWORDS if kw in pl]
        if hits:
            return 0.7, f"Mot-clé à haut risque détecté : « {hits[0]} »"
        return 0.0, None

    def _check_escalation(self, prompt: str, ctx: SessionContext) -> tuple[float, str | None]:
        """
        Détecte les attaques progressives :
          tour N   → mise en scène (roleplay setup)
          tour N+1 → mot d'escalade pour pousser vers l'action
        Le score monte en fonction du nombre de messages précédents suspects.
        """
        pl   = prompt.lower()
        prev = ctx.messages[-1].lower()

        prev_has_roleplay  = any(k in prev for k in ROLEPLAY_TRIGGERS)
        curr_has_escalation = any(k in pl   for k in ESCALATION_TRIGGERS)

        if not (prev_has_roleplay and curr_has_escalation):
            return 0.0, None

        # Prompt court → moins suspect (peut être anodin)
        length_factor = min(len(prompt) / 200, 1.0)   # seuil à 200 chars
        score = 0.4 + 0.3 * length_factor

        return score, "Escalade multi-tours détectée (roleplay → action)"

    # ── Gestion des sessions ──────────────────────────────────────────────────

    def _get_or_create(self, session_id: str | None) -> tuple[str, SessionContext]:
        """Retourne (sid, ctx). Crée la session si nécessaire. NON thread-safe seul."""
        sid = session_id or str(uuid.uuid4())

        # Lazy TTL : si la session existe mais est expirée, on la recrée
        if sid in self._sessions and self._sessions[sid].is_expired(self.session_ttl):
            logger.debug("Session expirée, réinitialisation : %s", sid)
            del self._sessions[sid]

        if sid not in self._sessions:
            self._sessions[sid] = SessionContext(session_id=sid)
            logger.debug("Nouvelle session créée : %s", sid)
        else:
            self._sessions[sid].touch()

        return sid, self._sessions[sid]

    def _maybe_cleanup(self, interval: float = 300.0) -> None:
        """Nettoyage périodique toutes les `interval` secondes. NON thread-safe seul."""
        now = time.time()
        if now - self._last_cleanup < interval:
            return

        expired = [
            sid for sid, ctx in self._sessions.items()
            if ctx.is_expired(self.session_ttl)
        ]
        for sid in expired:
            del self._sessions[sid]

        # Éviction LRU si dépassement du plafond
        overflow = len(self._sessions) - self.max_sessions
        if overflow > 0:
            lru = sorted(self._sessions.items(), key=lambda x: x[1].last_seen)
            for sid, _ in lru[:overflow]:
                del self._sessions[sid]

        self._last_cleanup = now
        logger.debug("Nettoyage sessions : %d expirées, %d restantes", len(expired), len(self._sessions))

    # ── Helpers internes ──────────────────────────────────────────────────────

    @staticmethod
    def _blocked(session_id: str, reason: str) -> DetectionResult:
        return {"malicious": True, "reason": reason, "score": 1.0, "session_id": session_id}
