import time
import uuid
from collections import defaultdict
from typing import TypedDict


class DetectionResult(TypedDict):
    malicious: bool
    reason: str | None


class SessionContext:
    def __init__(self):
        self.messages: list[str] = []
        self.flags: list[str] = []
        self.created_at: float = time.time()
        self.last_seen: float = time.time()
        self.flag_count: int = 0


class Detector:
    """
    Profil A — Détection des attaques multi-tours et suivi de session.
    Garde le contexte de conversation pour repérer les attaques
    progressives (ex: jailbreak par étapes).

    Le moteur IA sémantique (Profil B) viendra se brancher ici
    via le contrat API défini en commun.
    """

    MAX_FLAGS_PER_SESSION = 3   # blocage après N signalements
    SESSION_TTL = 3600          # 1h en secondes
    MAX_SESSIONS = 10000        # limite mémoire

    # Patterns multi-tours (détectables seulement avec contexte)
    ESCALATION_KEYWORDS = [
        "maintenant", "now", "alors", "donc", "et si",
        "what if", "suppose", "imagine", "hypothetically",
        "just pretend", "let's say", "as a game"
    ]

    def __init__(self):
        self._sessions: dict[str, SessionContext] = {}

    def _get_or_create(self, session_id: str | None) -> tuple[str, SessionContext]:
        if not session_id or session_id not in self._sessions:
            sid = session_id or str(uuid.uuid4())
            self._sessions[sid] = SessionContext()
            self._cleanup_old_sessions()
            return sid, self._sessions[sid]
        ctx = self._sessions[session_id]
        ctx.last_seen = time.time()
        return session_id, ctx

    def detect(self, prompt: str, session_id: str | None = None) -> DetectionResult:
        sid, ctx = self._get_or_create(session_id)

        # Vérification : session déjà blacklistée
        if ctx.flag_count >= self.MAX_FLAGS_PER_SESSION:
            return {
                "malicious": True,
                "reason": f"Session bloquée après {ctx.flag_count} signalements"
            }

        # Détection d'escalade progressive
        if len(ctx.messages) > 0:
            result = self._check_escalation(prompt, ctx)
            if result["malicious"]:
                ctx.flag_count += 1
                ctx.flags.append(result["reason"])
                return result

        # Enregistrement du message dans la session
        ctx.messages.append(prompt)
        return {"malicious": False, "reason": None}

    def _check_escalation(self, prompt: str, ctx: SessionContext) -> DetectionResult:
        """Détecte les attaques progressives sur plusieurs tours"""
        prompt_lower = prompt.lower()

        # Si le message précédent contenait une mise en scène
        # et que le nouveau utilise un mot d'escalade → suspicion
        prev = ctx.messages[-1].lower() if ctx.messages else ""
        role_setup_keywords = ["pretend", "imagine", "rôle", "joue", "play", "scenario"]

        prev_has_roleplay = any(k in prev for k in role_setup_keywords)
        curr_has_escalation = any(k in prompt_lower for k in self.ESCALATION_KEYWORDS)

        if prev_has_roleplay and curr_has_escalation and len(prompt) > 50:
            return {
                "malicious": True,
                "reason": "Escalade détectée : tentative de jailbreak multi-tours"
            }

        return {"malicious": False, "reason": None}

    def get_session(self, session_id: str) -> dict | None:
        ctx = self._sessions.get(session_id)
        if not ctx:
            return None
        return {
            "session_id": session_id,
            "message_count": len(ctx.messages),
            "flag_count": ctx.flag_count,
            "flags": ctx.flags,
            "created_at": ctx.created_at,
            "last_seen": ctx.last_seen,
        }

    def clear_session(self, session_id: str):
        self._sessions.pop(session_id, None)

    def _cleanup_old_sessions(self):
        """Supprime les sessions expirées pour libérer la mémoire"""
        now = time.time()
        expired = [
            sid for sid, ctx in self._sessions.items()
            if now - ctx.last_seen > self.SESSION_TTL
        ]
        for sid in expired:
            del self._sessions[sid]

        # Si encore trop de sessions, supprime les plus anciennes
        if len(self._sessions) > self.MAX_SESSIONS:
            sorted_sessions = sorted(
                self._sessions.items(),
                key=lambda x: x[1].last_seen
            )
            for sid, _ in sorted_sessions[:len(self._sessions) - self.MAX_SESSIONS]:
                del self._sessions[sid]
