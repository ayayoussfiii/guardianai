"""
Ce fichier est la couche analytique il enregistre tt ce qui ce passe et l affiche en temps reel sur la dashboard 
routes.py — Routes supplémentaires (stats, historique, config)
"""

from __future__ import annotations
import uuid
from datetime import datetime
from collections import deque
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api", tags=["analytics"])


# ── Stockage en mémoire (remplacer par Redis/DB en prod) ──────────────────────

MAX_HISTORY = 500
_history: deque[dict] = deque(maxlen=MAX_HISTORY)
_stats = {
    "total_requests" : 0,
    "blocked"        : 0,
    "allowed"        : 0,
    "jailbreaks"     : 0,
    "injections"     : 0,
    "pii_leaks"      : 0,
    "secret_leaks"   : 0,
}


# ── Schémas ───────────────────────────────────────────────────────────────────

class EventLog(BaseModel):
    request_id  : str
    timestamp   : str
    allowed     : bool
    threat_level: str
    threat_type : str
    confidence  : float
    details     : str
    latency_ms  : float


# ── Helpers ───────────────────────────────────────────────────────────────────

def log_event(allowed: bool, threat_level: str, threat_type: str,
              confidence: float, details: str, latency_ms: float):
    """Enregistre un événement dans l'historique et met à jour les stats."""

    event = EventLog(
        request_id   = str(uuid.uuid4()),
        timestamp    = datetime.utcnow().isoformat(),
        allowed      = allowed,
        threat_level = threat_level,
        threat_type  = threat_type,
        confidence   = confidence,
        details      = details,
        latency_ms   = latency_ms,
    )

    _history.appendleft(event.dict())
    _stats["total_requests"] += 1

    if allowed:
        _stats["allowed"] += 1
    else:
        _stats["blocked"] += 1

    if threat_type == "jailbreak":
        _stats["jailbreaks"] += 1
    elif threat_type == "prompt_injection":
        _stats["injections"] += 1
    elif threat_type == "pii_leak":
        _stats["pii_leaks"] += 1
    elif threat_type == "secret_leak":
        _stats["secret_leaks"] += 1


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/stats")
def get_stats():
    """Retourne les statistiques globales."""
    total = _stats["total_requests"]
    return {
        **_stats,
        "block_rate": round(_stats["blocked"] / total * 100, 2) if total > 0 else 0,
    }


@router.get("/history")
def get_history(limit: int = 50):
    """Retourne les derniers événements loggés."""
    return list(_history)[:limit]


@router.get("/history/{threat_type}")
def get_history_by_type(threat_type: str, limit: int = 50):
    """Filtre l'historique par type de menace."""
    filtered = [e for e in _history if e["threat_type"] == threat_type]
    return filtered[:limit]


@router.delete("/history")
def clear_history():
    """Vide l'historique (admin seulement en prod)."""
    _history.clear()
    return {"message": "Historique vidé"}


@router.get("/config")
def get_config():
    """Retourne la configuration actuelle de GuardianAI."""
    return {
        "version"           : "1.0.0",
        "ml_enabled"        : False,
        "max_history"       : MAX_HISTORY,
        "confidence_threshold": 0.70,
        "latency_target_ms" : 50,
    }
