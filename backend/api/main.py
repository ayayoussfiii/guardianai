"""
main.py — Point d'entrée FastAPI de GuardianAI
Assemble le scanner, le detector et le filter en un seul middleware
"""

from __future__ import annotations
import time
import uuid
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from middleware.scanner  import PromptScanner,   ThreatLevel
from middleware.detector import IntentDetector
from middleware.filter   import ResponseFilter



app = FastAPI(
    title       = "GuardianAI",
    description = "Middleware de sécurité pour LLMs en temps réel",
    version     = "1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)

# ── Instances des composants ──────────────────────────────────────────────────

scanner  = PromptScanner()
detector = IntentDetector(use_ml=False)   # passer True pour activer le ML
filter_  = ResponseFilter()




class PromptRequest(BaseModel):
    prompt    : str
    user_id   : str | None = None
    session_id: str | None = None


class LLMResponse(BaseModel):
    response  : str
    user_id   : str | None = None
    session_id: str | None = None


class GuardResult(BaseModel):
    request_id    : str
    allowed       : bool
    threat_level  : str
    threat_type   : str
    confidence    : float
    details       : str
    latency_ms    : float
    filtered_text : str | None = None


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "GuardianAI is running 🛡️"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/guard/prompt", response_model=GuardResult)
def guard_prompt(request: PromptRequest):
    """
    Analyse un prompt AVANT qu'il soit envoyé au LLM.
    Retourne allowed=False si une menace est détectée.
    """
    start = time.perf_counter()
    request_id = str(uuid.uuid4())

    # Étape 1 — Scanner rapide (regex)
    scan = scanner.scan(request.prompt)

    # Étape 2 — Detector ML/heuristique (si le scanner dit SAFE)
    if scan.threat_level == ThreatLevel.SAFE:
        detection   = detector.detect(request.prompt)
        threat_level = detection.threat_level
        threat_type  = detection.threat_type
        confidence   = detection.confidence
        details      = detection.details
    else:
        threat_level = scan.threat_level
        threat_type  = scan.threat_type
        confidence   = scan.confidence
        details      = scan.details

    allowed    = threat_level == ThreatLevel.SAFE
    latency_ms = (time.perf_counter() - start) * 1000

    return GuardResult(
        request_id   = request_id,
        allowed      = allowed,
        threat_level = threat_level,
        threat_type  = threat_type,
        confidence   = confidence,
        details      = details,
        latency_ms   = round(latency_ms, 2),
    )


@app.post("/guard/response", response_model=GuardResult)
def guard_response(payload: LLMResponse):
    """
    Filtre la réponse du LLM AVANT de la renvoyer à l'utilisateur.
    Masque les données sensibles ou bloque si contenu dangereux.
    """
    start      = time.perf_counter()
    request_id = str(uuid.uuid4())

    result     = filter_.filter(payload.response)
    latency_ms = (time.perf_counter() - start) * 1000

    return GuardResult(
        request_id    = request_id,
        allowed       = result.is_safe,
        threat_level  = "safe" if result.is_safe else "critical",
        threat_type   = "none" if result.is_safe else "dangerous_output",
        confidence    = 1.0,
        details       = result.details,
        latency_ms    = round(latency_ms, 2),
        filtered_text = result.filtered_text,
    )
