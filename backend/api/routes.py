from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from middleware.scanner import Scanner
from middleware.filter import Filter
from middleware.detector import Detector
import httpx
import logging
import os
from functools import lru_cache
from typing import Annotated

# ─── Logging ────────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)

# ─── Configuration ───────────────────────────────────────────────────────────

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "60"))
DEFAULT_MODEL  = os.getenv("DEFAULT_MODEL", "llama3")

# ─── Singleton des middlewares (injectés via DI) ──────────────────────────────

@lru_cache(maxsize=1)
def get_scanner()  -> Scanner:  return Scanner()

@lru_cache(maxsize=1)
def get_filter()   -> Filter:   return Filter()

@lru_cache(maxsize=1)
def get_detector() -> Detector: return Detector()

ScannerDep  = Annotated[Scanner,  Depends(get_scanner)]
FilterDep   = Annotated[Filter,   Depends(get_filter)]
DetectorDep = Annotated[Detector, Depends(get_detector)]

# ─── Schémas ─────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    model:      str         = Field(DEFAULT_MODEL, min_length=1, examples=["llama3"])
    prompt:     str         = Field(..., min_length=1, max_length=8_192, examples=["Bonjour !"])
    stream:     bool        = False
    session_id: str | None  = Field(None, max_length=128)

    @field_validator("prompt")
    @classmethod
    def prompt_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Le prompt ne peut pas être vide ou uniquement des espaces.")
        return v.strip()


class ChatResponse(BaseModel):
    response: str
    blocked:  bool        = False
    reason:   str | None  = None


class SessionResponse(BaseModel):
    session_id: str
    context:    dict


# ─── Client HTTP partagé (cycle de vie géré par lifespan dans main.py) ───────
# Utilisation d'un client singleton pour réutiliser les connexions TCP.

_http_client: httpx.AsyncClient | None = None

def get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(timeout=OLLAMA_TIMEOUT)
    return _http_client


# ─── Helpers ─────────────────────────────────────────────────────────────────

async def _call_ollama(client: httpx.AsyncClient, model: str, prompt: str) -> str:
    """Envoie le prompt à Ollama et retourne la réponse texte."""
    try:
        resp = await client.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
        )
        resp.raise_for_status()
        return resp.json().get("response", "")
    except httpx.ConnectError as exc:
        logger.error("Ollama inaccessible : %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Le service Ollama est inaccessible.",
        )
    except httpx.TimeoutException as exc:
        logger.error("Timeout Ollama : %s", exc)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Le service Ollama n'a pas répondu à temps.",
        )
    except httpx.HTTPStatusError as exc:
        logger.error("Erreur HTTP Ollama %s : %s", exc.response.status_code, exc)
        raise HTTPException(
            status_code=exc.response.status_code,
            detail=f"Erreur Ollama : {exc.response.text}",
        )


# ─── Router ──────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/api", tags=["chat"])


@router.post(
    "/chat",
    response_model=ChatResponse,
    summary="Envoie un prompt au LLM via le pipeline de sécurité",
    status_code=status.HTTP_200_OK,
)
async def chat(
    body:     ChatRequest,
    scanner:  ScannerDep,
    filter_:  FilterDep,
    detector: DetectorDep,
) -> ChatResponse:
    logger.info("Nouvelle requête /chat | session=%s model=%s", body.session_id, body.model)

    # Étape 1 — Scan statique du prompt
    scan_result = scanner.scan(body.prompt)
    if scan_result["flagged"]:
        logger.warning("Prompt bloqué (scanner) : %s", scan_result["reason"])
        return ChatResponse(blocked=True, reason=scan_result["reason"], response="")

    # Étape 2 — Détection d'intention malveillante
    detection = detector.detect(body.prompt, session_id=body.session_id)
    if detection["malicious"]:
        logger.warning("Prompt bloqué (detector) : %s", detection["reason"])
        return ChatResponse(blocked=True, reason=detection["reason"], response="")

    # Étape 3 — Filtrage / nettoyage du contenu
    filtered_prompt = filter_.clean(body.prompt)

    # Étape 4 — Appel Ollama
    client   = get_http_client()
    response = await _call_ollama(client, body.model, filtered_prompt)
    logger.info("Réponse Ollama reçue (%d caractères)", len(response))
    return ChatResponse(response=response)


@router.get(
    "/models",
    summary="Liste les modèles disponibles sur Ollama",
)
async def list_models() -> dict:
    client = get_http_client()
    try:
        resp = await client.get(f"{OLLAMA_URL}/api/tags", timeout=10.0)
        resp.raise_for_status()
        return resp.json()
    except httpx.ConnectError:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Le service Ollama est inaccessible.",
        )
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=exc.response.status_code,
            detail=f"Erreur Ollama : {exc.response.text}",
        )


@router.get(
    "/sessions/{session_id}",
    response_model=SessionResponse,
    summary="Récupère le contexte d'une session",
)
def get_session(session_id: str, detector: DetectorDep) -> SessionResponse:
    ctx = detector.get_session(session_id)
    if ctx is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' introuvable.",
        )
    return SessionResponse(session_id=session_id, context=ctx)


@router.delete(
    "/sessions/{session_id}",
    summary="Supprime une session",
    status_code=status.HTTP_200_OK,
)
def delete_session(session_id: str, detector: DetectorDep) -> dict:
    detector.clear_session(session_id)
    logger.info("Session supprimée : %s", session_id)
    return {"deleted": True, "session_id": session_id}
