from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from middleware.scanner import Scanner
from middleware.filter import Filter
from middleware.detector import Detector
import httpx
import os

router = APIRouter()

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")

scanner = Scanner()
filter_ = Filter()
detector = Detector()


class ChatRequest(BaseModel):
    model: str = "llama3"
    prompt: str
    stream: bool = False
    session_id: str | None = None


class ChatResponse(BaseModel):
    response: str
    blocked: bool = False
    reason: str | None = None


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    # Etape 1 : scan du prompt entrant
    scan_result = scanner.scan(request.prompt)
    if scan_result["flagged"]:
        return ChatResponse(
            response="",
            blocked=True,
            reason=scan_result["reason"]
        )

    # Etape 2 : detection d'intention malveillante
    detection = detector.detect(request.prompt, session_id=request.session_id)
    if detection["malicious"]:
        return ChatResponse(
            response="",
            blocked=True,
            reason=detection["reason"]
        )

    # Etape 3 : filtrage du contenu
    filtered_prompt = filter_.clean(request.prompt)

    # Etape 4 : transfert vers Ollama
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": request.model,
                    "prompt": filtered_prompt,
                    "stream": False
                }
            )
            resp.raise_for_status()
            data = resp.json()
            return ChatResponse(response=data.get("response", ""))

    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="Ollama inaccessible")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=str(e))


@router.get("/models")
async def list_models():
    """Liste les modèles disponibles sur Ollama"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{OLLAMA_URL}/api/tags")
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="Ollama inaccessible")


@router.get("/sessions/{session_id}")
def get_session(session_id: str):
    """Récupère le contexte d'une session"""
    ctx = detector.get_session(session_id)
    if not ctx:
        raise HTTPException(status_code=404, detail="Session introuvable")
    return ctx


@router.delete("/sessions/{session_id}")
def delete_session(session_id: str):
    """Supprime une session"""
    detector.clear_session(session_id)
    return {"deleted": True, "session_id": session_id}
