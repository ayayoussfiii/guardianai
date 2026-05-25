import os
import time
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from api.routes import router
import uvicorn

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("guardianai")


# ── Lifespan (startup / shutdown) ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🛡  GuardianAI Proxy starting on port %s", os.getenv("PORT", 8000))
    logger.info("🔗  Ollama URL: %s", os.getenv("OLLAMA_URL", "http://localhost:11434"))
    yield
    logger.info("🛑  GuardianAI Proxy shutting down")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="GuardianAI Proxy",
    description="Proxy de sécurité pour LLMs locaux (Ollama)",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# ── CORS ──────────────────────────────────────────────────────────────────────

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request logging middleware ────────────────────────────────────────────────

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000
    logger.info(
        "%s %s → %s (%.1fms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    response.headers["X-Response-Time"] = f"{duration_ms:.1f}ms"
    response.headers["X-Powered-By"] = "GuardianAI"
    return response


# ── Global error handler ──────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled error on %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "path": str(request.url.path)},
    )


# ── Routes ────────────────────────────────────────────────────────────────────

app.include_router(router, prefix="/api", tags=["proxy"])


# ── Health & info endpoints ───────────────────────────────────────────────────

@app.get("/health", tags=["system"])
def health():
    return {
        "status": "ok",
        "service": "GuardianAI Proxy",
        "version": "1.0.0",
        "ollama_url": os.getenv("OLLAMA_URL", "http://localhost:11434"),
    }


@app.get("/", tags=["system"])
def root():
    return {
        "service": "GuardianAI Proxy",
        "docs": "/docs",
        "health": "/health",
        "api": "/api",
    }


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=os.getenv("ENV", "development") == "development",
        log_level="info",
    )
