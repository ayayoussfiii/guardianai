"""
Guardian AI - Proxy Backend Main Application
Enhanced version with better error handling, monitoring, and production readiness
"""

import os
import sys
import time
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import uvicorn

# ────────────────────────────────────────────────────────────────────────────
# LOGGING CONFIGURATION
# ────────────────────────────────────────────────────────────────────────────

def setup_logging() -> logging.Logger:
    """Configure structured logging with proper formatting"""
    
    log_format = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s"
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, log_level),
        format=log_format,
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ]
    )
    
    # Create app logger
    logger = logging.getLogger("guardianai")
    
    # Suppress noisy loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    
    return logger


logger = setup_logging()


# ────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────────────────────────────

class Config:
    """Application configuration from environment variables"""
    
    # Server
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    ENV: str = os.getenv("ENV", "development")
    DEBUG: bool = ENV == "development"
    
    # Services
    OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    PROFIL_B_URL: str = os.getenv("PROFIL_B_URL", "http://localhost:8001")
    
    # CORS
    ALLOWED_ORIGINS: list = os.getenv("ALLOWED_ORIGINS", "*").split(",")
    
    # Timeouts
    REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "60"))
    OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "120"))
    PROFIL_B_TIMEOUT: int = int(os.getenv("PROFIL_B_TIMEOUT", "30"))
    
    # Monitoring
    PROMETHEUS_ENABLED: bool = os.getenv("PROMETHEUS_ENABLED", "true").lower() == "true"
    
    @classmethod
    def validate(cls) -> bool:
        """Validate critical configuration"""
        try:
            # Validate OLLAMA_URL is provided
            if not cls.OLLAMA_URL:
                logger.warning("⚠️  OLLAMA_URL not configured")
            
            # Validate port is valid
            if not (1 <= cls.PORT <= 65535):
                logger.error("❌ Invalid PORT: %d", cls.PORT)
                return False
            
            return True
        except Exception as e:
            logger.error("❌ Configuration validation failed: %s", e)
            return False


# ────────────────────────────────────────────────────────────────────────────
# LIFESPAN MANAGEMENT
# ────────────────────────────────────────────────────────────────────────────

class AppState:
    """Application state holder"""
    startup_time: Optional[float] = None
    ready: bool = False


app_state = AppState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown"""
    
    # ─── STARTUP ─────────────────────────────────────────────────────────────
    try:
        app_state.startup_time = time.time()
        logger.info("=" * 80)
        logger.info("🚀 GuardianAI Proxy Starting...")
        logger.info("=" * 80)
        
        # Log configuration
        logger.info("📋 Configuration:")
        logger.info("  • Environment: %s", Config.ENV)
        logger.info("  • Host: %s:%d", Config.HOST, Config.PORT)
        logger.info("  • Ollama URL: %s", Config.OLLAMA_URL)
        logger.info("  • Profil B URL: %s", Config.PROFIL_B_URL)
        logger.info("  • CORS Origins: %s", Config.ALLOWED_ORIGINS)
        logger.info("  • Request Timeout: %ds", Config.REQUEST_TIMEOUT)
        logger.info("  • Prometheus Enabled: %s", Config.PROMETHEUS_ENABLED)
        
        # Validate configuration
        if not Config.validate():
            logger.error("❌ Configuration validation failed!")
            raise RuntimeError("Invalid configuration")
        
        # Initialize services (if any)
        logger.info("📡 Initializing services...")
        # TODO: Add service initialization here (Redis, DB, etc.)
        
        app_state.ready = True
        logger.info("✅ GuardianAI Proxy Ready!")
        logger.info("📖 Documentation: http://%s:%d/docs", Config.HOST, Config.PORT)
        logger.info("=" * 80)
        
    except Exception as e:
        logger.critical("❌ Startup failed: %s", e, exc_info=True)
        raise
    
    # ─── RUNNING ─────────────────────────────────────────────────────────────
    yield
    
    # ─── SHUTDOWN ────────────────────────────────────────────────────────────
    try:
        logger.info("=" * 80)
        logger.info("🛑 GuardianAI Proxy Shutting Down...")
        logger.info("=" * 80)
        
        uptime_seconds = time.time() - app_state.startup_time
        logger.info("⏱️  Uptime: %d seconds", int(uptime_seconds))
        
        # Cleanup services (if any)
        logger.info("🧹 Cleaning up resources...")
        # TODO: Add service cleanup here
        
        logger.info("✅ Shutdown complete")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error("❌ Error during shutdown: %s", e, exc_info=True)


# ────────────────────────────────────────────────────────────────────────────
# FASTAPI APPLICATION
# ────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="GuardianAI Proxy",
    description="Security proxy for local LLMs (Ollama)",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# ────────────────────────────────────────────────────────────────────────────
# MIDDLEWARE
# ────────────────────────────────────────────────────────────────────────────

# 1. Trusted Host Middleware (Security)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"] if Config.ENV == "development" else ["localhost", "127.0.0.1"],
)

# 2. CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=Config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    max_age=600,  # Cache CORS preflight for 10 minutes
)


# 3. Request/Response Logging Middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all HTTP requests with timing information"""
    
    # Skip logging for health checks (reduce log noise)
    if request.url.path in ["/health", "/readiness"]:
        response = await call_next(request)
        return response
    
    # Capture request info
    request_id = request.headers.get("X-Request-ID", "unknown")
    start_time = time.perf_counter()
    
    try:
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start_time) * 1000
        
        # Add response headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{duration_ms:.1f}ms"
        response.headers["X-Powered-By"] = "GuardianAI/1.0"
        
        # Log request
        log_level = logging.WARNING if response.status_code >= 400 else logging.INFO
        logger.log(
            log_level,
            "📨 %s %s → %d (%0.1fms) [%s]",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            request_id,
        )
        
        return response
        
    except Exception as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        logger.error(
            "❌ %s %s → ERROR (%0.1fms) [%s]: %s",
            request.method,
            request.url.path,
            duration_ms,
            request_id,
            str(e),
        )
        raise


# ────────────────────────────────────────────────────────────────────────────
# EXCEPTION HANDLERS
# ────────────────────────────────────────────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle Pydantic validation errors"""
    logger.warning(
        "⚠️  Validation error on %s %s: %s",
        request.method,
        request.url.path,
        exc.error_count(),
    )
    return JSONResponse(
        status_code=422,
        content={
            "detail": "Validation error",
            "errors": exc.errors(),
            "path": str(request.url.path),
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all unhandled exceptions"""
    logger.error(
        "❌ Unhandled exception on %s %s: %s",
        request.method,
        request.url.path,
        str(exc),
        exc_info=True,
    )
    
    status_code = 500
    message = "Internal server error"
    
    # Return different messages based on environment
    if Config.ENV == "development":
        message = str(exc)
    
    return JSONResponse(
        status_code=status_code,
        content={
            "detail": message,
            "path": str(request.url.path),
            "error_type": type(exc).__name__,
        },
    )


# ────────────────────────────────────────────────────────────────────────────
# ROUTES
# ────────────────────────────────────────────────────────────────────────────

# Import routes (lazy loading to avoid circular imports)
try:
    from api.routes import router
    app.include_router(router, prefix="/api", tags=["proxy"])
    logger.info("✅ Routes loaded successfully")
except ImportError as e:
    logger.warning("⚠️  Could not load routes: %s (using fallback)", e)


# ────────────────────────────────────────────────────────────────────────────
# HEALTH CHECK ENDPOINTS
# ────────────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["system"], summary="Basic health check")
async def health_check():
    """Basic health check endpoint"""
    return {
        "status": "healthy",
        "service": "GuardianAI Proxy",
        "version": "1.0.0",
        "ready": app_state.ready,
    }


@app.get("/readiness", tags=["system"], summary="Readiness probe for K8s")
async def readiness_probe():
    """Readiness probe for Kubernetes"""
    if not app_state.ready:
        return JSONResponse(
            status_code=503,
            content={"status": "not ready"},
        )
    
    return {
        "status": "ready",
        "service": "GuardianAI Proxy",
        "ollama_url": Config.OLLAMA_URL,
        "profil_b_url": Config.PROFIL_B_URL,
    }


@app.get("/liveness", tags=["system"], summary="Liveness probe for K8s")
async def liveness_probe():
    """Liveness probe for Kubernetes"""
    return {
        "status": "alive",
        "service": "GuardianAI Proxy",
        "uptime_seconds": int(time.time() - app_state.startup_time) if app_state.startup_time else 0,
    }


# ────────────────────────────────────────────────────────────────────────────
# INFO ENDPOINTS
# ────────────────────────────────────────────────────────────────────────────

@app.get("/", tags=["system"], summary="API information")
async def root():
    """Root endpoint with API information"""
    return {
        "service": "GuardianAI Proxy",
        "version": "1.0.0",
        "environment": Config.ENV,
        "docs": "/docs",
        "openapi": "/openapi.json",
        "health": "/health",
        "readiness": "/readiness",
        "liveness": "/liveness",
        "status": "ready" if app_state.ready else "starting",
    }


@app.get("/config", tags=["system"], summary="Configuration info (dev only)")
async def get_config():
    """Get current configuration (development only)"""
    if Config.ENV != "development":
        return JSONResponse(
            status_code=403,
            content={"detail": "Configuration endpoint only available in development"},
        )
    
    return {
        "environment": Config.ENV,
        "host": Config.HOST,
        "port": Config.PORT,
        "ollama_url": Config.OLLAMA_URL,
        "profil_b_url": Config.PROFIL_B_URL,
        "request_timeout": Config.REQUEST_TIMEOUT,
        "prometheus_enabled": Config.PROMETHEUS_ENABLED,
    }


# ────────────────────────────────────────────────────────────────────────────
# METRICS (Optional Prometheus)
# ────────────────────────────────────────────────────────────────────────────

if Config.PROMETHEUS_ENABLED:
    try:
        from prometheus_client import Counter, Histogram, generate_latest
        
        # Define metrics
        request_count = Counter(
            "guardianai_requests_total",
            "Total requests",
            ["method", "path", "status"],
        )
        
        request_duration = Histogram(
            "guardianai_request_duration_seconds",
            "Request duration in seconds",
            ["method", "path"],
        )
        
        @app.get("/metrics", tags=["monitoring"])
        async def metrics():
            """Prometheus metrics endpoint"""
            return generate_latest()
        
        logger.info("✅ Prometheus metrics enabled")
        
    except ImportError:
        logger.warning("⚠️  Prometheus not installed, metrics endpoint disabled")


# ────────────────────────────────────────────────────────────────────────────
# ENTRYPOINT
# ────────────────────────────────────────────────────────────────────────────

def main():
    """Main entrypoint"""
    
    # Parse arguments
    workers = int(os.getenv("WORKERS", "1" if Config.DEBUG else "4"))
    
    logger.info("🎯 Starting Uvicorn with %d workers...", workers)
    
    uvicorn.run(
        "main:app",
        host=Config.HOST,
        port=Config.PORT,
        workers=workers,
        reload=Config.DEBUG,
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
        access_log=Config.ENV == "development",
        env_file=".env",
    )


if __name__ == "__main__":
    main()
