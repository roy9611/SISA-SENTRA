"""
Kynetic Sentra — FastAPI Application.
Entry point with CORS, rate limiting, request tracing, and health check.
"""

import time
import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api.analyze import router as analyze_router
from app.routes.chat import router as chat_router
from app.core.config import settings
from app.core.logging_config import generate_request_id, logger, request_id_var

# ── Rate Limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Kynetic Sentra — Modular cybersecurity analysis platform. "
        "Ingests multi-source data, detects sensitive information, "
        "analyzes logs, scores risk, and generates AI-powered insights."
    ),
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# ── Rate Limiting ─────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# ── CORS ──────────────────────────────────────────────────────────────────────
# In production, restrict to the actual frontend origin via env var
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "")
if allowed_origins_env:
    allowed_origins = [o.strip() for o in allowed_origins_env.split(",")]
else:
    # Development default — allow all
    allowed_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request Tracing Middleware ────────────────────────────────────────────────
@app.middleware("http")
async def request_tracing(request: Request, call_next):
    """Add request ID and timing to every request."""
    req_id = generate_request_id()
    request_id_var.set(req_id)
    start = time.time()

    logger.info(f"→ {request.method} {request.url.path}")

    response = await call_next(request)

    duration_ms = (time.time() - start) * 1000
    logger.info(
        f"← {request.method} {request.url.path} "
        f"status={response.status_code} duration={duration_ms:.1f}ms"
    )

    response.headers["X-Request-ID"] = req_id
    return response


# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(analyze_router, tags=["Analysis"])
app.include_router(chat_router, tags=["Chat"])


# ── Health Check ──────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "endpoints": {
            "analyze": "POST /analyze",
            "chat":    "POST /chat",
            "health":  "GET /health",
        },
    }
