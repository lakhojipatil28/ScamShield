"""
Main FastAPI Application Entry Point for ScamShield.
Configures CORS, rate limiting, security headers, input sanitization, and routers.
Supports serving bundled React frontend SPA when built.
"""

import os
import time
from collections import defaultdict

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.config import settings
from backend.routers.health import router as health_router
from backend.routers.metrics import router as metrics_router
from backend.routers.scans import router as scans_router

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-Enabled Cyber Threat & Scam Detection Platform",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory IP-based rate limiter
rate_limit_records = defaultdict(list)


@app.middleware("http")
async def security_and_rate_limit_middleware(request: Request, call_next):
    # 1. Rate Limiting Check
    client_ip = request.client.host if request.client else "unknown"
    current_time = time.time()

    # Clean records older than 60 seconds
    rate_limit_records[client_ip] = [
        t for t in rate_limit_records[client_ip] if current_time - t < 60
    ]

    # Exclude health check and assets from rate limits
    if not request.url.path.startswith(
        ("/assets", "/health", "/docs", "/openapi.json")
    ):
        if len(rate_limit_records[client_ip]) >= settings.RATE_LIMIT_PER_MINUTE:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "message": f"Maximum of {settings.RATE_LIMIT_PER_MINUTE} requests per minute exceeded. Please try again shortly.",
                },
            )
        rate_limit_records[client_ip].append(current_time)

    # 2. Process Request
    response: Response = await call_next(request)

    # 3. Add Defensive Security Headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )

    return response


# Include API Routers
app.include_router(health_router)
app.include_router(scans_router)
app.include_router(metrics_router)

# Mount frontend SPA if dist exists
dist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")
if os.path.exists(dist_path):
    assets_path = os.path.join(dist_path, "assets")
    if os.path.exists(assets_path):
        app.mount("/assets", StaticFiles(directory=assets_path), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Allow API endpoints to fall through
        if full_path.startswith(("api/", "health", "docs", "redoc", "openapi.json")):
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        file_path = os.path.join(dist_path, full_path)
        if full_path and os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(dist_path, "index.html"))
else:

    @app.get("/")
    def root():
        return {
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "operational",
            "documentation": "/docs",
        }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
