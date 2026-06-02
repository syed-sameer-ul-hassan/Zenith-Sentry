#!/usr/bin/env python3
"""
FastAPI main application for Zenith-Sentry REST API.
"""
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
import logging
from datetime import datetime
from typing import Dict, Any

from zenith.api.auth import get_current_user

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Zenith-Sentry API",
    description="Linux Endpoint Detection and Response (EDR) REST API",
    version="2.1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

@app.get("/", tags=["Root"])
async def root() -> Dict[str, Any]:
    """Root endpoint with API information."""
    return {
        "name": "Zenith-Sentry API",
        "version": "2.1.0.0",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "api": "/api/v1"
        }
    }

@app.get("/health", tags=["Health"])
async def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "zenith-sentry-api"}

@app.get("/api/v1/status", tags=["Status"])
async def api_status() -> Dict[str, Any]:
    """Get API and system status."""
    return {
        "api_status": "operational",
        "version": "2.1.0.0",
        "features": {
            "eBPF_monitoring": False,
            "mitigation": True,
            "telemetry": True
        }
    }

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for all unhandled exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

from zenith.api.routes import scans, findings, system, defense
app.include_router(
    scans.router,
    prefix="/api/v1/scans",
    tags=["Scans"],
    dependencies=[Depends(get_current_user)]
)
app.include_router(
    findings.router,
    prefix="/api/v1/findings",
    tags=["Findings"],
    dependencies=[Depends(get_current_user)]
)
app.include_router(
    system.router,
    prefix="/api/v1/system",
    tags=["System"],
    dependencies=[Depends(get_current_user)]
)
app.include_router(
    defense.router,
    prefix="/api/v1/defense",
    tags=["Defense"],
    dependencies=[Depends(get_current_user)]
)

@app.get("/health/ready", tags=["Health"])
async def readiness_check():
    """Readiness check - is the service ready to accept traffic?"""
    from zenith.monitoring.health import get_health_check
    health_check = get_health_check()
    result = health_check.run_all_checks()
    
    if result["status"] == "unhealthy":
        raise HTTPException(status_code=503, detail="Service not ready")
    
    return {"status": "ready"}

@app.get("/health/live", tags=["Health"])
async def liveness_check():
    """Liveness check - is the service running?"""
    return {"status": "alive", "timestamp": datetime.utcnow().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
