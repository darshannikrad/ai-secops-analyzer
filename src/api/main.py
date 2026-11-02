"""FastAPI main application entrypoint for SecOps Log Analyzer."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ..database.engine import init_db
from ..utils.config import get_settings
from .routes import router as api_v1_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan managing database table initialization and startup tasks."""
    logger.info("Initializing database schema...")
    try:
        init_db()
        logger.info("Database schema initialized successfully.")
    except Exception as exc:
        logger.error(f"Error during database initialization: {exc}", exc_info=True)
    yield
    logger.info("SecOps Analyzer backend shutting down.")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="AI SecOps Log Analyzer",
        description="Autonomous AI-driven Security Operations Log Analyzer and Incident Response API",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Configure CORS
    allowed_origins = settings.allowed_origins
    if isinstance(allowed_origins, str):
        allowed_origins = [o.strip() for o in allowed_origins.split(",") if o.strip()]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins or ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API v1 Router
    app.include_router(api_v1_router)

    # Root health endpoint
    @app.get("/health", tags=["System"], summary="Root health check")
    def root_health():
        return {"status": "ok", "app": "AI SecOps Log Analyzer", "version": "1.0.0"}

    @app.get("/", tags=["System"], summary="API Root")
    def root_index():
        return {
            "name": "AI SecOps Log Analyzer API",
            "version": "1.0.0",
            "docs": "/docs",
            "api_v1": "/api/v1",
        }

    # Custom Exception Handlers
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        logger.warning(f"Validation error on {request.url.path}: {exc.errors()}")
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Unprocessable Entity",
                "detail": exc.errors(),
                "body": str(exc.body)[:200] if hasattr(exc, "body") else None,
            },
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        logger.warning(f"HTTP exception on {request.url.path}: status={exc.status_code} detail={exc.detail}")
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "HTTP Error",
                "status_code": exc.status_code,
                "detail": exc.detail,
            },
            headers=exc.headers,
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.exception(f"Unhandled server error processing {request.url.path}: {exc}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal Server Error",
                "detail": "An unexpected error occurred processing your request.",
            },
        )

    return app


app = create_app()
