"""FastAPI application for the SecOps Analyzer dashboard.

Run (from the project root):
    uvicorn web.main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import service

LOG = logging.getLogger("secops.web")
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

ALLOWED_PROVIDERS = {"offline", "auto", "openai", "ollama"}
PAID_PROVIDERS = {"openai", "ollama"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    service.ensure_seeded_data()
    yield


app = FastAPI(
    title="Autonomous AI SecOps Log Analyzer",
    description="Agentic framework for threat profiling — hybrid statistical + LLM log analysis.",
    version="1.0.0",
    lifespan=lifespan,
)


def _resolve_provider(requested: str, x_admin_token: str | None) -> str:
    provider = (requested or "offline").strip().lower()
    if provider not in ALLOWED_PROVIDERS:
        provider = "offline"
    if provider in PAID_PROVIDERS:
        # optional gate: if ADMIN_TOKEN is set, paid providers need the header token
        required = os.environ.get("ADMIN_TOKEN")
        if required and x_admin_token != required:
            raise HTTPException(status_code=403,
                                detail="an admin token is required to use paid LLM providers")
        if provider == "openai" and not os.environ.get("OPENAI_API_KEY"):
            provider = "offline"  # silently degrade — nothing to abuse
    return provider


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "AI SecOps Log Analyzer",
        "provider": "offline/auto",
    }


@app.post("/api/demo")
def api_demo(payload: dict | None = None, x_admin_token: str | None = Header(default=None)):
    """Run the full pipeline and return results. Body: {seed?, minutes?, provider?}"""
    payload = payload or {}
    try:
        provider = _resolve_provider(payload.get("provider", "offline"), x_admin_token)
        return service.run_demo(
            seed=payload.get("seed"), minutes=payload.get("minutes"),
            provider=provider,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        LOG.exception("demo run failed")
        raise HTTPException(status_code=500, detail="pipeline execution failed")


@app.post("/api/analyze")
async def api_analyze(file: UploadFile = File(...)):
    """Analyze an uploaded access-log CSV (detection mode, no ground truth)."""
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="empty file")
    if len(content) > service.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413,
                            detail=f"file too large (max {service.MAX_UPLOAD_BYTES // (1024 * 1024)} MB)")
    try:
        return service.analyze_upload(file.filename or "upload.csv", content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"could not parse log: {exc}")
    except Exception as exc:  # noqa: BLE001
        LOG.exception("upload analysis failed")
        raise HTTPException(status_code=500, detail="analysis failed")


@app.get("/api/last")
def api_last():
    return service.get_last_run() or {"run_id": None}


@app.get("/api/figures/{name}")
def api_figure(name: str):
    """Serve a generated figure PNG (allowlist)."""
    allowed = {"fig1_traffic_timeline.png", "fig2_anomaly_scores.png",
               "fig3_alerts_vs_true.png", "fig4_detection_quality.png",
               "fig5_latency.png"}
    if name not in allowed:
        raise HTTPException(status_code=404, detail="unknown figure")
    path = os.path.join(service.OUTPUT_DIR, "figures", name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="figure not generated yet")
    return FileResponse(path, media_type="image/png")


# Serve the frontend (must be mounted last so /api wins)
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
