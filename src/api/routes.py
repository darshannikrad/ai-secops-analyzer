"""FastAPI API routes for SecOps Log Analyzer under /api/v1/."""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse, PlainTextResponse

from ..correlation.engine import CorrelationEngine
from ..database.engine import get_engine
from ..database.repository import AnalysisRepository
from ..detection.engine import DetectionEngine
from ..ingestion.parser import ingest_content
from ..investigation.agent import InvestigationAgent
from ..prioritization.engine import PrioritizationEngine
from ..reporting.generator import ReportGenerator
from ..utils.config import get_settings
from ..utils.models import (
    AnalysisStatus,
    Detection,
    Incident,
    IncidentStatus,
    Investigation,
    LogRecord,
    Severity,
    ValidationResult,
)
from .schemas import (
    AnalysisResponse,
    ConfigResponse,
    DetectionListResponse,
    HealthResponse,
    IncidentListResponse,
    InvestigationRequest,
    InvestigationResponse,
    JobListResponse,
    JobResponse,
    StatsResponse,
    StatusUpdateRequest,
    UploadResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

# In-memory and disk record cache for analysis jobs
_JOB_RECORDS_CACHE: Dict[str, List[LogRecord]] = {}
_START_TIME = time.time()


def get_repository() -> AnalysisRepository:
    """Dependency provider for AnalysisRepository."""
    return AnalysisRepository()


def _get_records_storage_dir() -> Path:
    """Return directory path for persisting ingested records between upload and analyze."""
    p = Path(__file__).resolve().parent.parent.parent / "data" / "cache"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _save_records_to_cache(job_id: str, records: List[LogRecord]) -> None:
    """Save parsed records to in-memory cache and disk backup."""
    _JOB_RECORDS_CACHE[job_id] = records
    try:
        cache_file = _get_records_storage_dir() / f"{job_id}.json"
        dumpable = [
            r.model_dump(mode="json") if hasattr(r, "model_dump") else r.__dict__
            for r in records
        ]
        cache_file.write_text(json.dumps(dumpable, default=str), encoding="utf-8")
    except Exception as e:
        logger.warning(f"Could not persist record cache to disk for {job_id}: {e}")


def _load_records_from_cache(job_id: str) -> List[LogRecord]:
    """Retrieve records from memory or disk backup."""
    if job_id in _JOB_RECORDS_CACHE:
        return _JOB_RECORDS_CACHE[job_id]

    cache_file = _get_records_storage_dir() / f"{job_id}.json"
    if cache_file.is_file():
        try:
            raw_data = json.loads(cache_file.read_text(encoding="utf-8"))
            records = [LogRecord(**item) for item in raw_data]
            _JOB_RECORDS_CACHE[job_id] = records
            return records
        except Exception as e:
            logger.error(f"Failed to reload cached records from disk for {job_id}: {e}")

    return []


# ====================================================================
# Health and System Routes
# ====================================================================


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    tags=["System"],
)
def get_health() -> HealthResponse:
    """Perform health and connectivity checks."""
    db_ok = True
    try:
        engine = get_engine()
        with engine.connect() as conn:
            pass
    except Exception as exc:
        logger.warning(f"Database health check failed: {exc}")
        db_ok = False

    uptime = time.time() - _START_TIME
    return HealthResponse(
        status="ok" if db_ok else "degraded",
        version="1.0.0",
        database_ok=db_ok,
        uptime_seconds=round(uptime, 2),
    )


@router.get(
    "/config",
    response_model=ConfigResponse,
    summary="Get sanitized configuration",
    tags=["System"],
)
def get_configuration() -> ConfigResponse:
    """Return runtime configuration with secret keys securely masked."""
    settings = get_settings()
    data = settings.model_dump()

    # Redact sensitive values
    sensitive_keys = {
        "secret_key",
        "openai_api_key",
        "anthropic_api_key",
        "google_api_key",
    }
    for k in sensitive_keys:
        if k in data and data[k]:
            data[k] = "********"

    return ConfigResponse(config=data)


@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Get system statistics",
    tags=["System"],
)
def get_system_stats(
    repo: AnalysisRepository = Depends(get_repository),
) -> StatsResponse:
    """Return aggregated system counts and status distributions."""
    stats = repo.get_stats()
    return StatsResponse(
        total_jobs=stats.get("total_jobs", 0),
        total_detections=stats.get("total_detections", 0),
        total_incidents=stats.get("total_incidents", 0),
        total_investigations=stats.get("total_investigations", 0),
        jobs_by_status=stats.get("jobs_by_status", {}),
        incidents_by_status=stats.get("incidents_by_status", {}),
        incidents_by_priority=stats.get("incidents_by_priority", {}),
        detections_by_severity=stats.get("detections_by_severity", {}),
    )


# ====================================================================
# Upload and Ingestion Route
# ====================================================================


@router.post(
    "/upload",
    response_model=UploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and validate log file",
    tags=["Ingestion"],
)
async def upload_log_file(
    file: UploadFile = File(..., description="Log file in CSV, JSON, or JSONL format"),
    repo: AnalysisRepository = Depends(get_repository),
) -> UploadResponse:
    """
    Upload a log file, validate its structure, and initialize an AnalysisJob.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must have a valid filename.",
        )

    settings = get_settings()
    max_bytes = settings.max_upload_size_mb * 1024 * 1024

    try:
        content_bytes = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {exc}",
        )

    if len(content_bytes) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {settings.max_upload_size_mb}MB.",
        )

    if len(content_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    try:
        records, validation_result = ingest_content(content_bytes, filename=file.filename)
    except Exception as exc:
        logger.exception("Ingestion failed")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to parse log file: {exc}",
        )

    # Create job in database
    job = repo.create_job(
        filename=file.filename,
        config_snapshot={"format": validation_result.schema_info.get("format", "unknown")},
    )
    repo.update_job(job.id, record_count=validation_result.valid_records)

    # Cache records for subsequent /analyze call
    _save_records_to_cache(job.id, records)

    message = (
        f"Successfully ingested {validation_result.valid_records} valid records "
        f"({validation_result.invalid_records} malformed, {validation_result.duplicate_count} duplicates)."
    )

    return UploadResponse(
        job_id=job.id,
        validation_result=validation_result,
        message=message,
    )


# ====================================================================
# Analysis Pipeline Route
# ====================================================================


@router.post(
    "/analyze/{job_id}",
    response_model=AnalysisResponse,
    summary="Run full analysis pipeline",
    tags=["Analysis"],
)
def run_analysis(
    job_id: str,
    repo: AnalysisRepository = Depends(get_repository),
) -> AnalysisResponse:
    """
    Execute full detection, correlation, offline investigation, and prioritization pipeline.
    """
    job = repo.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found")

    records = _load_records_from_cache(job_id)
    if not records:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No ingested records found for this job. Upload logs before analyzing.",
        )

    # Set status to RUNNING
    repo.update_job(job_id, status=AnalysisStatus.RUNNING.value)

    try:
        # 1. Detection Engine
        det_engine = DetectionEngine()
        if hasattr(det_engine, "detect"):
            detections = det_engine.detect(records)
        elif hasattr(det_engine, "run_all_detectors"):
            detections = det_engine.run_all_detectors(records)
        else:
            detections = []

        # 2. Correlation Engine
        corr_engine = CorrelationEngine()
        incidents = corr_engine.correlate(detections)

        # 3. Investigation Agent (offline mode default)
        inv_agent = InvestigationAgent(provider="offline")
        investigations: List[Investigation] = []
        for inc in incidents:
            try:
                inv = inv_agent.investigate(
                    inc,
                    context={"records": records, "detections": detections, "incidents": incidents},
                )
                investigations.append(inv)
            except Exception as e:
                logger.warning(f"Investigation failed for incident {inc.incident_id}: {e}")

        # 4. Prioritization Engine
        pri_engine = PrioritizationEngine()
        incidents = pri_engine.prioritize(incidents)

        # 5. Persist detections and incidents
        repo.save_detections(job_id, detections)
        repo.save_incidents(job_id, incidents)
        for inv in investigations:
            try:
                repo.save_investigation(inv)
            except Exception as e:
                logger.warning(f"Could not save investigation {inv.investigation_id}: {e}")

        # 6. Generate and save default JSON report
        try:
            report_gen = ReportGenerator()
            report_dict = report_gen.generate_json_report(
                job_id=job_id,
                incidents=incidents,
                detections=detections,
                investigations=investigations,
            )
            repo.save_report(job_id, report_dict, format="json")
        except Exception as e:
            logger.warning(f"Could not generate initial report for job {job_id}: {e}")

        # 7. Update Job Status
        repo.update_job(
            job_id,
            status=AnalysisStatus.COMPLETED.value,
            completion_time=datetime.now(timezone.utc),
            detection_count=len(detections),
            incident_count=len(incidents),
            error_message=None,
        )

        return AnalysisResponse(
            job_id=job_id,
            status=AnalysisStatus.COMPLETED,
            detection_count=len(detections),
            incident_count=len(incidents),
            message="Analysis pipeline completed successfully",
        )

    except Exception as exc:
        logger.exception(f"Analysis pipeline failed for job {job_id}")
        repo.update_job(
            job_id,
            status=AnalysisStatus.FAILED.value,
            error_message=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis pipeline encountered an error: {exc}",
        )


# ====================================================================
# Job Management Routes
# ====================================================================


@router.get(
    "/jobs",
    response_model=JobListResponse,
    summary="List analysis jobs",
    tags=["Jobs"],
)
def list_jobs(
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
    repo: AnalysisRepository = Depends(get_repository),
) -> JobListResponse:
    """Retrieve paginated list of log analysis jobs."""
    offset = (page - 1) * page_size
    job_rows = repo.list_jobs(limit=page_size, offset=offset)
    total = repo.count_jobs()

    jobs_out = []
    for j in job_rows:
        cfg = None
        if j.config_snapshot:
            try:
                cfg = json.loads(j.config_snapshot)
            except Exception:
                pass
        jobs_out.append(
            JobResponse(
                id=j.id,
                status=j.status,
                filename=j.filename,
                upload_time=j.upload_time,
                completion_time=j.completion_time,
                record_count=j.record_count,
                detection_count=j.detection_count,
                incident_count=j.incident_count,
                error_message=j.error_message,
                config_snapshot=cfg,
            )
        )

    return JobListResponse(
        jobs=jobs_out,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/jobs/{job_id}",
    response_model=JobResponse,
    summary="Get job details",
    tags=["Jobs"],
)
def get_job_details(
    job_id: str,
    repo: AnalysisRepository = Depends(get_repository),
) -> JobResponse:
    """Retrieve detailed state of a single analysis job."""
    job = repo.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found")

    cfg = None
    if job.config_snapshot:
        try:
            cfg = json.loads(job.config_snapshot)
        except Exception:
            pass

    return JobResponse(
        id=job.id,
        status=job.status,
        filename=job.filename,
        upload_time=job.upload_time,
        completion_time=job.completion_time,
        record_count=job.record_count,
        detection_count=job.detection_count,
        incident_count=job.incident_count,
        error_message=job.error_message,
        config_snapshot=cfg,
    )


# ====================================================================
# Detection & Incident Routes
# ====================================================================


@router.get(
    "/detections/{job_id}",
    response_model=DetectionListResponse,
    summary="Get detections for a job",
    tags=["Detections"],
)
def get_job_detections(
    job_id: str,
    type: Optional[str] = Query(None, description="Optional detection type filter"),
    severity: Optional[str] = Query(None, description="Optional severity filter"),
    repo: AnalysisRepository = Depends(get_repository),
) -> DetectionListResponse:
    """Retrieve security detections associated with a job."""
    job = repo.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found")

    detections = repo.get_detections(job_id, detection_type=type, severity=severity)
    return DetectionListResponse(detections=detections, total=len(detections))


@router.get(
    "/incidents/{job_id}",
    response_model=IncidentListResponse,
    summary="Get incidents for a job",
    tags=["Incidents"],
)
def get_job_incidents(
    job_id: str,
    repo: AnalysisRepository = Depends(get_repository),
) -> IncidentListResponse:
    """Retrieve correlated incidents for a job."""
    job = repo.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found")

    incidents = repo.get_incidents(job_id)
    return IncidentListResponse(incidents=incidents, total=len(incidents))


@router.patch(
    "/incidents/{incident_id}/status",
    summary="Update incident status",
    tags=["Incidents"],
)
def update_incident_status(
    incident_id: str,
    payload: StatusUpdateRequest,
    repo: AnalysisRepository = Depends(get_repository),
) -> Dict[str, Any]:
    """Update lifecycle status of an incident."""
    updated = repo.update_incident_status(incident_id, payload.status)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    return {
        "message": "Incident status updated successfully",
        "incident_id": incident_id,
        "status": payload.status.value,
        "updated_at": updated.updated_at.isoformat(),
    }


# ====================================================================
# Investigation Routes
# ====================================================================


@router.post(
    "/investigate/{incident_id}",
    response_model=InvestigationResponse,
    summary="Trigger incident investigation",
    tags=["Investigations"],
)
def trigger_investigation(
    incident_id: str,
    payload: Optional[InvestigationRequest] = None,
    repo: AnalysisRepository = Depends(get_repository),
) -> InvestigationResponse:
    """Run an automated AI or heuristic investigation on an incident."""
    inc_db = repo.get_incident_by_id(incident_id)
    if not inc_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    provider = payload.provider if payload else "offline"

    # Fetch incident domain model
    job_incidents = repo.get_incidents(inc_db.analysis_job_id)
    incident = next((i for i in job_incidents if i.incident_id == incident_id), None)
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    records = _load_records_from_cache(inc_db.analysis_job_id)
    detections = repo.get_detections(inc_db.analysis_job_id)

    try:
        agent = InvestigationAgent(provider=provider)
        inv = agent.investigate(
            incident,
            context={"records": records, "detections": detections, "incidents": job_incidents},
        )
        repo.save_investigation(inv)
        return InvestigationResponse(
            incident_id=incident_id,
            investigation=inv,
            message=f"Investigation completed using provider '{provider}'",
        )
    except Exception as exc:
        logger.exception("Investigation execution failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation failed: {exc}",
        )


@router.get(
    "/investigation/{incident_id}",
    response_model=InvestigationResponse,
    summary="Get incident investigation findings",
    tags=["Investigations"],
)
def get_incident_investigation(
    incident_id: str,
    repo: AnalysisRepository = Depends(get_repository),
) -> InvestigationResponse:
    """Retrieve investigation findings for an incident."""
    inv = repo.get_investigation(incident_id)
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No investigation found for this incident",
        )

    return InvestigationResponse(
        incident_id=incident_id,
        investigation=inv,
        message="Investigation retrieved successfully",
    )


# ====================================================================
# Reporting Route
# ====================================================================


@router.get(
    "/reports/{job_id}",
    summary="Get analysis report (JSON or CSV)",
    tags=["Reports"],
)
def get_report(
    job_id: str,
    format: str = Query("json", description="Report format: 'json' or 'csv'"),
    repo: AnalysisRepository = Depends(get_repository),
) -> Response:
    """
    Retrieve generated threat and incident analysis report.
    """
    fmt = format.strip().lower()
    if fmt not in ("json", "csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported format. Only 'json' and 'csv' formats are supported.",
        )

    job = repo.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found")

    # Check database cache for previously saved report
    cached = repo.get_report(job_id, fmt)
    if cached:
        if fmt == "json":
            try:
                parsed_json = json.loads(cached.content_json)
                return JSONResponse(content=parsed_json)
            except Exception:
                return Response(content=cached.content_json, media_type="application/json")
        else:
            return PlainTextResponse(
                content=cached.content_json,
                media_type="text/csv",
                headers={"Content-Disposition": f'attachment; filename="report_{job_id}.csv"'},
            )

    # Generate on-demand if not already generated
    incidents = repo.get_incidents(job_id)
    detections = repo.get_detections(job_id)
    investigations = []
    for inc in incidents:
        inv = repo.get_investigation(inc.incident_id)
        if inv:
            investigations.append(inv)

    generator = ReportGenerator()
    if fmt == "json":
        report_data = generator.generate_json_report(
            job_id=job_id,
            incidents=incidents,
            detections=detections,
            investigations=investigations,
        )
        repo.save_report(job_id, report_data, "json")
        return JSONResponse(content=report_data)
    else:
        csv_data = generator.generate_csv_report(
            job_id=job_id,
            incidents=incidents,
            detections=detections,
        )
        repo.save_report(job_id, csv_data, "csv")
        return PlainTextResponse(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="report_{job_id}.csv"'},
        )
