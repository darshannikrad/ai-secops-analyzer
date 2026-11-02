"""Request and response schemas for the SecOps Log Analyzer FastAPI backend."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ..utils.models import (
    AnalysisStatus,
    Detection,
    Incident,
    IncidentStatus,
    Investigation,
    ValidationResult,
)


class UploadResponse(BaseModel):
    """Response returned upon uploading a log file."""

    job_id: str = Field(description="Unique identifier for the created analysis job")
    validation_result: Optional[ValidationResult] = Field(
        default=None, description="Pre-validation results for ingested records"
    )
    message: str = Field(description="Informational status message")


class AnalysisResponse(BaseModel):
    """Response returned when an analysis pipeline completes or runs."""

    job_id: str = Field(description="Job identifier")
    status: AnalysisStatus = Field(description="Current status of the analysis job")
    detection_count: int = Field(default=0, description="Number of detected anomalies")
    incident_count: int = Field(default=0, description="Number of correlated incidents")
    message: Optional[str] = Field(default=None, description="Optional status message")


class JobResponse(BaseModel):
    """Detailed model representing an analysis job."""

    id: str
    status: str
    filename: str
    upload_time: datetime
    completion_time: Optional[datetime] = None
    record_count: int = 0
    detection_count: int = 0
    incident_count: int = 0
    error_message: Optional[str] = None
    config_snapshot: Optional[Dict[str, Any]] = None


class JobListResponse(BaseModel):
    """Paginated list of analysis jobs."""

    jobs: List[JobResponse] = Field(default_factory=list)
    total: int = Field(description="Total count of jobs available")
    page: int = Field(default=1, description="Current page number (1-based)")
    page_size: int = Field(default=50, description="Number of items per page")


class DetectionListResponse(BaseModel):
    """List response for detection queries."""

    detections: List[Detection] = Field(default_factory=list)
    total: int = Field(description="Count of returned detections")


class IncidentListResponse(BaseModel):
    """List response for incident queries."""

    incidents: List[Incident] = Field(default_factory=list)
    total: int = Field(description="Count of returned incidents")


class StatusUpdateRequest(BaseModel):
    """Payload to update an incident's lifecycle status."""

    status: IncidentStatus = Field(description="New status for the incident")


class InvestigationRequest(BaseModel):
    """Payload to trigger an AI or heuristic investigation."""

    provider: str = Field(
        default="offline",
        description="Investigation provider to use (offline, openai, anthropic, google, local)",
    )


class InvestigationResponse(BaseModel):
    """Response containing triage investigation results."""

    incident_id: str
    investigation: Optional[Investigation] = None
    message: Optional[str] = None


class HealthResponse(BaseModel):
    """Application health and availability response."""

    status: str = Field(default="ok", description="Overall system health status")
    version: str = Field(default="1.0.0", description="Backend version")
    database_ok: bool = Field(default=True, description="Database connectivity status")
    uptime_seconds: float = Field(default=0.0, description="Server uptime in seconds")


class ConfigResponse(BaseModel):
    """Sanitized configuration settings (all secrets redacted)."""

    config: Dict[str, Any] = Field(description="Sanitized application settings")


class StatsResponse(BaseModel):
    """System-wide operational metrics."""

    total_jobs: int = 0
    total_detections: int = 0
    total_incidents: int = 0
    total_investigations: int = 0
    jobs_by_status: Dict[str, int] = Field(default_factory=dict)
    incidents_by_status: Dict[str, int] = Field(default_factory=dict)
    incidents_by_priority: Dict[str, int] = Field(default_factory=dict)
    detections_by_severity: Dict[str, int] = Field(default_factory=dict)
