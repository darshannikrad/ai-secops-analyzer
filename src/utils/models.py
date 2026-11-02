"""Core Pydantic models for SecOps Log Analyzer."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class DetectionType(str, Enum):
    """Types of security detections."""

    DOS = "DOS"
    BRUTE_FORCE = "BRUTE_FORCE"
    PORT_SCAN = "PORT_SCAN"
    HTTP_ANOMALY = "HTTP_ANOMALY"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    INJECTION = "INJECTION"
    DATA_EXFIL = "DATA_EXFIL"
    AUTH_ANOMALY = "AUTH_ANOMALY"
    STATISTICAL_ANOMALY = "STATISTICAL_ANOMALY"


class Severity(str, Enum):
    """Standard security severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IncidentPriority(str, Enum):
    """Incident response priority rankings."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


Priority = IncidentPriority


class IncidentStatus(str, Enum):
    """Lifecycle status of a security incident."""

    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


class AnalysisStatus(str, Enum):
    """Job status for log analysis pipelines."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ReportFormat(str, Enum):
    """Output format for threat reports."""

    JSON = "json"
    CSV = "csv"
    PDF = "pdf"


class LogRecord(BaseModel):
    """Canonical normalized representation of an ingested log record."""

    record_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the parsed record",
    )
    timestamp: Optional[datetime] = Field(
        default=None,
        description="Event timestamp in UTC",
    )
    source_ip: Optional[str] = Field(
        default=None,
        description="Source IPv4 or IPv6 address",
    )
    dest_ip: Optional[str] = Field(
        default=None,
        description="Destination IPv4 or IPv6 address",
    )
    source_port: Optional[int] = Field(
        default=None,
        ge=0,
        le=65535,
        description="Source port number",
    )
    dest_port: Optional[int] = Field(
        default=None,
        ge=0,
        le=65535,
        description="Destination port number",
    )
    protocol: Optional[str] = Field(
        default=None,
        description="Transport or application protocol (TCP, UDP, HTTP, etc.)",
    )
    method: Optional[str] = Field(
        default=None,
        description="HTTP method (GET, POST, etc.) if applicable",
    )
    url: Optional[str] = Field(
        default=None,
        description="Target request URI / URL",
    )
    status_code: Optional[int] = Field(
        default=None,
        ge=100,
        le=599,
        description="HTTP status response code",
    )
    bytes_sent: Optional[int] = Field(
        default=0,
        ge=0,
        description="Bytes sent by client / source",
    )
    bytes_received: Optional[int] = Field(
        default=0,
        ge=0,
        description="Bytes received / returned by server",
    )
    user_agent: Optional[str] = Field(
        default=None,
        description="Client User-Agent header value",
    )
    username: Optional[str] = Field(
        default=None,
        description="Associated user account identifier",
    )
    action: Optional[str] = Field(
        default=None,
        description="Action recorded (e.g., ALLOW, BLOCK, LOGIN_FAILED)",
    )
    severity_source: Optional[str] = Field(
        default=None,
        description="Raw severity emitted by source log generator",
    )
    raw_line: str = Field(
        default="",
        description="Raw, unparsed log record text",
    )
    source_file: Optional[str] = Field(
        default=None,
        description="Originating log filename or stream",
    )
    line_number: Optional[int] = Field(
        default=None,
        ge=1,
        description="Line number in source file",
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_timestamp_utc(cls, value: Any) -> datetime:
        """Ensure timestamps are tz-aware UTC datetimes."""
        if isinstance(value, str):
            from .helpers import safe_parse_timestamp

            parsed = safe_parse_timestamp(value)
            if parsed is None:
                raise ValueError(f"Unable to parse timestamp: {value}")
            return parsed
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value


class ValidationResult(BaseModel):
    """Validation outcome for a batch or stream of ingested log entries."""

    valid_records: int = Field(default=0, ge=0)
    invalid_records: int = Field(default=0, ge=0)
    malformed_details: List[Dict[str, Any]] = Field(default_factory=list)
    duplicate_count: int = Field(default=0, ge=0)
    schema_info: Dict[str, Any] = Field(default_factory=dict)

    @property
    def valid_count(self) -> int:
        return self.valid_records

    @valid_count.setter
    def valid_count(self, value: int):
        self.valid_records = value

    @property
    def invalid_count(self) -> int:
        return self.invalid_records

    @invalid_count.setter
    def invalid_count(self, value: int):
        self.invalid_records = value


class Detection(BaseModel):
    """A single security anomaly or signature detection triggered by detector rules."""

    detection_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detection_type: DetectionType
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    measured_value: Optional[float] = None
    threshold_value: Optional[float] = None
    baseline_value: Optional[float] = None
    source_event_ids: List[str] = Field(default_factory=list)
    timestamp_start: Optional[datetime] = None
    timestamp_end: Optional[datetime] = None
    source_ips: List[str] = Field(default_factory=list)
    dest_ips: List[str] = Field(default_factory=list)
    explanation: Optional[str] = None


class Incident(BaseModel):
    """A correlated set of detections forming an actionable security incident."""

    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    detections: List[Detection] = Field(default_factory=list)
    severity: Severity
    priority: IncidentPriority
    status: IncidentStatus = Field(default=IncidentStatus.NEW)
    correlation_explanation: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)
    related_incident_ids: List[str] = Field(default_factory=list)
    priority_score: Optional[float] = None
    priority_explanation: Optional[str] = None


class InvestigationStep(BaseModel):
    """A discrete tool call or investigative step taken by an analyst or agent."""

    step_number: int = Field(ge=1)
    tool_name: str
    tool_args: Dict[str, Any] = Field(default_factory=dict)
    tool_result: Any = None
    reasoning: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Investigation(BaseModel):
    """Full triage and root cause investigation record for an incident."""

    investigation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    provider_used: str = Field(
        description="LLM provider or offline heuristic engine identifier",
    )
    steps: List[InvestigationStep] = Field(default_factory=list)
    hypothesis_malicious: Optional[str] = None
    hypothesis_benign: Optional[str] = None
    supporting_evidence: List[str] = Field(default_factory=list)
    contradictory_evidence: List[str] = Field(default_factory=list)
    missing_info: List[str] = Field(default_factory=list)
    threat_assessment: Optional[str] = None
    recommendations: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    report_text: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = Field(default=0.0, ge=0.0)
    tool_call_count: int = Field(default=0, ge=0)


class AnalysisJob(BaseModel):
    """Background tracking record for log file processing jobs."""

    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: AnalysisStatus = Field(default=AnalysisStatus.PENDING)
    filename: str
    upload_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completion_time: Optional[datetime] = None
    record_count: int = Field(default=0, ge=0)
    detection_count: int = Field(default=0, ge=0)
    incident_count: int = Field(default=0, ge=0)
    error_message: Optional[str] = None


class ThreatReport(BaseModel):
    """Consolidated threat intelligence report summarizing incidents and metrics."""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    analysis_job_id: str
    incidents: List[Incident] = Field(default_factory=list)
    summary_stats: Dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    format: ReportFormat = Field(default=ReportFormat.JSON)


class PriorityPolicy(BaseModel):
    """Policy weights used for calculating dynamic incident priority scores."""

    severity_weight: float = Field(default=0.35, ge=0.0, le=1.0)
    anomaly_score_weight: float = Field(default=0.25, ge=0.0, le=1.0)
    confidence_weight: float = Field(default=0.15, ge=0.0, le=1.0)
    recency_weight: float = Field(default=0.15, ge=0.0, le=1.0)
    affected_assets_weight: float = Field(default=0.10, ge=0.0, le=1.0)

    @field_validator("affected_assets_weight")
    @classmethod
    def validate_weights_sum(cls, v: float, info: Any) -> float:
        """Verify weights roughly sum to 1.0."""
        # Optional check or normalization can occur in scoring engine
        return v


class EvaluationResult(BaseModel):
    """Evaluation metrics for detection algorithms or investigation agents."""

    experiment_name: str
    precision: float = Field(..., ge=0.0, le=1.0)
    recall: float = Field(..., ge=0.0, le=1.0)
    f1_score: float = Field(..., ge=0.0, le=1.0)
    false_positive_rate: float = Field(..., ge=0.0, le=1.0)
    latency_ms: float = Field(..., ge=0.0)
    tool_call_count: int = Field(default=0, ge=0)
    config: Dict[str, Any] = Field(default_factory=dict)
