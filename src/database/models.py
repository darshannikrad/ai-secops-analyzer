"""SQLAlchemy ORM models for SecOps Log Analyzer.

Uses SQLAlchemy 2.0 style DeclarativeBase with typed mapped_column definitions.
JSON fields are persisted as Text containing serialized JSON strings.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


class AnalysisJobDB(Base):
    """Database model for an analysis job tracking uploaded log processing."""

    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_new_id)
    status: Mapped[str] = mapped_column(String(32), index=True, default="PENDING")
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    upload_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, nullable=False, index=True
    )
    completion_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    record_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    detection_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    incident_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    config_snapshot: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    detections: Mapped[List[DetectionDB]] = relationship(
        "DetectionDB", back_populates="analysis_job", cascade="all, delete-orphan"
    )
    incidents: Mapped[List[IncidentDB]] = relationship(
        "IncidentDB", back_populates="analysis_job", cascade="all, delete-orphan"
    )
    reports: Mapped[List[ReportDB]] = relationship(
        "ReportDB", back_populates="analysis_job", cascade="all, delete-orphan"
    )


class DetectionDB(Base):
    """Database model for security detection entries."""

    __tablename__ = "detections"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_new_id)
    analysis_job_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    detection_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    measured_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    threshold_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    source_event_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    timestamp_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    timestamp_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ips_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationship
    analysis_job: Mapped[AnalysisJobDB] = relationship("AnalysisJobDB", back_populates="detections")


class IncidentDB(Base):
    """Database model for security incidents grouping related detections."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_new_id)
    analysis_job_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    priority: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), index=True, default="NEW", nullable=False)
    correlation_explanation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, onupdate=_utc_now, nullable=False
    )
    evidence_summary_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    detection_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    # Relationships
    analysis_job: Mapped[AnalysisJobDB] = relationship("AnalysisJobDB", back_populates="incidents")
    investigations: Mapped[List[InvestigationDB]] = relationship(
        "InvestigationDB", back_populates="incident", cascade="all, delete-orphan"
    )


class InvestigationDB(Base):
    """Database model for AI/offline triage investigations conducted on incidents."""

    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_new_id)
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_used: Mapped[str] = mapped_column(String(64), nullable=False)
    steps_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    hypothesis_malicious: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hypothesis_benign: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    supporting_evidence_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    contradictory_evidence_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    threat_assessment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendations_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    report_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, nullable=False
    )
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    tool_call_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationship
    incident: Mapped[IncidentDB] = relationship("IncidentDB", back_populates="investigations")


class ReportDB(Base):
    """Database model for generated threat and analysis reports."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_new_id)
    analysis_job_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    format: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    content_json: Mapped[str] = mapped_column(Text, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, nullable=False
    )

    # Relationship
    analysis_job: Mapped[AnalysisJobDB] = relationship("AnalysisJobDB", back_populates="reports")
