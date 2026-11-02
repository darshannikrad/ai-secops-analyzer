"""Repository data access layer for SecOps Log Analyzer.

Provides typed CRUD operations and bidirectional mapping between
Pydantic domain models and SQLAlchemy ORM models.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from ..utils.models import (
    AnalysisJob,
    AnalysisStatus,
    Detection,
    DetectionType,
    Incident,
    IncidentPriority,
    IncidentStatus,
    Investigation,
    InvestigationStep,
    Severity,
)
from .engine import get_session
from .models import (
    AnalysisJobDB,
    DetectionDB,
    IncidentDB,
    InvestigationDB,
    ReportDB,
)

logger = logging.getLogger(__name__)


def _to_json_str(val: Any) -> str:
    """Safely serialize an object to a JSON string."""
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    try:
        return json.dumps(val, default=str)
    except Exception:
        return str(val)


def _from_json_str(val: Optional[str], default: Any = None) -> Any:
    """Safely deserialize a JSON string to a Python object."""
    if not val:
        return default
    try:
        return json.loads(val)
    except Exception:
        return default


class AnalysisRepository:
    """Data access repository for SecOps log analysis entities."""

    def __init__(self, session_override: Optional[Session] = None):
        """
        Initialize repository.

        Args:
            session_override: Optional active session for testing or transaction sharing.
        """
        self._session_override = session_override

    def _get_session_cm(self):
        """Context manager helper returning the active or a new session."""
        if self._session_override is not None:
            @staticmethod
            def _cm():
                class DummyCM:
                    def __enter__(self_inner):
                        return self._session_override

                    def __exit__(self_inner, exc_type, exc_val, exc_tb):
                        pass
                return DummyCM()
            return _cm()
        return get_session()

    # ==========================================
    # Analysis Job Operations
    # ==========================================

    def create_job(
        self,
        filename: str,
        config_snapshot: Optional[Union[str, Dict[str, Any]]] = None,
        job_id: Optional[str] = None,
    ) -> AnalysisJobDB:
        """Create and persist a new analysis job."""
        config_str = _to_json_str(config_snapshot) if config_snapshot else None
        job = AnalysisJobDB(
            filename=filename,
            status=AnalysisStatus.PENDING.value,
            config_snapshot=config_str,
        )
        if job_id:
            job.id = job_id

        with self._get_session_cm() as session:
            session.add(job)
            session.flush()
            session.refresh(job)
            logger.info(f"Created analysis job id={job.id} for file={filename}")
            return job

    def update_job(self, job_id: str, **kwargs) -> Optional[AnalysisJobDB]:
        """Update fields of an existing analysis job."""
        with self._get_session_cm() as session:
            job = session.get(AnalysisJobDB, job_id)
            if not job:
                logger.warning(f"Analysis job {job_id} not found for update")
                return None

            for key, val in kwargs.items():
                if hasattr(job, key):
                    if key in ("config_snapshot",) and isinstance(val, (dict, list)):
                        val = _to_json_str(val)
                    elif hasattr(val, "value"):
                        val = val.value
                    setattr(job, key, val)

            session.flush()
            session.refresh(job)
            return job

    def get_job(self, job_id: str) -> Optional[AnalysisJobDB]:
        """Retrieve an analysis job by primary key id."""
        with self._get_session_cm() as session:
            return session.get(AnalysisJobDB, job_id)

    def list_jobs(self, limit: int = 50, offset: int = 0) -> List[AnalysisJobDB]:
        """List analysis jobs ordered by upload time descending."""
        with self._get_session_cm() as session:
            stmt = (
                select(AnalysisJobDB)
                .order_by(AnalysisJobDB.upload_time.desc())
                .offset(offset)
                .limit(limit)
            )
            return list(session.scalars(stmt).all())

    def count_jobs(self) -> int:
        """Get total count of analysis jobs."""
        with self._get_session_cm() as session:
            stmt = select(func.count(AnalysisJobDB.id))
            return session.scalar(stmt) or 0

    # ==========================================
    # Detection Operations
    # ==========================================

    def save_detections(self, job_id: str, detections: List[Detection]) -> List[DetectionDB]:
        """Convert and batch save domain Detection models to the database."""
        db_entries: List[DetectionDB] = []
        for d in detections:
            det_type_val = d.detection_type.value if hasattr(d.detection_type, "value") else str(d.detection_type)
            sev_val = d.severity.value if hasattr(d.severity, "value") else str(d.severity)

            entry = DetectionDB(
                id=d.detection_id,
                analysis_job_id=job_id,
                detection_type=det_type_val,
                severity=sev_val,
                confidence=d.confidence,
                description=d.description,
                evidence_json=_to_json_str(d.evidence),
                measured_value=d.measured_value,
                threshold_value=d.threshold_value,
                source_event_ids_json=_to_json_str(d.source_event_ids),
                timestamp_start=d.timestamp_start,
                timestamp_end=d.timestamp_end,
                source_ips_json=_to_json_str(d.source_ips),
                explanation=d.explanation,
            )
            db_entries.append(entry)

        with self._get_session_cm() as session:
            session.add_all(db_entries)
            session.flush()
            logger.info(f"Saved {len(db_entries)} detections for job_id={job_id}")
            return db_entries

    def get_detections(
        self,
        job_id: str,
        detection_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Detection]:
        """Fetch detections for a job and map them back to Pydantic domain models."""
        with self._get_session_cm() as session:
            stmt = select(DetectionDB).where(DetectionDB.analysis_job_id == job_id)
            if detection_type:
                stmt = stmt.where(DetectionDB.detection_type == detection_type)
            if severity:
                stmt = stmt.where(DetectionDB.severity == severity)
            stmt = stmt.order_by(DetectionDB.timestamp_start.asc())

            rows = session.scalars(stmt).all()
            return [self._detection_db_to_domain(r) for r in rows]

    def _detection_db_to_domain(self, row: DetectionDB) -> Detection:
        """Map DetectionDB entity to Pydantic Detection model."""
        try:
            det_type = DetectionType(row.detection_type)
        except ValueError:
            det_type = DetectionType.STATISTICAL_ANOMALY

        try:
            sev = Severity(row.severity)
        except ValueError:
            sev = Severity.MEDIUM

        return Detection(
            detection_id=row.id,
            detection_type=det_type,
            severity=sev,
            confidence=row.confidence,
            description=row.description,
            evidence=_from_json_str(row.evidence_json, {}),
            measured_value=row.measured_value,
            threshold_value=row.threshold_value,
            source_event_ids=_from_json_str(row.source_event_ids_json, []),
            timestamp_start=row.timestamp_start,
            timestamp_end=row.timestamp_end,
            source_ips=_from_json_str(row.source_ips_json, []),
            dest_ips=[],
            explanation=row.explanation,
        )

    # ==========================================
    # Incident Operations
    # ==========================================

    def save_incidents(self, job_id: str, incidents: List[Incident]) -> List[IncidentDB]:
        """Convert and batch save Incident models to the database."""
        db_entries: List[IncidentDB] = []
        for inc in incidents:
            sev_val = inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity)
            pri_val = inc.priority.value if hasattr(inc.priority, "value") else str(inc.priority)
            sta_val = inc.status.value if hasattr(inc.status, "value") else str(inc.status)

            det_ids = [
                d.detection_id if hasattr(d, "detection_id") else str(d)
                for d in inc.detections
            ]

            entry = IncidentDB(
                id=inc.incident_id,
                analysis_job_id=job_id,
                title=inc.title,
                severity=sev_val,
                priority=pri_val,
                status=sta_val,
                correlation_explanation=inc.correlation_explanation,
                created_at=inc.created_at,
                updated_at=inc.updated_at,
                evidence_summary_json=_to_json_str(inc.evidence_summary),
                detection_ids_json=_to_json_str(det_ids),
            )
            db_entries.append(entry)

        with self._get_session_cm() as session:
            session.add_all(db_entries)
            session.flush()
            logger.info(f"Saved {len(db_entries)} incidents for job_id={job_id}")
            return db_entries

    def get_incidents(self, job_id: str) -> List[Incident]:
        """Fetch incidents for a job and map back to Pydantic models including detections."""
        with self._get_session_cm() as session:
            # Query incidents
            inc_stmt = (
                select(IncidentDB)
                .where(IncidentDB.analysis_job_id == job_id)
                .order_by(IncidentDB.created_at.asc())
            )
            inc_rows = session.scalars(inc_stmt).all()

            # Query all detections for this job to populate incident.detections efficiently
            det_stmt = select(DetectionDB).where(DetectionDB.analysis_job_id == job_id)
            det_rows = session.scalars(det_stmt).all()
            det_map = {r.id: self._detection_db_to_domain(r) for r in det_rows}

            results: List[Incident] = []
            for inc_row in inc_rows:
                det_ids = _from_json_str(inc_row.detection_ids_json, [])
                attached_dets = [det_map[did] for did in det_ids if did in det_map]

                try:
                    sev = Severity(inc_row.severity)
                except ValueError:
                    sev = Severity.MEDIUM

                try:
                    pri = IncidentPriority(inc_row.priority)
                except ValueError:
                    pri = IncidentPriority.P3

                try:
                    sta = IncidentStatus(inc_row.status)
                except ValueError:
                    sta = IncidentStatus.NEW

                incident = Incident(
                    incident_id=inc_row.id,
                    title=inc_row.title,
                    detections=attached_dets,
                    severity=sev,
                    priority=pri,
                    status=sta,
                    correlation_explanation=inc_row.correlation_explanation,
                    created_at=inc_row.created_at,
                    updated_at=inc_row.updated_at,
                    evidence_summary=_from_json_str(inc_row.evidence_summary_json, {}),
                )
                results.append(incident)

            return results

    def get_incident_by_id(self, incident_id: str) -> Optional[IncidentDB]:
        """Fetch raw IncidentDB entity by id."""
        with self._get_session_cm() as session:
            return session.get(IncidentDB, incident_id)

    def update_incident_status(
        self, incident_id: str, status: Union[str, IncidentStatus]
    ) -> Optional[IncidentDB]:
        """Update lifecycle status of an incident."""
        status_val = status.value if hasattr(status, "value") else str(status)
        with self._get_session_cm() as session:
            inc = session.get(IncidentDB, incident_id)
            if not inc:
                return None
            inc.status = status_val
            inc.updated_at = datetime.now(timezone.utc)
            session.flush()
            session.refresh(inc)
            logger.info(f"Updated incident {incident_id} status to {status_val}")
            return inc

    # ==========================================
    # Investigation Operations
    # ==========================================

    def save_investigation(self, investigation: Investigation) -> InvestigationDB:
        """Save investigation entity and its tool steps."""
        serialized_steps = []
        for step in investigation.steps:
            if hasattr(step, "model_dump"):
                serialized_steps.append(step.model_dump(mode="json"))
            elif hasattr(step, "dict"):
                serialized_steps.append(step.dict())
            else:
                serialized_steps.append(step.__dict__)

        db_entry = InvestigationDB(
            id=investigation.investigation_id,
            incident_id=investigation.incident_id,
            provider_used=investigation.provider_used,
            steps_json=_to_json_str(serialized_steps),
            hypothesis_malicious=investigation.hypothesis_malicious,
            hypothesis_benign=investigation.hypothesis_benign,
            supporting_evidence_json=_to_json_str(investigation.supporting_evidence),
            contradictory_evidence_json=_to_json_str(investigation.contradictory_evidence),
            threat_assessment=investigation.threat_assessment,
            recommendations_json=_to_json_str(investigation.recommendations),
            confidence=investigation.confidence,
            report_text=investigation.report_text,
            created_at=investigation.created_at,
            duration_seconds=investigation.duration_seconds,
            tool_call_count=investigation.tool_call_count,
        )

        with self._get_session_cm() as session:
            session.add(db_entry)
            session.flush()
            session.refresh(db_entry)
            logger.info(f"Saved investigation {db_entry.id} for incident {investigation.incident_id}")
            return db_entry

    def get_investigation(self, incident_id: str) -> Optional[Investigation]:
        """Fetch latest investigation for an incident as domain model."""
        with self._get_session_cm() as session:
            stmt = (
                select(InvestigationDB)
                .where(InvestigationDB.incident_id == incident_id)
                .order_by(InvestigationDB.created_at.desc())
            )
            row = session.scalars(stmt).first()
            if not row:
                return None

            raw_steps = _from_json_str(row.steps_json, [])
            steps = []
            for s in raw_steps:
                try:
                    steps.append(InvestigationStep(**s))
                except Exception:
                    pass

            return Investigation(
                investigation_id=row.id,
                incident_id=row.incident_id,
                provider_used=row.provider_used,
                steps=steps,
                hypothesis_malicious=row.hypothesis_malicious,
                hypothesis_benign=row.hypothesis_benign,
                supporting_evidence=_from_json_str(row.supporting_evidence_json, []),
                contradictory_evidence=_from_json_str(row.contradictory_evidence_json, []),
                threat_assessment=row.threat_assessment,
                recommendations=_from_json_str(row.recommendations_json, []),
                confidence=row.confidence,
                report_text=row.report_text,
                created_at=row.created_at,
                duration_seconds=row.duration_seconds,
                tool_call_count=row.tool_call_count,
            )

    # ==========================================
    # Report Operations
    # ==========================================

    def save_report(self, job_id: str, report: Any, format: str) -> ReportDB:
        """Save a generated report."""
        content_str = _to_json_str(report) if not isinstance(report, str) else report
        db_entry = ReportDB(
            analysis_job_id=job_id,
            format=format.lower(),
            content_json=content_str,
            generated_at=datetime.now(timezone.utc),
        )
        with self._get_session_cm() as session:
            session.add(db_entry)
            session.flush()
            session.refresh(db_entry)
            logger.info(f"Saved report {db_entry.id} for job_id={job_id} format={format}")
            return db_entry

    def get_report(self, job_id: str, format: str) -> Optional[ReportDB]:
        """Retrieve most recent report by job id and format."""
        with self._get_session_cm() as session:
            stmt = (
                select(ReportDB)
                .where(ReportDB.analysis_job_id == job_id, ReportDB.format == format.lower())
                .order_by(ReportDB.generated_at.desc())
            )
            return session.scalars(stmt).first()

    # ==========================================
    # Maintenance and Stats
    # ==========================================

    def delete_old_jobs(self, max_age_days: int) -> int:
        """Purge analysis jobs older than max_age_days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        with self._get_session_cm() as session:
            stmt = delete(AnalysisJobDB).where(AnalysisJobDB.upload_time < cutoff)
            result = session.execute(stmt)
            deleted_count = result.rowcount or 0
            logger.info(f"Purged {deleted_count} analysis jobs older than {max_age_days} days")
            return deleted_count

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate high-level system metrics across jobs, detections, and incidents."""
        with self._get_session_cm() as session:
            total_jobs = session.scalar(select(func.count(AnalysisJobDB.id))) or 0
            total_detections = session.scalar(select(func.count(DetectionDB.id))) or 0
            total_incidents = session.scalar(select(func.count(IncidentDB.id))) or 0
            total_investigations = session.scalar(select(func.count(InvestigationDB.id))) or 0

            # Jobs by status
            jobs_by_status = dict(
                session.execute(
                    select(AnalysisJobDB.status, func.count(AnalysisJobDB.id)).group_by(
                        AnalysisJobDB.status
                    )
                ).all()
            )

            # Incidents by status
            incidents_by_status = dict(
                session.execute(
                    select(IncidentDB.status, func.count(IncidentDB.id)).group_by(
                        IncidentDB.status
                    )
                ).all()
            )

            # Incidents by priority
            incidents_by_priority = dict(
                session.execute(
                    select(IncidentDB.priority, func.count(IncidentDB.id)).group_by(
                        IncidentDB.priority
                    )
                ).all()
            )

            # Detections by severity
            detections_by_severity = dict(
                session.execute(
                    select(DetectionDB.severity, func.count(DetectionDB.id)).group_by(
                        DetectionDB.severity
                    )
                ).all()
            )

            return {
                "total_jobs": total_jobs,
                "total_detections": total_detections,
                "total_incidents": total_incidents,
                "total_investigations": total_investigations,
                "jobs_by_status": jobs_by_status,
                "incidents_by_status": incidents_by_status,
                "incidents_by_priority": incidents_by_priority,
                "detections_by_severity": detections_by_severity,
            }
