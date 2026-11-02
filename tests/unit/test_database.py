"""Unit tests for the SecOps analyzer database models, engine, and repository."""

import os
from datetime import datetime, timezone
try:
    import pytest
except ImportError:
    class _PytestStub:
        @staticmethod
        def fixture(*args, **kwargs):
            if args and callable(args[0]):
                return args[0]
            def decorator(fn):
                return fn
            return decorator
    pytest = _PytestStub()
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.database.engine import init_db
from src.database.models import (
    AnalysisJobDB,
    Base,
    DetectionDB,
    IncidentDB,
    InvestigationDB,
    ReportDB,
)
from src.database.repository import AnalysisRepository
from src.utils.models import (
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


@pytest.fixture
def in_memory_repo():
    """Create a temporary in-memory SQLite database and repository."""
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = session_factory()
    repo = AnalysisRepository(session_override=session)
    yield repo
    session.close()
    engine.dispose()


def test_job_crud(in_memory_repo):
    """Test job creation, retrieval, listing, and updates."""
    job = in_memory_repo.create_job("test_syslog.csv", config_snapshot={"fmt": "csv"})
    assert job.id is not None
    assert job.filename == "test_syslog.csv"
    assert job.status == AnalysisStatus.PENDING.value

    # Get job
    retrieved = in_memory_repo.get_job(job.id)
    assert retrieved is not None
    assert retrieved.id == job.id

    # Update job
    updated = in_memory_repo.update_job(
        job.id,
        status=AnalysisStatus.COMPLETED.value,
        record_count=100,
        detection_count=2,
    )
    assert updated.status == AnalysisStatus.COMPLETED.value
    assert updated.record_count == 100
    assert updated.detection_count == 2

    # List jobs
    jobs = in_memory_repo.list_jobs(limit=10, offset=0)
    assert len(jobs) == 1
    assert jobs[0].id == job.id


def test_detections_and_incidents(in_memory_repo):
    """Test saving and retrieving detections and correlated incidents."""
    job = in_memory_repo.create_job("network.log")

    detection = Detection(
        detection_id="det-123",
        detection_type=DetectionType.PORT_SCAN,
        severity=Severity.HIGH,
        confidence=0.85,
        description="Port scan detected across 20 ports",
        evidence={"ports": [80, 443, 22]},
        source_event_ids=["evt-1", "evt-2"],
        timestamp_start=datetime.now(timezone.utc),
        timestamp_end=datetime.now(timezone.utc),
        source_ips=["10.10.10.5"],
    )

    in_memory_repo.save_detections(job.id, [detection])
    fetched_dets = in_memory_repo.get_detections(job.id)
    assert len(fetched_dets) == 1
    assert fetched_dets[0].detection_id == "det-123"
    assert fetched_dets[0].detection_type == DetectionType.PORT_SCAN

    incident = Incident(
        incident_id="inc-456",
        title="Port Scan Activity",
        detections=[detection],
        severity=Severity.HIGH,
        priority=IncidentPriority.P2,
        status=IncidentStatus.NEW,
        correlation_explanation="Single source recon",
    )

    in_memory_repo.save_incidents(job.id, [incident])
    fetched_incs = in_memory_repo.get_incidents(job.id)
    assert len(fetched_incs) == 1
    assert fetched_incs[0].incident_id == "inc-456"
    assert len(fetched_incs[0].detections) == 1
    assert fetched_incs[0].detections[0].detection_id == "det-123"

    # Status update
    updated_inc = in_memory_repo.update_incident_status("inc-456", IncidentStatus.CONFIRMED)
    assert updated_inc.status == IncidentStatus.CONFIRMED.value


def test_investigation_and_reports(in_memory_repo):
    """Test saving and retrieving investigation results and threat reports."""
    job = in_memory_repo.create_job("logs.json")
    incident = Incident(
        incident_id="inc-789",
        title="Injection Attempt",
        detections=[],
        severity=Severity.CRITICAL,
        priority=IncidentPriority.P1,
        status=IncidentStatus.NEW,
        correlation_explanation="SQLi payloads identified",
    )
    in_memory_repo.save_incidents(job.id, [incident])

    step = InvestigationStep(
        step_number=1,
        tool_name="get_incident_details",
        tool_args={"incident_id": "inc-789"},
        tool_result={"info": "analyzed"},
        reasoning="Inspect incident indicators",
    )
    investigation = Investigation(
        investigation_id="inv-999",
        incident_id="inc-789",
        provider_used="offline",
        steps=[step],
        threat_assessment="Critical SQL Injection threat confirmed",
        recommendations=["Block source IP", "Patch SQL vulnerability"],
        confidence=0.9,
    )
    in_memory_repo.save_investigation(investigation)

    fetched_inv = in_memory_repo.get_investigation("inc-789")
    assert fetched_inv is not None
    assert fetched_inv.investigation_id == "inv-999"
    assert fetched_inv.confidence == 0.9
    assert len(fetched_inv.steps) == 1

    # Report test
    rep = in_memory_repo.save_report(job.id, {"executive_summary": "All good"}, "json")
    assert rep.format == "json"
    fetched_rep = in_memory_repo.get_report(job.id, "json")
    assert fetched_rep is not None
    assert "executive_summary" in fetched_rep.content_json


def test_stats(in_memory_repo):
    """Test statistics aggregation method."""
    job = in_memory_repo.create_job("stats.csv")
    stats = in_memory_repo.get_stats()
    assert stats["total_jobs"] == 1
    assert stats["jobs_by_status"]["PENDING"] == 1
