"""Unit tests for detection engine, statistical baselines, and individual detectors."""

from datetime import datetime, timedelta, timezone
from src.detection.baselines import (
    BaselineStats,
    compute_auth_baselines,
    compute_request_baselines,
    compute_status_baselines,
    compute_traffic_baselines,
)
from src.detection.detectors import (
    detect_auth_anomalies,
    detect_brute_force,
    detect_data_exfiltration,
    detect_dos,
    detect_http_anomalies,
    detect_injection,
    detect_path_traversal,
    detect_port_scan,
    detect_statistical_anomalies,
)
from src.detection.engine import DetectionEngine
from src.utils.models import DetectionType, LogRecord, Severity


def _create_dummy_record(
    ts: datetime,
    src_ip: str = "192.168.1.10",
    dest_ip: str = "10.0.0.1",
    dport: int = 80,
    method: str = "GET",
    url: str = "/index.html",
    status: int = 200,
    bytes_sent: int = 500,
    bytes_received: int = 200,
    username: str = None,
    action: str = None,
    raw_line: str = "log line",
) -> LogRecord:
    return LogRecord(
        timestamp=ts,
        source_ip=src_ip,
        dest_ip=dest_ip,
        dest_port=dport,
        method=method,
        url=url,
        status_code=status,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        username=username,
        action=action,
        raw_line=raw_line,
    )


def test_baseline_computation():
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    records = [
        _create_dummy_record(now + timedelta(seconds=i), bytes_sent=100 * (i + 1), status=200 if i < 8 else 404)
        for i in range(10)
    ]
    traffic_base = compute_traffic_baselines(records)
    assert traffic_base["bytes_sent"].count == 10
    assert traffic_base["bytes_sent"].median > 0

    status_base = compute_status_baselines(records)
    assert status_base["counts"]["2xx"] == 8
    assert status_base["counts"]["4xx"] == 2
    assert status_base["rates"]["4xx"] == 0.2


def test_detect_dos():
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    # Generate 60 requests in 20 seconds from single IP
    records = [
        _create_dummy_record(now + timedelta(milliseconds=300 * i), src_ip="192.168.1.200")
        for i in range(60)
    ]
    detections = detect_dos(records)
    assert len(detections) >= 1
    d = detections[0]
    assert d.detection_type == DetectionType.DOS
    assert d.source_ips == ["192.168.1.200"]
    assert d.measured_value >= 50
    assert len(d.source_event_ids) >= 50
    assert "DoS" in d.description


def test_detect_brute_force():
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    records = [
        _create_dummy_record(
            now + timedelta(seconds=i * 2),
            src_ip="10.20.30.40",
            username=f"user_{i % 3}",
            action="LOGIN_FAILED",
            status=401,
        )
        for i in range(8)
    ]
    detections = detect_brute_force(records)
    assert len(detections) >= 1
    d = detections[0]
    assert d.detection_type == DetectionType.BRUTE_FORCE
    assert d.source_ips == ["10.20.30.40"]
    assert d.evidence["failure_count"] >= 5


def test_detect_port_scan():
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    records = [
        _create_dummy_record(
            now + timedelta(seconds=i),
            src_ip="172.16.1.99",
            dport=1000 + i,
        )
        for i in range(20)
    ]
    detections = detect_port_scan(records)
    assert len(detections) >= 1
    d = detections[0]
    assert d.detection_type == DetectionType.PORT_SCAN
    assert d.evidence["unique_ports_count"] == 20
    assert d.source_ips == ["172.16.1.99"]


def test_detect_path_traversal():
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    records = [
        _create_dummy_record(
            now,
            src_ip="198.51.100.5",
            url="/static/../../etc/passwd",
        )
    ]
    detections = detect_path_traversal(records)
    assert len(detections) == 1
    d = detections[0]
    assert d.detection_type == DetectionType.PATH_TRAVERSAL
    assert d.severity == Severity.CRITICAL
    assert len(d.source_event_ids) == 1


def test_detect_injection():
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    records = [
        _create_dummy_record(
            now,
            src_ip="198.51.100.10",
            url="/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users",
        )
    ]
    detections = detect_injection(records)
    assert len(detections) == 1
    d = detections[0]
    assert d.detection_type == DetectionType.INJECTION
    assert d.severity == Severity.CRITICAL


def test_detect_data_exfiltration():
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    records = [
        _create_dummy_record(
            now + timedelta(seconds=i * 10),
            src_ip="192.168.1.50",
            dest_ip="203.0.113.88",
            bytes_sent=4_000_000,
        )
        for i in range(4)
    ]
    # Total 16MB > 10MB threshold
    detections = detect_data_exfiltration(records)
    assert len(detections) == 1
    d = detections[0]
    assert d.detection_type == DetectionType.DATA_EXFIL
    assert d.measured_value >= 10_000_000


def test_detect_http_anomalies():
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    records = [
        _create_dummy_record(
            now + timedelta(seconds=i),
            src_ip="192.168.5.5",
            status=404 if i < 15 else 200,
        )
        for i in range(20)
    ]
    detections = detect_http_anomalies(records)
    assert len(detections) == 1
    d = detections[0]
    assert d.detection_type == DetectionType.HTTP_ANOMALY
    assert d.evidence["error_rate"] >= 0.7


def test_detect_auth_anomalies_impossible_travel():
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    records = [
        _create_dummy_record(now, src_ip="1.1.1.1", username="admin_alice", action="LOGIN_SUCCESS"),
        _create_dummy_record(now + timedelta(seconds=30), src_ip="2.2.2.2", username="admin_alice", action="LOGIN_SUCCESS"),
    ]
    detections = detect_auth_anomalies(records)
    assert len(detections) == 1
    d = detections[0]
    assert d.detection_type == DetectionType.AUTH_ANOMALY
    assert d.evidence["username"] == "admin_alice"


def test_detect_statistical_anomalies():
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    # Background traffic
    records = [
        _create_dummy_record(now + timedelta(seconds=i), bytes_sent=200, bytes_received=100, status=200)
        for i in range(25)
    ]
    # Add outlier
    records.append(
        _create_dummy_record(now + timedelta(seconds=26), bytes_sent=50_000_000, bytes_received=10_000, status=500)
    )
    detections = detect_statistical_anomalies(records)
    assert len(detections) >= 1
    d = detections[0]
    assert d.detection_type == DetectionType.STATISTICAL_ANOMALY


def test_detection_engine_end_to_end():
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    normal_recs = [
        _create_dummy_record(now + timedelta(seconds=i), src_ip=f"10.0.0.{i % 5}")
        for i in range(25)
    ]
    attack_recs = [
        _create_dummy_record(
            now + timedelta(seconds=10),
            src_ip="198.51.100.66",
            url="/cgi-bin/script?id=1;%20cat%20/etc/shadow",
        )
    ]
    engine = DetectionEngine()
    results = engine.run_all_detectors(normal_recs + attack_recs)
    assert len(results) >= 1
    types = [r.detection_type for r in results]
    assert DetectionType.INJECTION in types or DetectionType.PATH_TRAVERSAL in types
