"""Unit tests for the event correlation engine."""

import unittest
from datetime import datetime, timedelta, timezone

from src.correlation.engine import CorrelationEngine
from src.utils.models import Detection, DetectionType, Priority, Severity


class TestCorrelationEngine(unittest.TestCase):
    """Test suite for CorrelationEngine logic and clustering rules."""

    def setUp(self) -> None:
        self.engine = CorrelationEngine(time_window_minutes=30, ip_overlap_threshold=0.5)
        self.base_time = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)

    def test_empty_detections(self) -> None:
        """Engine should return empty list when no detections provided."""
        incidents = self.engine.correlate([])
        self.assertEqual(incidents, [])

    def test_single_detection_incident(self) -> None:
        """A single detection creates an isolated incident with full metadata."""
        det = Detection(
            detection_id="det-1",
            detection_type=DetectionType.PORT_SCAN,
            severity=Severity.MEDIUM,
            confidence=0.8,
            description="Recon port scan detected",
            evidence={"ports_scanned": [22, 80, 443]},
            measured_value=15.0,
            threshold_value=10.0,
            baseline_value=1.0,
            source_event_ids=["evt-1", "evt-2"],
            timestamp_start=self.base_time,
            timestamp_end=self.base_time + timedelta(minutes=5),
            source_ips=["192.168.1.50"],
            dest_ips=["10.0.0.1"],
            explanation="15 distinct ports scanned within 5 minutes",
        )
        incidents = self.engine.correlate([det])
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.severity, Severity.MEDIUM)
        self.assertEqual(len(inc.detections), 1)
        self.assertIn("192.168.1.50", inc.title)
        self.assertIn("PORT_SCAN", inc.correlation_explanation)

    def test_same_source_ip_merge(self) -> None:
        """Detections from the same source IP within the time window should merge."""
        t1 = self.base_time
        t2 = t1 + timedelta(minutes=10)

        d1 = Detection(
            detection_id="det-1",
            detection_type=DetectionType.PORT_SCAN,
            severity=Severity.LOW,
            confidence=0.7,
            description="Port scan",
            timestamp_start=t1,
            timestamp_end=t1 + timedelta(minutes=2),
            source_ips=["198.51.100.22"],
            dest_ips=["10.0.0.10"],
        )
        d2 = Detection(
            detection_id="det-2",
            detection_type=DetectionType.BRUTE_FORCE,
            severity=Severity.HIGH,
            confidence=0.85,
            description="SSH brute force",
            timestamp_start=t2,
            timestamp_end=t2 + timedelta(minutes=3),
            source_ips=["198.51.100.22"],
            dest_ips=["10.0.0.10"],
        )

        incidents = self.engine.correlate([d1, d2])
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(len(inc.detections), 2)
        self.assertEqual(inc.severity, Severity.HIGH)
        self.assertIn("Attack chain progression", inc.correlation_explanation)
        self.assertIn("198.51.100.22", inc.correlation_explanation)

    def test_attack_chain_multi_stage_escalation(self) -> None:
        """Complete attack chains (recon -> exploit -> exfil) should escalate priority/severity."""
        t0 = self.base_time
        d1 = Detection(
            detection_id="det-1",
            detection_type=DetectionType.PORT_SCAN,
            severity=Severity.LOW,
            confidence=0.8,
            description="Recon scan",
            timestamp_start=t0,
            timestamp_end=t0 + timedelta(minutes=2),
            source_ips=["203.0.113.5"],
            dest_ips=["10.0.0.50"],
        )
        d2 = Detection(
            detection_id="det-2",
            detection_type=DetectionType.INJECTION,
            severity=Severity.HIGH,
            confidence=0.9,
            description="SQL injection exploit",
            timestamp_start=t0 + timedelta(minutes=5),
            timestamp_end=t0 + timedelta(minutes=7),
            source_ips=["203.0.113.5"],
            dest_ips=["10.0.0.50"],
        )
        d3 = Detection(
            detection_id="det-3",
            detection_type=DetectionType.DATA_EXFIL,
            severity=Severity.HIGH,
            confidence=0.95,
            description="Data exfiltration transfer",
            timestamp_start=t0 + timedelta(minutes=15),
            timestamp_end=t0 + timedelta(minutes=20),
            source_ips=["203.0.113.5"],
            dest_ips=["10.0.0.50"],
        )

        incidents = self.engine.correlate([d1, d2, d3])
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(len(inc.detections), 3)
        # Escalation: 3 distinct stages + multiple HIGHs elevates to CRITICAL / P1
        self.assertEqual(inc.severity, Severity.CRITICAL)
        self.assertEqual(inc.priority, Priority.P1)
        self.assertIn("Multi-Vector", inc.title)

    def test_same_target_multi_vector_merge(self) -> None:
        """Attacks targeting same destination IP within time window should merge."""
        t0 = self.base_time
        d1 = Detection(
            detection_id="det-1",
            detection_type=DetectionType.DOS,
            severity=Severity.HIGH,
            confidence=0.85,
            description="SYN flood DoS",
            timestamp_start=t0,
            timestamp_end=t0 + timedelta(minutes=5),
            source_ips=["192.0.2.1"],
            dest_ips=["10.0.0.80"],
        )
        d2 = Detection(
            detection_id="det-2",
            detection_type=DetectionType.HTTP_ANOMALY,
            severity=Severity.MEDIUM,
            confidence=0.75,
            description="Malformed HTTP headers",
            timestamp_start=t0 + timedelta(minutes=4),
            timestamp_end=t0 + timedelta(minutes=8),
            source_ips=["192.0.2.2"],
            dest_ips=["10.0.0.80"],
        )

        incidents = self.engine.correlate([d1, d2])
        self.assertEqual(len(incidents), 1)
        self.assertIn("10.0.0.80", incidents[0].correlation_explanation)

    def test_unrelated_events_never_merged(self) -> None:
        """Events with disjoint IPs and unrelated vectors must never be merged."""
        t0 = self.base_time
        d1 = Detection(
            detection_id="det-1",
            detection_type=DetectionType.BRUTE_FORCE,
            severity=Severity.HIGH,
            confidence=0.8,
            description="SSH brute force",
            timestamp_start=t0,
            timestamp_end=t0 + timedelta(minutes=5),
            source_ips=["192.168.1.10"],
            dest_ips=["10.0.0.1"],
        )
        d2 = Detection(
            detection_id="det-2",
            detection_type=DetectionType.PATH_TRAVERSAL,
            severity=Severity.HIGH,
            confidence=0.8,
            description="Web path traversal",
            timestamp_start=t0 + timedelta(minutes=2),
            timestamp_end=t0 + timedelta(minutes=7),
            source_ips=["10.200.0.55"],
            dest_ips=["172.16.0.99"],
        )

        incidents = self.engine.correlate([d1, d2])
        self.assertEqual(len(incidents), 2)
        self.assertNotEqual(incidents[0].incident_id, incidents[1].incident_id)

    def test_time_window_expiry_prevents_merge(self) -> None:
        """Events beyond time window threshold must NOT be merged despite same IP."""
        t0 = self.base_time
        t_late = t0 + timedelta(hours=2)  # Exceeds 30 min window

        d1 = Detection(
            detection_id="det-1",
            detection_type=DetectionType.PORT_SCAN,
            severity=Severity.LOW,
            confidence=0.7,
            description="Morning scan",
            timestamp_start=t0,
            timestamp_end=t0 + timedelta(minutes=5),
            source_ips=["198.51.100.99"],
            dest_ips=["10.0.0.1"],
        )
        d2 = Detection(
            detection_id="det-2",
            detection_type=DetectionType.PORT_SCAN,
            severity=Severity.LOW,
            confidence=0.7,
            description="Afternoon scan",
            timestamp_start=t_late,
            timestamp_end=t_late + timedelta(minutes=5),
            source_ips=["198.51.100.99"],
            dest_ips=["10.0.0.1"],
        )

        incidents = self.engine.correlate([d1, d2])
        self.assertEqual(len(incidents), 2)


if __name__ == "__main__":
    unittest.main()
