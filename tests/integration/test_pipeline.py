"""
Integration tests for the AI SecOps Log Analyzer.

Tests the full pipeline from ingestion through detection, correlation,
investigation, prioritization, and reporting.
"""

import os
import sys
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class TestFullPipeline:
    """Test the complete analysis pipeline end-to-end."""

    @pytest.fixture
    def synthetic_csv(self):
        """Generate synthetic CSV dataset."""
        from src.evaluation.synthetic_data import generate_full_dataset
        import csv
        import io

        records_raw, ground_truth = generate_full_dataset(normal_count=100, seed=42)

        csv_buffer = io.StringIO()
        fieldnames = [k for k in records_raw[0].keys() if not k.startswith("_")]
        writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
        writer.writeheader()
        for rec in records_raw:
            cleaned = {k: v for k, v in rec.items() if not k.startswith("_")}
            writer.writerow(cleaned)

        return csv_buffer.getvalue(), ground_truth

    def test_ingestion_pipeline(self, synthetic_csv):
        """Test that synthetic data can be ingested."""
        csv_content, _ = synthetic_csv
        from src.ingestion.parser import ingest_content

        records, validation = ingest_content(csv_content, "test.csv", "csv")

        assert len(records) > 0
        assert validation.valid_count > 0
        assert validation.valid_count == len(records)

    def test_detection_pipeline(self, synthetic_csv):
        """Test that detections are found in synthetic attack data."""
        csv_content, _ = synthetic_csv
        from src.ingestion.parser import ingest_content
        from src.detection.engine import DetectionEngine

        records, _ = ingest_content(csv_content, "test.csv", "csv")
        engine = DetectionEngine()
        detections = engine.run_all_detectors(records)

        assert len(detections) > 0
        # Should detect at least some of the embedded attacks
        detection_types = {str(d.detection_type) for d in detections}
        assert len(detection_types) > 0

    def test_detection_evidence_completeness(self, synthetic_csv):
        """Test that all detections have proper evidence."""
        csv_content, _ = synthetic_csv
        from src.ingestion.parser import ingest_content
        from src.detection.engine import DetectionEngine

        records, _ = ingest_content(csv_content, "test.csv", "csv")
        engine = DetectionEngine()
        detections = engine.run_all_detectors(records)

        for d in detections:
            # Every detection must have an explanation
            assert d.explanation, f"Detection {d.detection_id} missing explanation"
            # Every detection must have source event IDs
            assert d.source_event_ids is not None, f"Detection {d.detection_id} missing source_event_ids"
            assert len(d.source_event_ids) > 0, f"Detection {d.detection_id} has empty source_event_ids"
            # Every detection must have measured value
            assert d.measured_value is not None, f"Detection {d.detection_id} missing measured_value"

    def test_correlation_pipeline(self, synthetic_csv):
        """Test that detections are correlated into incidents."""
        csv_content, _ = synthetic_csv
        from src.ingestion.parser import ingest_content
        from src.detection.engine import DetectionEngine
        from src.correlation.engine import CorrelationEngine

        records, _ = ingest_content(csv_content, "test.csv", "csv")
        engine = DetectionEngine()
        detections = engine.run_all_detectors(records)

        correlator = CorrelationEngine()
        incidents = correlator.correlate(detections)

        assert len(incidents) > 0
        for inc in incidents:
            assert inc.incident_id
            assert inc.title
            assert inc.correlation_explanation
            assert len(inc.detections) > 0

    def test_investigation_pipeline(self, synthetic_csv):
        """Test offline investigation on correlated incidents."""
        csv_content, _ = synthetic_csv
        from src.ingestion.parser import ingest_content
        from src.detection.engine import DetectionEngine
        from src.correlation.engine import CorrelationEngine
        from src.investigation.agent import InvestigationAgent

        records, _ = ingest_content(csv_content, "test.csv", "csv")
        engine = DetectionEngine()
        detections = engine.run_all_detectors(records)

        correlator = CorrelationEngine()
        incidents = correlator.correlate(detections)

        agent = InvestigationAgent(provider="offline")
        context = {"records": records, "detections": detections, "incidents": incidents}

        # Investigate first incident
        if incidents:
            investigation = agent.investigate(incidents[0], context)
            assert investigation.investigation_id
            assert investigation.provider_used == "offline"
            assert investigation.tool_call_count > 0
            assert investigation.report_text
            assert investigation.hypothesis_malicious
            assert investigation.hypothesis_benign

    def test_prioritization_pipeline(self, synthetic_csv):
        """Test that incidents are prioritized correctly."""
        csv_content, _ = synthetic_csv
        from src.ingestion.parser import ingest_content
        from src.detection.engine import DetectionEngine
        from src.correlation.engine import CorrelationEngine
        from src.prioritization.engine import PrioritizationEngine

        records, _ = ingest_content(csv_content, "test.csv", "csv")
        engine = DetectionEngine()
        detections = engine.run_all_detectors(records)

        correlator = CorrelationEngine()
        incidents = correlator.correlate(detections)

        prioritizer = PrioritizationEngine()
        prioritized = prioritizer.prioritize(incidents)

        assert len(prioritized) == len(incidents)
        # Should be sorted by priority score
        if len(prioritized) >= 2:
            first_score = getattr(prioritized[0], 'priority_score', 0)
            last_score = getattr(prioritized[-1], 'priority_score', 0)
            assert first_score >= last_score

    def test_report_generation(self, synthetic_csv):
        """Test report generation from analysis results."""
        csv_content, _ = synthetic_csv
        from src.ingestion.parser import ingest_content
        from src.detection.engine import DetectionEngine
        from src.correlation.engine import CorrelationEngine
        from src.reporting.generator import ReportGenerator

        records, _ = ingest_content(csv_content, "test.csv", "csv")
        engine = DetectionEngine()
        detections = engine.run_all_detectors(records)

        correlator = CorrelationEngine()
        incidents = correlator.correlate(detections)

        reporter = ReportGenerator()
        json_report = reporter.generate_json_report(
            job_id="test-job-001",
            incidents=incidents,
            detections=detections,
        )

        assert json_report["report_metadata"]["analysis_job_id"] == "test-job-001"
        assert json_report["executive_summary"]["total_detections"] == len(detections)
        assert json_report["executive_summary"]["total_incidents"] == len(incidents)
        assert len(json_report["detailed_detections"]) == len(detections)
        assert len(json_report["evidence_chain"]) == len(incidents)

        # CSV report
        csv_report = reporter.generate_csv_report(
            job_id="test-job-001",
            incidents=incidents,
            detections=detections,
        )
        assert isinstance(csv_report, str)
        assert len(csv_report) > 0

    def test_no_evidence_fabrication(self, synthetic_csv):
        """Verify that no evidence is fabricated."""
        csv_content, ground_truth = synthetic_csv
        from src.ingestion.parser import ingest_content
        from src.detection.engine import DetectionEngine

        records, _ = ingest_content(csv_content, "test.csv", "csv")
        record_ids = {r.record_id for r in records}

        engine = DetectionEngine()
        detections = engine.run_all_detectors(records)

        for d in detections:
            # All source_event_ids must reference actual records
            for eid in d.source_event_ids or []:
                assert eid in record_ids, (
                    f"Detection {d.detection_id} references non-existent event {eid}"
                )

    def test_synthetic_data_determinism(self):
        """Test that synthetic data generation is deterministic."""
        from src.evaluation.synthetic_data import generate_full_dataset

        records1, labels1 = generate_full_dataset(normal_count=50, seed=42)
        records2, labels2 = generate_full_dataset(normal_count=50, seed=42)

        assert len(records1) == len(records2)
        for r1, r2 in zip(records1, records2):
            assert r1["timestamp"] == r2["timestamp"]
            assert r1["source_ip"] == r2["source_ip"]

    def test_ground_truth_separation(self):
        """Test that ground truth labels are separate from dataset records."""
        from src.evaluation.synthetic_data import generate_full_dataset

        records, labels = generate_full_dataset(normal_count=50, seed=42)

        # Records should not contain ground truth fields
        for rec in records:
            assert "is_malicious" not in rec
            assert "attack_type" not in rec

        # Labels should contain ground truth
        for label in labels:
            assert "is_malicious" in label
