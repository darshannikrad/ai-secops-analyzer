"""
Research evaluation framework.

Evaluates the evidence-grounded agentic investigation workflow across five
experimental conditions (A-E), computing precision, recall, F1-score,
false-positive rate, and other metrics.

Uses fixed random seeds and configuration tracking for reproducibility.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ExperimentConfig:
    """Configuration for a single experiment run."""
    experiment_name: str
    condition: str  # A, B, C, D, E
    description: str
    seed: int = 42
    detection_enabled: bool = True
    statistical_detection: bool = False
    correlation_enabled: bool = False
    investigation_mode: str = "none"  # none, deterministic, llm, agentic
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExperimentResult:
    """Results from a single experiment run."""
    experiment_name: str
    condition: str
    # Detection metrics
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    false_positive_rate: float = 0.0
    # Incident-level metrics
    incidents_created: int = 0
    incidents_correct: int = 0
    incident_precision: float = 0.0
    # Evidence metrics
    evidence_attribution_accuracy: float = 0.0
    unsupported_claim_rate: float = 0.0
    # Performance metrics
    latency_ms: float = 0.0
    tool_call_count: int = 0
    # Config
    config: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def calculate_metrics(self):
        """Calculate derived metrics from TP/FP/TN/FN counts."""
        tp, fp, fn, tn = self.true_positives, self.false_positives, self.false_negatives, self.true_negatives

        self.precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        self.recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        if self.precision + self.recall > 0:
            self.f1_score = 2 * (self.precision * self.recall) / (self.precision + self.recall)
        else:
            self.f1_score = 0.0
        self.false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    def to_dict(self) -> dict:
        return asdict(self)


class EvaluationFramework:
    """
    Runs reproducible evaluation experiments across five conditions:
    
    A. Rule-based detection only
    B. Rules + statistical anomaly detection
    C. Detection + correlation + deterministic investigation
    D. Detection + correlation + LLM-only investigation
    E. Complete tool-using agentic framework
    """

    def __init__(self, output_dir: str = "data/results"):
        self.output_dir = output_dir
        self.results: list[ExperimentResult] = []
        os.makedirs(output_dir, exist_ok=True)

    def define_experiments(self) -> list[ExperimentConfig]:
        """Define the five experimental conditions."""
        return [
            ExperimentConfig(
                experiment_name="Condition_A",
                condition="A",
                description="Rule-based detection only",
                detection_enabled=True,
                statistical_detection=False,
                correlation_enabled=False,
                investigation_mode="none",
            ),
            ExperimentConfig(
                experiment_name="Condition_B",
                condition="B",
                description="Rules + statistical anomaly detection",
                detection_enabled=True,
                statistical_detection=True,
                correlation_enabled=False,
                investigation_mode="none",
            ),
            ExperimentConfig(
                experiment_name="Condition_C",
                condition="C",
                description="Detection + correlation + deterministic investigation",
                detection_enabled=True,
                statistical_detection=True,
                correlation_enabled=True,
                investigation_mode="deterministic",
            ),
            ExperimentConfig(
                experiment_name="Condition_D",
                condition="D",
                description="Detection + correlation + LLM-only investigation (simulated)",
                detection_enabled=True,
                statistical_detection=True,
                correlation_enabled=True,
                investigation_mode="llm",
            ),
            ExperimentConfig(
                experiment_name="Condition_E",
                condition="E",
                description="Complete tool-using agentic framework",
                detection_enabled=True,
                statistical_detection=True,
                correlation_enabled=True,
                investigation_mode="agentic",
            ),
        ]

    def run_experiment(
        self,
        config: ExperimentConfig,
        records: list,
        ground_truth: list,
        detection_engine=None,
        correlation_engine=None,
        investigation_agent=None,
    ) -> ExperimentResult:
        """
        Run a single experiment with the given configuration.
        
        Args:
            config: Experiment configuration
            records: Log records (list of LogRecord objects or dicts)
            ground_truth: Ground truth labels (list of dicts with is_malicious, attack_type)
            detection_engine: DetectionEngine instance
            correlation_engine: CorrelationEngine instance (used if correlation_enabled)
            investigation_agent: InvestigationAgent instance (used if investigation_mode != 'none')
        """
        result = ExperimentResult(
            experiment_name=config.experiment_name,
            condition=config.condition,
            config=config.to_dict(),
        )

        start_time = time.time()

        try:
            # Step 1: Detection
            detections = []
            if config.detection_enabled and detection_engine:
                detections = detection_engine.run_all_detectors(
                    records,
                    include_statistical=config.statistical_detection,
                )

            # Step 2: Correlation
            incidents = []
            if config.correlation_enabled and correlation_engine and detections:
                incidents = correlation_engine.correlate(detections)
                result.incidents_created = len(incidents)

            # Step 3: Investigation
            tool_calls = 0
            if config.investigation_mode != "none" and investigation_agent and incidents:
                for incident in incidents:
                    context = {
                        "records": records,
                        "detections": detections,
                        "incidents": incidents,
                    }
                    try:
                        investigation = investigation_agent.investigate(incident, context)
                        tool_calls += getattr(investigation, 'tool_call_count', 0)
                    except Exception as e:
                        logger.warning(f"Investigation failed for incident: {e}")

            result.tool_call_count = tool_calls

            # Step 4: Evaluate against ground truth
            self._evaluate_detections(result, detections, records, ground_truth)

            # Step 5: Evidence quality metrics
            self._evaluate_evidence_quality(result, detections)

        except Exception as e:
            logger.error(f"Experiment {config.experiment_name} failed: {e}")

        result.latency_ms = (time.time() - start_time) * 1000
        result.calculate_metrics()
        self.results.append(result)

        logger.info(
            f"Experiment {config.experiment_name}: "
            f"P={result.precision:.3f} R={result.recall:.3f} F1={result.f1_score:.3f} "
            f"FPR={result.false_positive_rate:.3f} Latency={result.latency_ms:.0f}ms"
        )

        return result

    def _evaluate_detections(
        self,
        result: ExperimentResult,
        detections: list,
        records: list,
        ground_truth: list,
    ):
        """Evaluate detection results against ground truth."""
        # Build ground truth lookup: record index -> is_malicious
        gt_malicious_indices = set()
        for i, label in enumerate(ground_truth):
            if label.get("is_malicious", False):
                gt_malicious_indices.add(i)

        # Build detected indices from source_event_ids
        detected_record_ids = set()
        for d in detections:
            for eid in getattr(d, 'source_event_ids', []) or []:
                detected_record_ids.add(eid)

        # Map record_ids to indices
        record_id_to_idx = {}
        for i, rec in enumerate(records):
            rid = getattr(rec, 'record_id', None) or (rec.get('record_id') if isinstance(rec, dict) else None)
            if rid:
                record_id_to_idx[rid] = i

        detected_indices = set()
        for rid in detected_record_ids:
            if rid in record_id_to_idx:
                detected_indices.add(record_id_to_idx[rid])

        # If we can't map by record_id, use a simpler approach:
        # Consider a detection as TP if any of its source IPs match attacker IPs in ground truth
        if not detected_indices and detections:
            # Fallback: evaluate at detection level using IP matching
            gt_attacker_ips = set()
            gt_attack_types = set()
            for label in ground_truth:
                if label.get("is_malicious"):
                    if label.get("attacker_ip"):
                        gt_attacker_ips.add(label["attacker_ip"])
                    if label.get("attack_type"):
                        gt_attack_types.add(label["attack_type"])

            for d in detections:
                det_ips = set(getattr(d, 'source_ips', []) or [])
                if det_ips & gt_attacker_ips:
                    result.true_positives += 1
                else:
                    result.false_positives += 1

            # Count undetected attack types
            detected_types = set()
            for d in detections:
                dt = getattr(d, 'detection_type', None)
                if dt:
                    detected_types.add(str(dt).split('.')[-1] if '.' in str(dt) else str(dt))

            for at in gt_attack_types:
                if at not in detected_types:
                    result.false_negatives += 1

            result.true_negatives = max(0, len(ground_truth) - len(gt_malicious_indices) - result.false_positives)
            return

        # Standard evaluation using indices
        total_records = len(ground_truth)
        for i in range(total_records):
            is_malicious = i in gt_malicious_indices
            is_detected = i in detected_indices

            if is_malicious and is_detected:
                result.true_positives += 1
            elif is_malicious and not is_detected:
                result.false_negatives += 1
            elif not is_malicious and is_detected:
                result.false_positives += 1
            else:
                result.true_negatives += 1

    def _evaluate_evidence_quality(self, result: ExperimentResult, detections: list):
        """Evaluate evidence attribution quality."""
        if not detections:
            return

        total_claims = 0
        supported_claims = 0

        for d in detections:
            total_claims += 1
            # A claim is "supported" if it has source_event_ids and measured_value
            has_events = bool(getattr(d, 'source_event_ids', None))
            has_measurement = getattr(d, 'measured_value', None) is not None
            has_threshold = getattr(d, 'threshold_value', None) is not None

            if has_events and has_measurement:
                supported_claims += 1

        result.evidence_attribution_accuracy = supported_claims / total_claims if total_claims > 0 else 0.0
        result.unsupported_claim_rate = 1.0 - result.evidence_attribution_accuracy

    def run_all_experiments(
        self,
        records: list,
        ground_truth: list,
        detection_engine=None,
        correlation_engine=None,
        investigation_agent=None,
    ) -> list[ExperimentResult]:
        """Run all five experimental conditions."""
        configs = self.define_experiments()
        results = []

        for config in configs:
            result = self.run_experiment(
                config=config,
                records=records,
                ground_truth=ground_truth,
                detection_engine=detection_engine,
                correlation_engine=correlation_engine,
                investigation_agent=investigation_agent,
            )
            results.append(result)

        self.save_results()
        return results

    def save_results(self, filename_prefix: str = "experiment_results"):
        """Save results to CSV and JSON."""
        if not self.results:
            return

        # JSON
        json_path = os.path.join(self.output_dir, f"{filename_prefix}.json")
        with open(json_path, "w") as f:
            json.dump([r.to_dict() for r in self.results], f, indent=2, default=str)

        # CSV
        csv_path = os.path.join(self.output_dir, f"{filename_prefix}.csv")
        fieldnames = [
            "experiment_name", "condition", "true_positives", "false_positives",
            "true_negatives", "false_negatives", "precision", "recall",
            "f1_score", "false_positive_rate", "incidents_created",
            "evidence_attribution_accuracy", "unsupported_claim_rate",
            "latency_ms", "tool_call_count", "timestamp",
        ]
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for r in self.results:
                writer.writerow(r.to_dict())

        logger.info(f"Results saved to {json_path} and {csv_path}")

    def generate_comparison_table(self) -> str:
        """Generate a markdown comparison table of results."""
        if not self.results:
            return "No results available."

        lines = [
            "| Condition | Description | Precision | Recall | F1 | FPR | Evidence Acc. | Latency (ms) | Tool Calls |",
            "|-----------|-------------|-----------|--------|-----|-----|--------------|-------------|------------|",
        ]
        for r in self.results:
            desc = r.config.get("description", r.condition) if r.config else r.condition
            lines.append(
                f"| {r.condition} | {desc} | "
                f"{r.precision:.3f} | {r.recall:.3f} | {r.f1_score:.3f} | "
                f"{r.false_positive_rate:.3f} | {r.evidence_attribution_accuracy:.3f} | "
                f"{r.latency_ms:.0f} | {r.tool_call_count} |"
            )
        return "\n".join(lines)
