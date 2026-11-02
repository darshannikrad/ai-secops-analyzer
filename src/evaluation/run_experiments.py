"""
Run all evaluation experiments.

Executes the five experimental conditions (A-E) using the synthetic dataset
and produces machine-readable results in CSV and JSON.
"""

from __future__ import annotations

import json
import logging
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.evaluation.synthetic_data import generate_full_dataset
from src.evaluation.framework import EvaluationFramework, ExperimentConfig
from src.detection.engine import DetectionEngine
from src.correlation.engine import CorrelationEngine
from src.investigation.agent import InvestigationAgent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def run_experiments():
    """Run all five experimental conditions and save results."""
    logger.info("=" * 60)
    logger.info("AI SecOps Log Analyzer - Evaluation Experiments")
    logger.info("=" * 60)

    # Generate synthetic dataset
    logger.info("Generating synthetic dataset...")
    data_dir = os.path.join("data", "sample")
    records_raw, ground_truth = generate_full_dataset(
        normal_count=500,
        seed=42,
        output_dir=data_dir,
    )
    logger.info(f"Generated {len(records_raw)} records "
                f"({sum(1 for l in ground_truth if l.get('is_malicious'))} malicious)")

    # Parse records through ingestion pipeline
    logger.info("Parsing records through ingestion pipeline...")
    from src.ingestion.parser import ingest_content
    import csv as csv_mod
    import io

    # Convert raw dicts to CSV for ingestion
    csv_buffer = io.StringIO()
    if records_raw:
        fieldnames = [k for k in records_raw[0].keys() if not k.startswith("_")]
        writer = csv_mod.DictWriter(csv_buffer, fieldnames=fieldnames)
        writer.writeheader()
        for rec in records_raw:
            cleaned = {k: v for k, v in rec.items() if not k.startswith("_")}
            writer.writerow(cleaned)

    csv_content = csv_buffer.getvalue()
    records, validation = ingest_content(csv_content, "synthetic_dataset.csv", "csv")
    logger.info(f"Ingested {len(records)} valid records")

    # Initialize engines
    detection_engine = DetectionEngine()
    correlation_engine = CorrelationEngine()
    investigation_agent = InvestigationAgent(provider="offline")

    # Run evaluation
    results_dir = os.path.join("data", "results")
    framework = EvaluationFramework(output_dir=results_dir)

    logger.info("Running experiments...")
    results = framework.run_all_experiments(
        records=records,
        ground_truth=ground_truth,
        detection_engine=detection_engine,
        correlation_engine=correlation_engine,
        investigation_agent=investigation_agent,
    )

    # Print comparison table
    logger.info("\n" + framework.generate_comparison_table())

    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("EXPERIMENT SUMMARY")
    logger.info("=" * 60)
    for r in results:
        logger.info(
            f"  {r.condition} ({r.config.get('description', '')}): "
            f"F1={r.f1_score:.3f}, P={r.precision:.3f}, R={r.recall:.3f}, "
            f"FPR={r.false_positive_rate:.3f}"
        )

    logger.info(f"\nResults saved to {results_dir}/")
    return results


if __name__ == "__main__":
    run_experiments()
