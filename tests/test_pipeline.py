"""End-to-end pipeline smoke test (offline, no API key)."""
import os

import pytest

from secops.config import load_settings
from secops.pipeline import run_pipeline


def test_pipeline_end_to_end(tmp_path, monkeypatch):
    cfg = str(tmp_path / "config.yaml")
    monkeypatch.setenv("OPENAI_API_KEY", "")  # ensure offline
    settings = load_settings(cfg)
    settings.data["dataset"]["minutes"] = 30
    settings.data["dataset"]["seed"] = 5
    settings.data["dataset"]["output_dir"] = str(tmp_path / "data")
    settings.data["pipeline"]["output_dir"] = str(tmp_path / "outputs")
    settings.data["llm"]["provider"] = "offline"

    results = run_pipeline(settings)

    assert results["agent"]["provider"] == "offline"
    assert results["agent"]["llm_calls"] == 0
    assert len(results["agent"]["reports"]) > 0  # threats were surfaced
    assert "evaluation" in results
    ev = results["evaluation"]
    records = {d["detector"]: d for d in ev["detectors"]}
    assert {"stats_only", "rule_based", "agentic_hybrid"} <= set(records)
    # hybrid must beat the raw statistical stage on precision
    assert records["agentic_hybrid"]["precision"] >= records["stats_only"]["precision"]

    # outputs written
    for name in ["feature_frame.csv", "verdicts.json", "incident_reports.json",
                 "metrics.json", "comparison.csv", "cost_ledger.json",
                 "dossiers.json", "rule_hits.json"]:
        assert os.path.exists(os.path.join(settings.output_dir, name)), name
    reports_dir = os.path.join(settings.output_dir, "reports")
    assert any(f.endswith(".md") for f in os.listdir(reports_dir))
