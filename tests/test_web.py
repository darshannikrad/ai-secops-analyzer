"""Tests for the web service layer (API payloads)."""
import json
import os

import pytest

from web import service


@pytest.fixture()
def small_settings(tmp_path, monkeypatch):
    service.DATA_DIR = str(tmp_path / "data")
    service.OUTPUT_DIR = str(tmp_path / "outputs")
    monkeypatch.setenv("OPENAI_API_KEY", "")


def test_run_demo_payload_shape(small_settings):
    payload = service.run_demo(seed=3, minutes=30, provider="offline")
    assert payload["provider"] == "offline"
    assert payload["dataset"]["total_events"] > 0
    assert "evaluation" in payload and "detectors" in payload["evaluation"]
    detectors = {d["detector"] for d in payload["evaluation"]["detectors"]}
    assert {"stats_only", "rule_based", "agentic_hybrid"} <= detectors
    assert len(payload["incidents"]) > 0
    assert payload["figures"]  # figures generated


def test_demo_reproducible(small_settings):
    p1 = service.run_demo(seed=11, minutes=30, provider="offline")
    p2 = service.run_demo(seed=11, minutes=30, provider="offline")
    assert p1["dataset"]["total_events"] == p2["dataset"]["total_events"]
    # deterministic metrics must be identical; wall-clock stage timing is excluded
    drop = {"pipeline_stage_s", "cost_usd"}
    d1 = [{k: v for k, v in r.items() if k not in drop}
          for r in p1["evaluation"]["detectors"]]
    d2 = [{k: v for k, v in r.items() if k not in drop}
          for r in p2["evaluation"]["detectors"]]
    assert d1 == d2


def test_analyze_upload(small_settings):
    # generate a small labelled log, then analyze it as an unlabelled upload
    from secops.data_generator import generate_logs

    generate_logs(seed=5, minutes=30, base_rate_per_min=10, background_ips=20,
                  out_dir=service.DATA_DIR)
    with open(os.path.join(service.DATA_DIR, "logs.csv"), "rb") as fh:
        content = fh.read()
    payload = service.analyze_upload("upload.csv", content)
    assert payload["mode"] == "upload"
    assert payload["n_events"] > 0
    assert payload["evaluation"] is None          # no ground truth in upload mode
    assert len(payload["incidents"]) > 0


def test_incidents_carry_markdown(small_settings):
    payload = service.run_demo(seed=3, minutes=30, provider="offline")
    assert all("markdown" in i for i in payload["incidents"])
    assert any(i["markdown"].startswith("#") for i in payload["incidents"])
