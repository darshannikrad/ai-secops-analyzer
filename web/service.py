"""Web application — backend service.

Wraps the SecOps pipeline for the dashboard API: run demo evaluations, analyze
uploaded log files, and regenerate figures — all behind simple JSON endpoints.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

import pandas as pd

from secops.config import load_settings
from secops.data_generator import generate_logs, summarize
from secops.figures import make_all
from secops.pipeline import analyze_logs, run_pipeline

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "outputs")
UPLOAD_DIR = os.path.join(PROJECT_ROOT, "outputs", "uploads")

_last_run: Dict[str, Any] = {}

# All pipeline runs share data/ and outputs/ — serialise them so concurrent
# requests (FastAPI threadpool) cannot clobber each other's files.
_PIPELINE_LOCK = threading.Lock()

MIN_MINUTES, MAX_MINUTES = 10, 720
MIN_SEED, MAX_SEED = 0, 999_999
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


# ---------------------------------------------------------------------------
# serialization helpers
# ---------------------------------------------------------------------------

def _load_json(path: str, default=None):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _dataset_summary() -> Dict[str, Any]:
    logs = os.path.join(DATA_DIR, "logs.csv")
    gt = os.path.join(DATA_DIR, "ground_truth.json")
    if not os.path.exists(logs):
        return {}
    df = pd.read_csv(logs)
    return {
        **summarize(df, _load_json(gt, [])),
        "attacks_by_type": df[df["is_attack"] == 1]
        .groupby("attack_type").size().to_dict(),
    }


def _incidents_payload() -> List[Dict[str, Any]]:
    reports = _load_json(os.path.join(OUTPUT_DIR, "incident_reports.json"), [])
    markdown_dir = os.path.join(OUTPUT_DIR, "reports")
    for r in reports:
        md_path = os.path.join(markdown_dir, f"{r['incident_id']}.md")
        r["markdown"] = _read(md_path)
    return reports


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def _build_payload(provider: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    metrics = _load_json(os.path.join(OUTPUT_DIR, "metrics.json"), {})
    verdicts = _load_json(os.path.join(OUTPUT_DIR, "verdicts.json"), [])
    ledger = _load_json(os.path.join(OUTPUT_DIR, "cost_ledger.json"), {})
    incidents = _incidents_payload()
    payload = {
        "run_id": str(uuid.uuid4())[:8],
        "provider": provider,
        "llm_cost_usd": float(ledger.get("llm_cost_usd", 0.0)),
        "prompt_tokens": ledger.get("prompt_tokens", 0),
        "completion_tokens": ledger.get("completion_tokens", 0),
        "llm_calls": ledger.get("llm_calls", 0),
        "offline_fallbacks": ledger.get("offline_fallbacks", 0),
        "stage_times": metrics.get("stage_times_s", {}),
        "dataset": _dataset_summary(),
        "evaluation": metrics,
        "verdict_counts": {
            "candidates": len(verdicts),
            "threats": sum(1 for v in verdicts if v.get("is_threat")),
            "benign": sum(1 for v in verdicts if not v.get("is_threat")),
            "review": sum(1 for v in verdicts if v.get("needs_human_review")),
        },
        "incidents": incidents,
        "figures": [
            n for n in os.listdir(os.path.join(OUTPUT_DIR, "figures"))
            if n.endswith(".png")
        ] if os.path.isdir(os.path.join(OUTPUT_DIR, "figures")) else [],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if extra:
        payload.update(extra)
    return payload


# ---------------------------------------------------------------------------
# operations
# ---------------------------------------------------------------------------

def run_demo(seed: Optional[int], minutes: Optional[int],
             provider: str = "offline") -> Dict[str, Any]:
    """Run the full pipeline (data → stats → rules → agents → evaluation).

    Inputs are clamped server-side (no unbounded jobs); pipeline execution is
    serialised with a lock because all runs share the data/ and outputs/ dirs.
    """
    seed = max(MIN_SEED, min(int(seed or 7), MAX_SEED))
    minutes = max(MIN_MINUTES, min(int(minutes or 90), MAX_MINUTES))

    settings = load_settings(os.path.join(PROJECT_ROOT, "config.yaml"))
    settings.data["dataset"]["output_dir"] = DATA_DIR
    settings.data["pipeline"]["output_dir"] = OUTPUT_DIR
    settings.data["dataset"]["seed"] = seed
    settings.data["dataset"]["minutes"] = minutes
    settings.data["llm"]["provider"] = provider

    t0 = time.perf_counter()
    with _PIPELINE_LOCK:
        results = run_pipeline(settings)
        figures = make_all(settings, OUTPUT_DIR)
    payload = _build_payload(provider, extra={
        "total_wall_s": round(time.perf_counter() - t0, 2),
        "figures": figures,
    })
    global _last_run
    _last_run = payload
    return payload


def analyze_upload(filename: str, content: bytes) -> Dict[str, Any]:
    """Analyze an uploaded access-log CSV (no ground truth)."""
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError(f"file too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)")
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    safe = os.path.basename(filename).replace(" ", "_")[:120]
    dest = os.path.join(UPLOAD_DIR, f"{int(time.time())}_{safe}")
    with open(dest, "wb") as fh:
        fh.write(content)

    settings = load_settings(os.path.join(PROJECT_ROOT, "config.yaml"))
    settings.data["dataset"]["output_dir"] = DATA_DIR
    settings.data["pipeline"]["output_dir"] = OUTPUT_DIR
    with _PIPELINE_LOCK:
        result = analyze_logs(settings, dest)

    incidents = _incidents_payload()
    return {
        "run_id": str(uuid.uuid4())[:8],
        "mode": "upload",
        "filename": safe,
        "n_events": result["n_events"],
        "n_anomalies": result["n_anomalies"],
        "n_rule_hits": result["n_rule_hits"],
        "n_reports": result["n_reports"],
        "provider": result["agent"]["provider"],
        "cost_usd": result["agent"]["llm_cost_usd"],
        "incidents": incidents,
        "verdict_counts": {
            "candidates": result["agent"]["candidate_ips"],
            "threats": sum(1 for v in result["agent"]["verdicts"] if v.is_threat),
            "benign": sum(1 for v in result["agent"]["verdicts"] if not v.is_threat),
        },
        "evaluation": None,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def get_last_run() -> Dict[str, Any]:
    return _last_run


def ensure_seeded_data() -> None:
    """Make sure a dataset exists so the dashboard has something to show."""
    if os.path.exists(os.path.join(DATA_DIR, "logs.csv")):
        return
    generate_logs(
        seed=7, minutes=90, base_rate_per_min=18,
        background_ips=40, out_dir=DATA_DIR,
    )
