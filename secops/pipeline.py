"""Phase 4 — End-to-end pipeline assembly.

    logs ─► stats engine ─► rule engine ─► orchestrator (agents) ─► reports ─► evaluation
            (Z-scores)      (baseline)        (enrich → reason → report)

Every stage is timed and every artefact is written to ``outputs/`` so the paper
can cite exact, reproducible numbers.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from .agents import Orchestrator
from .config import Settings, load_settings
from .data_generator import generate_logs, summarize
from .evaluation import compare_detectors, summarize_comparison
from .rule_engine import apply_rules, scan_ratio_flag
from .stats_engine import detect_anomalies
from .threat_models import dump_json
from .utils import LOG, ensure_dir, save_json

REQUIRED_EVENT_COLS = ["timestamp", "src_ip", "method", "path", "status",
                       "bytes", "latency_ms", "user_agent", "dst_port"]


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

def load_or_generate(settings: Settings) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
    """Load ``data/logs.csv`` if present, otherwise generate it (Phase 1)."""
    csv_path = os.path.join(settings.dataset_output_dir, "logs.csv")
    gt_path = os.path.join(settings.dataset_output_dir, "ground_truth.json")
    if os.path.exists(csv_path):
        df = pd.read_csv(csv_path, dtype={"src_ip": str})
        ground_truth = []
        if os.path.exists(gt_path):
            import json

            with open(gt_path, "r", encoding="utf-8") as fh:
                ground_truth = json.load(fh)
        LOG.info("Loaded existing dataset: %s (%d events)", csv_path, len(df))
        return df, ground_truth
    LOG.info("No dataset found — generating synthetic labelled logs (seed=%d)...",
             settings.seed)
    df, ground_truth = generate_logs(
        seed=settings.seed, minutes=settings.minutes,
        base_rate_per_min=settings.base_rate_per_min,
        background_ips=settings.background_ips,
        out_dir=settings.dataset_output_dir,
    )
    LOG.info("Dataset summary: %s", summarize(df, ground_truth))
    return df, ground_truth


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def run_pipeline(settings: Settings) -> Dict[str, Any]:
    """Run the full detection + reporting pipeline; return results dict."""
    t_total = time.perf_counter()
    stage_times: Dict[str, float] = {}
    out_dir = settings.output_dir
    ensure_dir(out_dir)

    # ---- Phase 1: data ----
    df, ground_truth = load_or_generate(settings)

    # ---- Phase 2: statistical baseline ----
    t0 = time.perf_counter()
    anomalies, feature_frame = detect_anomalies(
        df, window_minutes=settings.window_minutes,
        z_threshold=settings.z_threshold, robust=settings.robust_stats,
        min_baseline_samples=settings.min_baseline_samples,
    )
    stage_times["stats_stage_s"] = round(time.perf_counter() - t0, 4)
    LOG.info("Stats stage: %d anomalous (IP, window) pairs from %d ip-windows",
             len(anomalies), len(feature_frame))

    # ---- Baseline: signature rules ----
    t0 = time.perf_counter()
    rule_hits = apply_rules(feature_frame, settings.rule_thresholds)
    rule_hits += scan_ratio_flag(feature_frame)
    stage_times["rules_stage_s"] = round(time.perf_counter() - t0, 4)
    LOG.info("Rule stage: %d signature hits", len(rule_hits))

    # ---- Phase 3/4: agentic triage ----
    t0 = time.perf_counter()
    orchestrator = Orchestrator(settings)
    agent_result = orchestrator.run(df, anomalies, rule_hits, feature_frame)
    stage_times["agent_stage_s"] = round(time.perf_counter() - t0, 4)
    stage_times["total_pipeline_s"] = round(time.perf_counter() - t_total, 4)
    stage_times["events_per_sec"] = round(
        len(df) / max(stage_times["total_pipeline_s"], 1e-9), 1
    )
    LOG.info("Agent stage: %d candidates triaged (%d threats, %d benign), provider=%s",
             len(agent_result["candidate_ips"]),
             sum(1 for v in agent_result["verdicts"] if v.is_threat),
             sum(1 for v in agent_result["verdicts"] if not v.is_threat),
             agent_result["provider"])

    # ---- Outputs ----
    _write_outputs(df, feature_frame, rule_hits, agent_result, out_dir)

    # ---- Phase 5: evaluation (only with ground truth) ----
    results: Dict[str, Any] = {
        "n_events": int(len(df)),
        "n_anomalies": len(anomalies),
        "n_rule_hits": len(rule_hits),
        "agent": agent_result,
        "stage_times": stage_times,
        "ground_truth": ground_truth,
    }
    if ground_truth:
        results["evaluation"] = _evaluate(settings, ground_truth, feature_frame,
                                          rule_hits, agent_result, stage_times, out_dir)
    else:
        LOG.warning("No ground truth available — skipping evaluation metrics")
    return results


def _write_outputs(df, feature_frame, rule_hits, agent_result, out_dir: str) -> None:
    ensure_dir(f"{out_dir}/reports")
    # Anomaly feature table (full audit trail)
    save_json(feature_frame.astype(object).to_dict(orient="records"),
              f"{out_dir}/feature_frame.json")
    feature_frame.to_csv(f"{out_dir}/feature_frame.csv", index=False)
    # Rule hits
    save_json([h.to_dict() for h in rule_hits], f"{out_dir}/rule_hits.json")
    # Verdicts
    save_json([v.to_dict() for v in agent_result["verdicts"]],
              f"{out_dir}/verdicts.json")
    # Incident reports (JSON + markdown)
    dump_json([r.to_dict() for r in agent_result["reports"]],
              f"{out_dir}/incident_reports.json")
    for report in agent_result["reports"]:
        with open(f"{out_dir}/reports/{report.incident_id}.md", "w",
                  encoding="utf-8") as fh:
            fh.write(report.to_markdown() + "\n")
    # Agent dossier + cost ledger
    save_json(agent_result["dossiers"], f"{out_dir}/dossiers.json")
    save_json({
        "provider": agent_result["provider"],
        "llm_cost_usd": agent_result["llm_cost_usd"],
        "prompt_tokens": agent_result["prompt_tokens"],
        "completion_tokens": agent_result["completion_tokens"],
        "llm_calls": agent_result["llm_calls"],
        "offline_fallbacks": agent_result["offline_fallbacks"],
    }, f"{out_dir}/cost_ledger.json")
    LOG.info("Wrote outputs to %s/", out_dir)


def _evaluate(settings, ground_truth, feature_frame, rule_hits, agent_result,
              stage_times, out_dir: str) -> Dict[str, Any]:
    """Per-IP detector comparison + latency + persistence."""
    gt_ips = {a["attacker_ip"] for a in ground_truth}

    # first flag time per IP (window END = when detection completes)
    def _window_end(win_start: str) -> str:
        return (pd.Timestamp(win_start) + pd.Timedelta(minutes=settings.window_minutes)
                ).strftime("%Y-%m-%dT%H:%M:%S")

    z_thr = settings.z_threshold
    first_stats = {}
    for ip in feature_frame["src_ip"].unique():
        f = feature_frame[feature_frame["src_ip"] == ip]
        if (f["anomaly_score"] >= z_thr).any():
            first_stats[ip] = _window_end(f.loc[f["anomaly_score"] >= z_thr, "window"].iloc[0])
    first_rules = {}
    for h in rule_hits:
        first_rules.setdefault(h.ip, _window_end(h.window_start))
    first_agent = {}
    for ip in agent_result["candidate_ips"]:
        if ip in first_stats:
            first_agent[ip] = first_stats[ip]

    stats_ips = {a.ip for a in _stat_records(feature_frame, settings.z_threshold)}
    rule_ips = {h.ip for h in rule_hits}
    agent_ips = {v.ip for v in agent_result["verdicts"] if v.is_threat}
    review_ips = {v.ip for v in agent_result["verdicts"] if v.needs_human_review}

    comparison = compare_detectors(
        ground_truth,
        detectors={
            "stats_only": stats_ips,
            "rule_based": rule_ips,
            "agentic_hybrid": agent_ips,
            "agentic_plus_review": agent_ips | review_ips,
        },
        first_flag_times={"stats_only": first_stats, "rule_based": first_rules,
                          "agentic_hybrid": first_agent},
        stage_times=stage_times,
        llm_cost_usd=agent_result["llm_cost_usd"],
        provider=agent_result["provider"],
    )
    extra = {
        "n_events": int(len(feature_frame)),  # ip-windows
        "gt_attacker_ips": sorted(gt_ips),
        "undetected_by_agent": sorted(gt_ips - agent_ips),
        "stage_times_s": stage_times,
        "llm": {"provider": agent_result["provider"],
                "cost_usd": agent_result["llm_cost_usd"],
                "llm_calls": agent_result["llm_calls"]},
    }
    metrics = summarize_comparison(comparison, extra)
    save_json(metrics, f"{out_dir}/metrics.json")
    comparison.to_csv(f"{out_dir}/comparison.csv", index=False)

    LOG.info("=== Evaluation (ground-truth, per source IP) ===")
    cols = ["detector", "provider", "tp", "fp", "fn", "precision", "recall",
            "f1", "false_positive_rate", "alerts_issued", "alert_multiplicity",
            "detection_latency_mean_min"]
    print(comparison[cols].to_string(index=False))
    return metrics


def _stat_records(feature_frame: pd.DataFrame, z_threshold: float = 3.0) -> List[Any]:
    """Re-derive AnomalyRecord objects from the feature frame for evaluation."""
    from .threat_models import AnomalyRecord

    flagged = feature_frame[feature_frame["anomaly_score"] >= z_threshold]
    recs = []
    for _, row in flagged.iterrows():
        recs.append(AnomalyRecord(
            ip=row["src_ip"], window_start=row["window"],
            features={c: float(row[c]) for c in _FEATURES},
            z_scores={}, anomaly_score=float(row["anomaly_score"]),
            top_feature=str(row["top_feature"]),
        ))
    return recs


_FEATURES = ["n_requests", "req_rate", "error_rate", "bytes_out", "avg_latency_ms",
             "unique_paths", "unique_uas", "unique_ports", "failed_logins",
             "distinct_usernames", "sql_patterns", "xss_patterns", "path_entropy",
             "burst_max", "scan_ratio"]


def analyze_logs(settings: Settings, log_path: str) -> Dict[str, Any]:
    """Analyze an arbitrary unlabelled log file (no evaluation)."""
    df = pd.read_csv(log_path, dtype={"src_ip": str})
    for col in REQUIRED_EVENT_COLS:
        if col not in df.columns:
            raise ValueError(f"log file missing required column: {col}")
    LOG.info("Loaded %d events from %s", len(df), log_path)
    out_dir = settings.output_dir
    anomalies, feature_frame = detect_anomalies(
        df, window_minutes=settings.window_minutes,
        z_threshold=settings.z_threshold, robust=settings.robust_stats,
    )
    rule_hits = apply_rules(feature_frame, settings.rule_thresholds)
    rule_hits += scan_ratio_flag(feature_frame)
    orchestrator = Orchestrator(settings)
    agent_result = orchestrator.run(df, anomalies, rule_hits, feature_frame)
    _write_outputs(df, feature_frame, rule_hits, agent_result, out_dir)
    return {
        "n_events": int(len(df)),
        "n_anomalies": len(anomalies),
        "n_rule_hits": len(rule_hits),
        "n_reports": len(agent_result["reports"]),
        "agent": agent_result,
    }


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def run_from_cli(args) -> Dict[str, Any]:
    settings = load_settings(args.config)
    if args.seed is not None:
        settings.data["dataset"]["seed"] = args.seed
    if args.minutes:
        settings.data["dataset"]["minutes"] = args.minutes
    if args.llm:
        settings.data["llm"]["provider"] = args.llm
    return run_pipeline(settings)
