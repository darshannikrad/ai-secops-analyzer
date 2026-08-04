"""Phase 5 — Evaluation: hybrid agentic system vs. traditional rule-based IDS.

Metrics computed per detector (per-source-IP unit of analysis):

    precision, recall, F1, accuracy, false-positive rate
    alert multiplicity (alerts / true incidents)  -> alert-fatigue proxy
    detection latency (time from attack start to first flag)
    processing throughput (events/sec) and LLM cost (USD)

The ground truth comes from the labelled generator, making every number in the
paper reproducible with a fixed seed.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import pandas as pd


def binary_metrics(gt_ips: set, flagged_ips: set) -> Dict[str, float]:
    tp = len(gt_ips & flagged_ips)
    fp = len(flagged_ips - gt_ips)
    fn = len(gt_ips - flagged_ips)
    tn = len(gt_ips | flagged_ips)  # universe is the observed IP population
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = tp / (tp + fn) if (tp + fn) else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positive_rate": round(recall, 4),
        "false_positive_rate": round(fp / (fp + tn) if (fp + tn) else 0.0, 4),
        "alerts_issued": len(flagged_ips),
        "true_incidents": len(gt_ips),
        "alert_multiplicity": round(len(flagged_ips) / len(gt_ips), 2) if gt_ips else 0.0,
    }


def detection_latency(
    ground_truth: List[Dict[str, Any]],
    first_flag_time: Dict[str, str],
) -> Dict[str, float]:
    """Minutes between attack start (ground truth) and first detector flag."""
    deltas: List[float] = []
    for attack in ground_truth:
        ip = attack["attacker_ip"]
        flag_ts = first_flag_time.get(ip)
        if flag_ts:
            start = pd.Timestamp(attack["start_ts"])
            flag = pd.Timestamp(flag_ts)
            # flag_ts is the *end* of the triggering window; never negative
            deltas.append(max(0.0, (flag - start).total_seconds() / 60.0))
    if not deltas:
        return {"mean_min": 0.0, "median_min": 0.0, "detected": 0}
    import statistics

    return {
        "mean_min": round(statistics.mean(deltas), 2),
        "median_min": round(statistics.median(deltas), 2),
        "detected": len(deltas),
    }


def compare_detectors(
    ground_truth: List[Dict[str, Any]],
    detectors: Dict[str, set],
    first_flag_times: Dict[str, Dict[str, str]],
    stage_times: Dict[str, float],
    llm_cost_usd: float = 0.0,
    provider: str = "offline",
) -> pd.DataFrame:
    """Side-by-side per-detector metrics table (the paper's results table)."""
    gt_ips = {a["attacker_ip"] for a in ground_truth}
    rows = []
    for name, flagged in detectors.items():
        m = binary_metrics(gt_ips, flagged)
        lat = detection_latency(ground_truth, first_flag_times.get(name, {}))
        stage_key = "stats_stage_s" if name == "stats_only" else \
                    "rules_stage_s" if name == "rule_based" else "agent_stage_s"
        throughput = stage_times.get("events_per_sec", 0.0)
        cost = llm_cost_usd if name == "agentic_hybrid" else 0.0
        rows.append({
            "detector": name,
            "provider": provider if name == "agentic_hybrid" else "deterministic",
            **m,
            "detection_latency_mean_min": lat["mean_min"],
            "latency_attacks_detected": lat["detected"],
            "pipeline_stage_s": stage_times.get(stage_key, 0.0),
            "throughput_events_per_s": throughput,
            "cost_usd": cost,
        })
    df = pd.DataFrame(rows)
    df = df[["detector", "provider", "tp", "fp", "fn", "precision", "recall", "f1",
             "false_positive_rate", "alerts_issued", "true_incidents",
             "alert_multiplicity", "detection_latency_mean_min",
             "latency_attacks_detected", "pipeline_stage_s", "cost_usd"]]
    return df


def summarize_comparison(df: pd.DataFrame, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """JSON-serialisable summary for ``metrics.json``."""
    out: Dict[str, Any] = {"detectors": df.to_dict(orient="records")}
    if extra:
        out.update(extra)
    return out
