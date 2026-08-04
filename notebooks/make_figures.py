"""Generate publication-quality figures for the research paper.

Usage:
    python notebooks/make_figures.py

Figures are written to ``outputs/figures/``. If ``outputs/metrics.json`` already
exists the script reuses it; otherwise it runs the offline pipeline first.
"""
from __future__ import annotations

import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from secops.config import load_settings  # noqa: E402
from secops.pipeline import run_pipeline  # noqa: E402
from secops.utils import ensure_dir  # noqa: E402

FIG_DIR = os.path.join(ROOT, "outputs", "figures")
PALETTE = ["#4C72B0", "#DD8452", "#55A868"]


def _load_metrics(settings) -> dict:
    metrics_path = os.path.join(settings.output_dir, "metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    results = run_pipeline(settings)
    return results["evaluation"]


def fig1_traffic_timeline(df: pd.DataFrame, out: str) -> None:
    """Requests per minute, split into benign vs attack."""
    ts = pd.to_datetime(df["timestamp"])
    timeline = df.assign(minute=ts.dt.floor("1min"))
    attack = timeline[timeline["is_attack"] == 1].groupby("minute").size()
    benign = timeline[timeline["is_attack"] == 0].groupby("minute").size()
    fig, ax = plt.subplots(figsize=(10, 3.4))
    ax.bar(benign.index, benign.values, width=0.8 / 60 / 24, color=PALETTE[0],
           label="benign traffic", alpha=0.85)
    ax.bar(attack.index, attack.values, width=0.8 / 60 / 24, color=PALETTE[1],
           label="attack traffic", alpha=0.9)
    ax.set_title("Synthetic dataset: traffic timeline (requests / minute)")
    ax.set_xlabel("time"); ax.set_ylabel("requests / min")
    ax.legend(frameon=False)
    fig.tight_layout(); fig.savefig(out, dpi=200); plt.close(fig)


def fig2_anomaly_scores(feats: pd.DataFrame, threshold: float, out: str) -> None:
    """Distribution of statistical anomaly scores with flag threshold."""
    fig, ax = plt.subplots(figsize=(8, 3.6))
    scores = feats["anomaly_score"].clip(upper=20)
    ax.hist(scores, bins=60, color=PALETTE[0], alpha=0.85)
    ax.axvline(threshold, color=PALETTE[1], ls="--", lw=1.6,
               label=f"Z-threshold = {threshold}")
    ax.set_title("Statistical stage: anomaly-score distribution (per IP-window)")
    ax.set_xlabel("max Z-score"); ax.set_ylabel("IP-windows")
    ax.legend(frameon=False)
    fig.tight_layout(); fig.savefig(out, dpi=200); plt.close(fig)


def fig3_alerts_vs_true(df: pd.DataFrame, out: str) -> None:
    """Alert volume by detector vs the number of true incidents."""
    det = [r["detector"] for r in df["detectors"]]
    alerts = [r["alerts_issued"] for r in df["detectors"]]
    true = [r["true_incidents"] for r in df["detectors"]]
    x = np.arange(len(det)); w = 0.36
    fig, ax = plt.subplots(figsize=(8.5, 3.6))
    b1 = ax.bar(x - w / 2, alerts, w, label="alerts issued", color=PALETTE[1])
    b2 = ax.bar(x + w / 2, true, w, label="true incidents (ground truth)",
                color=PALETTE[0])
    ax.bar_label(b1, padding=2); ax.bar_label(b2, padding=2)
    ax.set_xticks(x); ax.set_xticklabels(det)
    ax.set_ylabel("count")
    ax.set_title("Alert volume: false-alert reduction across detectors")
    ax.legend(frameon=False)
    fig.tight_layout(); fig.savefig(out, dpi=200); plt.close(fig)


def fig4_prf(df: pd.DataFrame, out: str) -> None:
    """Grouped bars: precision / recall / F1 per detector."""
    det = [r["detector"] for r in df["detectors"]]
    metrics = {k: [r[k] for r in df["detectors"]] for k in ("precision", "recall", "f1")}
    x = np.arange(len(det)); w = 0.24
    fig, ax = plt.subplots(figsize=(8.5, 3.8))
    for i, (name, vals) in enumerate(metrics.items()):
        bars = ax.bar(x + (i - 1) * w, vals, w, label=name, color=PALETTE[i])
        ax.bar_label(bars, fmt="%.2f", padding=2, fontsize=8)
    ax.axhline(1.0, color="grey", lw=0.8, ls=":")
    ax.set_xticks(x); ax.set_xticklabels(det)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("score")
    ax.set_title("Detection quality: statistical vs rule-based vs agentic hybrid")
    ax.legend(frameon=False, ncols=3)
    fig.tight_layout(); fig.savefig(out, dpi=200); plt.close(fig)


def fig5_latency(df: pd.DataFrame, out: str) -> None:
    """Mean detection latency per detector (minutes)."""
    det = [r["detector"] for r in df["detectors"]]
    lat = [r["detection_latency_mean_min"] for r in df["detectors"]]
    fig, ax = plt.subplots(figsize=(8, 3.4))
    bars = ax.bar(det, lat, color=PALETTE)
    ax.bar_label(bars, fmt="%.1f min", padding=2)
    ax.set_ylabel("mean latency (min)")
    ax.set_title("Detection latency (time from attack start to first flag)")
    fig.tight_layout(); fig.savefig(out, dpi=200); plt.close(fig)


def main() -> None:
    ensure_dir(FIG_DIR)
    settings = load_settings(os.path.join(ROOT, "config.yaml"))
    settings.data["dataset"]["output_dir"] = os.path.join(ROOT, "data")
    settings.data["pipeline"]["output_dir"] = os.path.join(ROOT, "outputs")

    metrics = _load_metrics(settings)
    logs_path = os.path.join(settings.dataset_output_dir, "logs.csv")
    df = pd.read_csv(logs_path)

    fig1_traffic_timeline(df, f"{FIG_DIR}/fig1_traffic_timeline.png")
    feats = pd.read_csv(os.path.join(settings.output_dir, "feature_frame.csv"))
    fig2_anomaly_scores(feats, settings.z_threshold, f"{FIG_DIR}/fig2_anomaly_scores.png")
    fig3_alerts_vs_true(metrics, f"{FIG_DIR}/fig3_alerts_vs_true.png")
    fig4_prf(metrics, f"{FIG_DIR}/fig4_detection_quality.png")
    fig5_latency(metrics, f"{FIG_DIR}/fig5_latency.png")
    print(f"Figures written to {FIG_DIR}/")


if __name__ == "__main__":
    main()
