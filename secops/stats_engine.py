"""Phase 2 — Statistical anomaly baseline (Pandas).

For every (source IP, time-window) pair we compute a behavioural feature vector
(request volume, error rate, failed logins, distinct usernames, egress bytes,
latency, path entropy, port-scan ratio, burstiness, ...). Each feature is then
standardised across the whole observation horizon:

    Z = (X - mu) / sigma          (classic, mean/std)
    Z = 0.6745 * (X - med) / MAD  (robust, median/MAD)

Any window whose maximum Z exceeds the configured threshold (default 3.0) is
flagged as a *statistical outlier* and forwarded to the Agentic AI layer for
contextual triage. The design deliberately exposes several features so the LLM
receives a rich dossier rather than a bare "requests" count.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

from .threat_models import AnomalyRecord

SQLI_RE = re.compile(
    r"(?i)(?:union\s+select|or\s+1=1|drop\s+table|waitfor\s+delay|\bsleep\s*\(|'--|'\s*or\b)"
)
XSS_RE = re.compile(r"(?i)(?:<script|onerror\s*=|onload\s*=|javascript:)")

FEATURE_COLUMNS = [
    "n_requests", "req_rate", "error_rate", "bytes_out", "avg_latency_ms",
    "unique_paths", "unique_uas", "unique_ports", "failed_logins",
    "distinct_usernames", "sql_patterns", "xss_patterns", "path_entropy",
    "burst_max", "scan_ratio",
]

# Features where a LOW value is suspicious (standardised and negated)
LOW_IS_SUSPICIOUS = {"path_entropy"}


def _extract_features(df: pd.DataFrame, window_minutes: int) -> pd.DataFrame:
    """Compute per-(IP, window) behavioural features from raw events."""
    df = df.copy()
    ts = pd.to_datetime(df["timestamp"])
    df["window"] = ts.dt.floor(f"{window_minutes}min")
    df["minute"] = ts.dt.floor("1min")
    df["is_error"] = df["status"] >= 400
    df["is_login"] = df["path"].str.contains(r"/login", regex=True, case=False)
    df["failed_login"] = (df["is_login"] & df["is_error"]).astype(int)

    usernames = df["path"].str.extract(r"[?&](?:user|username)=([^&\s]+)")[0]
    df["username"] = usernames.fillna("")

    norm_path = df["path"].str.split("?").str[0]

    rows: List[Tuple[object, Dict[str, float]]] = []
    grouped = df.groupby(["src_ip", "window"], sort=False)
    for (ip, window), g in grouped:
        path_counts = g.groupby(norm_path.loc[g.index]).size()
        # Entropy H = -sum(p_i log2 p_i); probing is repetitive -> low entropy
        if len(path_counts) > 0:
            probs = path_counts / path_counts.sum()
            entropy = float(-(probs * np.log2(probs)).sum())
        else:
            entropy = 0.0
        minute_counts = g.groupby("minute").size()
        rows.append((
            (ip, window),
            {
                "n_requests": float(len(g)),
                "req_rate": float(len(g) / window_minutes),
                "error_rate": float(g["is_error"].mean()) if len(g) else 0.0,
                "bytes_out": float(g["bytes"].sum()),
                "avg_latency_ms": float(g["latency_ms"].mean()) if len(g) else 0.0,
                "unique_paths": float(g["path"].nunique()),
                "unique_uas": float(g["user_agent"].nunique()),
                "unique_ports": float(g["dst_port"].nunique()),
                "failed_logins": float(g["failed_login"].sum()),
                "distinct_usernames": float(g.loc[g["username"] != "", "username"].nunique()),
                "sql_patterns": float(g["path"].str.contains(SQLI_RE).sum()),
                "xss_patterns": float(g["path"].str.contains(XSS_RE).sum()),
                "path_entropy": entropy,
                "burst_max": float(minute_counts.max()) if len(minute_counts) else 0.0,
                "scan_ratio": float((~g["dst_port"].isin([80, 443])).mean())
                if len(g) else 0.0,
            },
        ))

    feats = pd.DataFrame([r[1] for r in rows])
    feats["src_ip"] = [r[0][0] for r in rows]
    feats["window"] = [r[0][1] for r in rows]
    feats["window"] = pd.to_datetime(feats["window"]).dt.strftime("%Y-%m-%dT%H:%M:%S")
    return feats


def _standardize(feats: pd.DataFrame, robust: bool) -> pd.DataFrame:
    """Standardise each feature column; return z-score frame."""
    z = pd.DataFrame(index=feats.index)
    cols = [c for c in FEATURE_COLUMNS if c in feats.columns]
    for col in cols:
        x = feats[col].astype(float)
        if robust:
            med = x.median()
            mad = (x - med).abs().median()
            zz = 0.6745 * (x - med) / max(mad, 1e-6)
        else:
            mu, sigma = x.mean(), x.std(ddof=0)
            zz = (x - mu) / max(sigma, 1e-6)
        if col in LOW_IS_SUSPICIOUS:
            zz = -zz  # low entropy -> high anomaly score
        z[col] = zz
    return z


def detect_anomalies(
    df: pd.DataFrame,
    window_minutes: int = 5,
    z_threshold: float = 3.0,
    robust: bool = False,
    min_baseline_samples: int = 8,
) -> Tuple[List[AnomalyRecord], pd.DataFrame]:
    """Run the statistical baseline.

    Returns (anomalies, feature_frame). ``feature_frame`` carries one row per
    (IP, window) with raw features and z-scores — the input for rule engine and
    the agentic enrichment layer.
    """
    feats = _extract_features(df, window_minutes)
    zs = _standardize(feats, robust)

    for col in FEATURE_COLUMNS:
        feats[f"z_{col}"] = zs[col]

    z_cols = [f"z_{c}" for c in FEATURE_COLUMNS]
    anomaly_score = zs[FEATURE_COLUMNS].max(axis=1)
    top_feature = zs[FEATURE_COLUMNS].idxmax(axis=1)
    feats["anomaly_score"] = anomaly_score
    feats["top_feature"] = top_feature

    # Only evaluate windows when a stable baseline exists
    stable = feats.groupby("window")["n_requests"].transform("count") >= min_baseline_samples
    flagged = feats[(anomaly_score >= z_threshold) & stable]

    anomalies: List[AnomalyRecord] = []
    for _, row in flagged.iterrows():
        anomalies.append(AnomalyRecord(
            ip=row["src_ip"],
            window_start=row["window"],
            features={c: float(row[c]) for c in FEATURE_COLUMNS},
            z_scores={c: float(row[c]) for c in z_cols},
            anomaly_score=float(row["anomaly_score"]),
            top_feature=str(row["top_feature"]),
        ))
    return anomalies, feats
