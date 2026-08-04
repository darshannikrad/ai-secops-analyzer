"""Tests for the statistical baseline (Z-score engine)."""
import numpy as np
import pandas as pd
import pytest

from secops.stats_engine import _standardize, detect_anomalies


def _mk_df(rows):
    return pd.DataFrame(rows)


def test_standardize_known_zscore():
    """Z = (X - mu) / sigma, hand-checked against the formula."""
    values = [2, 4, 4, 4, 5, 5, 7, 9, 10]
    feats = pd.DataFrame({"n_requests": values})
    z = _standardize(feats, robust=False)
    x = pd.Series(values, dtype=float)
    expected = (10 - x.mean()) / x.std(ddof=0)
    assert abs(z.loc[8, "n_requests"] - expected) < 1e-9


def test_standardize_constant_column_is_zero():
    feats = pd.DataFrame({"req_rate": [5.0, 5.0, 5.0, 5.0]})
    z = _standardize(feats, robust=False)
    assert (z["req_rate"].abs() < 1e-9).all()


def test_standardize_robust_mad():
    rng = np.random.default_rng(0)
    feats = pd.DataFrame({"n_requests": list(rng.normal(10, 1, 50)) + [500]})
    z = _standardize(feats, robust=True)
    assert z.loc[50, "n_requests"] > 10


def test_entropy_direction():
    """Repetitive probing -> low entropy -> anomaly score must be positive."""
    feats = pd.DataFrame({
        "path_entropy": [3.1, 3.0, 2.9, 3.2, 3.05, 2.95, 3.15, 0.2],
        "n_requests": [1, 1, 1, 1, 1, 1, 1, 1],
    })
    z = _standardize(feats, robust=False)
    # low-entropy row must get a positive z (suspicious)
    assert z.loc[7, "path_entropy"] > 2


def test_detect_anomalies_flags_outlier_window():
    base = pd.Timestamp("2024-01-01 00:00:00")
    rows = []
    for i in range(20):  # 20 quiet IPs, 1 req / 5 min
        for m in range(0, 60, 5):
            rows.append({"timestamp": base + pd.Timedelta(minutes=m),
                         "src_ip": f"10.0.0.{i}", "method": "GET", "path": "/",
                         "status": 200, "bytes": 1000, "latency_ms": 10.0,
                         "user_agent": "ua", "dst_port": 443})
    # one flooding IP: 2 req / min
    for m in range(60):
        for _ in range(2):
            rows.append({"timestamp": base + pd.Timedelta(minutes=m),
                         "src_ip": "10.0.0.99", "method": "GET", "path": "/",
                         "status": 200, "bytes": 1000, "latency_ms": 10.0,
                         "user_agent": "ua", "dst_port": 443})
    df = _mk_df(rows)
    anomalies, feats = detect_anomalies(df, window_minutes=60, z_threshold=3.0,
                                        min_baseline_samples=5)
    flagged_ips = {a.ip for a in anomalies}
    assert "10.0.0.99" in flagged_ips
    assert feats["anomaly_score"].max() > 3.0
