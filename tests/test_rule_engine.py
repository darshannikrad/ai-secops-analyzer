"""Tests for the rule-based baseline."""
import pandas as pd
import pytest

from secops.rule_engine import SIGNATURES, apply_rules, dedupe_by_ip, scan_ratio_flag
from secops.config import DEFAULTS


def _feature_frame():
    return pd.DataFrame([
        {"src_ip": "1.2.3.4", "window": "2024-01-01T00:00:00",
         "failed_logins": 40, "distinct_usernames": 1, "unique_ports": 2,
         "n_requests": 60, "bytes_out": 1e5, "sql_patterns": 0, "xss_patterns": 0,
         "scan_ratio": 0.0},
        {"src_ip": "5.6.7.8", "window": "2024-01-01T00:05:00",
         "failed_logins": 0, "distinct_usernames": 12, "unique_ports": 1,
         "n_requests": 20, "bytes_out": 1e5, "sql_patterns": 0, "xss_patterns": 0,
         "scan_ratio": 0.0},
        {"src_ip": "9.9.9.9", "window": "2024-01-01T00:10:00",
         "failed_logins": 0, "distinct_usernames": 0, "unique_ports": 200,
         "n_requests": 500, "bytes_out": 9e7, "sql_patterns": 3, "xss_patterns": 1,
         "scan_ratio": 0.9},
    ])


def test_brute_force_rule_fires():
    hits = apply_rules(_feature_frame(), DEFAULTS["rules"])
    assert any(h.ip == "1.2.3.4" and h.technique_id == "T1110.001" for h in hits)


def test_credential_stuffing_rule_fires():
    hits = apply_rules(_feature_frame(), DEFAULTS["rules"])
    assert any(h.ip == "5.6.7.8" and h.technique_id == "T1110.004" for h in hits)


def test_signatures_cover_all_techniques():
    techniques = {s["technique_id"] for s in SIGNATURES}
    assert techniques == {"T1110.001", "T1110.004", "T1046", "T1499",
                          "T1048.003", "T1190", "T1189"}


def test_scan_ratio_complement():
    hits = scan_ratio_flag(_feature_frame())
    assert any(h.ip == "9.9.9.9" for h in hits)


def test_dedupe_by_ip_keeps_highest_severity():
    hits = apply_rules(_feature_frame(), DEFAULTS["rules"])
    best = dedupe_by_ip(hits)
    # exfiltration (9.0) is the highest-severity hit for 9.9.9.9
    assert best["9.9.9.9"].technique_id == "T1048.003"
    assert best["9.9.9.9"].severity == 9.0
