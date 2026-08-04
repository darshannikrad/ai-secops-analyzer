"""Tests for the analyst layer (offline classifier + JSON guardrails)."""
import pytest

from secops.llm_client import LLMClient
from secops.offline_classifier import classify_ip
from secops.threat_models import RuleHit


def test_sqli_wins_over_volume():
    v = classify_ip({"n_requests": 500, "sql_patterns": 2, "xss_patterns": 0,
                     "failed_logins": 0, "distinct_usernames": 0, "unique_ports": 1,
                     "scan_ratio": 0.0, "bytes_out": 1e4}, [])
    assert v.is_threat and v.threat_type == "sql_injection"
    assert v.mitre_technique_id == "T1190"
    assert v.severity >= 8.0 and v.confidence > 0.5


def test_benign_outlier():
    # elevated volume but below every signature threshold -> benign
    v = classify_ip({"n_requests": 80, "sql_patterns": 0, "xss_patterns": 0,
                     "failed_logins": 0, "distinct_usernames": 0, "unique_ports": 1,
                     "scan_ratio": 0.0, "bytes_out": 1e5}, [])
    assert not v.is_threat and v.threat_type == "benign"


def test_credential_stuffing_beats_single_failures():
    v = classify_ip({"n_requests": 300, "failed_logins": 20,
                     "distinct_usernames": 15, "unique_ports": 1,
                     "sql_patterns": 0, "xss_patterns": 0,
                     "scan_ratio": 0.0, "bytes_out": 1e4}, [])
    assert v.threat_type == "credential_stuffing"


def test_exfiltration_by_bytes():
    v = classify_ip({"n_requests": 5, "bytes_out": 300_000_000,
                     "sql_patterns": 0, "xss_patterns": 0, "failed_logins": 0,
                     "distinct_usernames": 0, "unique_ports": 1,
                     "scan_ratio": 0.0}, [])
    assert v.threat_type == "data_exfiltration" and v.severity == 9.0


def test_json_extraction_strips_code_fences():
    text = '```json\n{"is_threat": true, "severity": 8}\n```'
    assert LLMClient._extract_json(text) == {"is_threat": True, "severity": 8}


def test_json_extraction_finds_embedded_object():
    text = 'Sure! Here: {"a": 1, "b": [2, 3]} done.'
    assert LLMClient._extract_json(text) == {"a": 1, "b": [2, 3]}
