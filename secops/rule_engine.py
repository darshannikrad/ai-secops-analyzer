"""Phase 5 baseline — traditional rule-based (signature) detection.

Classic SOC tooling (Snort/Suricata signatures, SIEM correlation rules) fires
when a hand-tuned numeric threshold is crossed. We re-create that behaviour on
top of the same windowed feature frame so the *only* difference between this
baseline and the hybrid agentic system is the reasoning layer — a clean
controlled comparison for the paper.
"""
from __future__ import annotations

import re
from typing import Dict, List

import pandas as pd

from .threat_models import RuleHit

SIGNATURES = [
    dict(rule_id="R001", rule_name="Excessive Failed Logins",
         technique_id="T1110.001", severity=8.0,
         key="failed_logins", threshold="brute_force_min_failures"),
    dict(rule_id="R002", rule_name="Credential Stuffing (many users)",
         technique_id="T1110.004", severity=7.5,
         key="distinct_usernames", threshold="cred_stuffing_min_users"),
    dict(rule_id="R003", rule_name="Port Scan / Service Discovery",
         technique_id="T1046", severity=4.0,
         key="unique_ports", threshold="port_scan_min_ports"),
    dict(rule_id="R004", rule_name="Request Flood / DoS",
         technique_id="T1499", severity=7.0,
         key="n_requests", threshold="ddos_min_requests"),
    dict(rule_id="R005", rule_name="Oversized Egress (Exfiltration)",
         technique_id="T1048.003", severity=9.0,
         key="bytes_out", threshold="exfil_min_bytes"),
    dict(rule_id="R006", rule_name="SQL Injection Pattern Match",
         technique_id="T1190", severity=8.5,
         key="sql_patterns", threshold="sqli_min_patterns"),
    dict(rule_id="R007", rule_name="XSS Probe Pattern Match",
         technique_id="T1189", severity=6.0,
         key="xss_patterns", threshold="xss_min_patterns"),
]


def apply_rules(feature_frame: pd.DataFrame, rule_thresholds: Dict[str, float]) -> List[RuleHit]:
    """Fire signature rules against the windowed feature frame."""
    hits: List[RuleHit] = []
    for sig in SIGNATURES:
        thr = rule_thresholds[sig["threshold"]]
        mask = feature_frame[sig["key"]].astype(float) >= thr
        for _, row in feature_frame[mask].iterrows():
            hits.append(RuleHit(
                ip=row["src_ip"],
                window_start=row["window"],
                rule_id=sig["rule_id"],
                rule_name=sig["rule_name"],
                technique_id=sig["technique_id"],
                severity=sig["severity"],
                evidence=f"{sig['key']}={float(row[sig['key']]):.2f} "
                         f"(threshold {thr:g})",
            ))
    return hits


def dedupe_by_ip(hits: List[RuleHit]) -> Dict[str, RuleHit]:
    """Keep the highest-severity rule hit per IP (for per-IP evaluation)."""
    best: Dict[str, RuleHit] = {}
    for h in hits:
        cur = best.get(h.ip)
        if cur is None or h.severity > cur.severity:
            best[h.ip] = h
    return best


def scan_ratio_flag(feature_frame: pd.DataFrame, threshold: float = 0.5) -> List[RuleHit]:
    """Complementary signature: majority of connections to non-standard ports."""
    hits: List[RuleHit] = []
    mask = feature_frame["scan_ratio"].astype(float) >= threshold
    for _, row in feature_frame[mask].iterrows():
        hits.append(RuleHit(
            ip=row["src_ip"], window_start=row["window"],
            rule_id="R008", rule_name="Non-standard Port Traffic",
            technique_id="T1046", severity=4.0,
            evidence=f"scan_ratio={float(row['scan_ratio']):.2f}",
        ))
    return hits
