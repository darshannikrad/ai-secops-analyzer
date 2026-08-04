"""Deterministic offline classifier — the zero-cost fallback analyst.

Design rationale
----------------
The LLM analyst requires network access and API credits, which is not always
possible in a demo or exam setting. This module implements a transparent,
explainable scoring function that mirrors the LLM's *output schema*, so the
entire pipeline runs offline with identical downstream artefacts (verdicts,
reports, evaluation). In the paper this doubles as the "cost-vs-accuracy"
ablation: the LLM's value is measured *relative* to this deterministic expert.
"""
from __future__ import annotations

from typing import Dict, List

from .mitre import lookup_technique
from .threat_models import RuleHit, ThreatVerdict


def _bounded_conf(margin: float, k: float = 1.5, max_conf: float = 0.97) -> float:
    """Sigmoid-ish confidence from an evidence margin above threshold."""
    import math

    return round(max_conf * (1 - math.exp(-k * max(margin, 0.0))), 3)


def classify_ip(features: Dict[str, float], rule_hits: List[RuleHit]) -> ThreatVerdict:
    """Classify a single IP from its feature vector + any rule hits.

    Priority order encodes domain knowledge: explicit exploit signatures
    (SQLi/XSS) outweigh volumetric signals; volumetric signals outweigh noise.
    """
    f = features or {}
    n_req = float(f.get("n_requests", 0))
    burst = float(f.get("burst_max", 0))
    failed = float(f.get("failed_logins", 0))
    users = float(f.get("distinct_usernames", 0))
    sql = float(f.get("sql_patterns", 0))
    xss = float(f.get("xss_patterns", 0))
    ports = float(f.get("unique_ports", 0))
    scan_ratio = float(f.get("scan_ratio", 0))
    bytes_out = float(f.get("bytes_out", 0))

    # --- signature-first reasoning (like a senior analyst reading the rules) ---
    if sql >= 1:
        tid, tname, tactic, _ = lookup_technique("sql_injection")
        return ThreatVerdict(
            ip="", is_threat=True, threat_type="sql_injection",
            mitre_technique_id=tid, mitre_technique_name=tname, mitre_tactic=tactic,
            severity=8.5 + min(1.0, sql * 0.2), confidence=_bounded_conf(sql, 3.0),
            rationale=f"Observed {int(sql)} SQL-injection probe pattern(s) "
                      f"(UNION SELECT / OR 1=1 / SLEEP) against public endpoints; "
                      f"exploit attempts against an application-facing service.",
            recommended_actions=["Block the source IP at the WAF",
                                 "Inspect web-server error logs for successful injection",
                                 "Hardening: parameterised queries / prepared statements"],
            source="offline",
        )
    if xss >= 1:
        tid, tname, tactic, _ = lookup_technique("xss")
        return ThreatVerdict(
            ip="", is_threat=True, threat_type="xss",
            mitre_technique_id=tid, mitre_technique_name=tname, mitre_tactic=tactic,
            severity=6.0 + min(1.0, xss * 0.2), confidence=_bounded_conf(xss, 3.0),
            rationale=f"Observed {int(xss)} reflected XSS probe(s) "
                      f"(<script>/onerror payloads) in request parameters.",
            recommended_actions=["Enable output encoding on all user-controlled fields",
                                 "Add CSP headers",
                                 "Triage any 200 responses to probe paths"],
            source="offline",
        )
    if failed >= 1 and users >= 8:
        tid, tname, tactic, _ = lookup_technique("credential_stuffing")
        return ThreatVerdict(
            ip="", is_threat=True, threat_type="credential_stuffing",
            mitre_technique_id=tid, mitre_technique_name=tname, mitre_tactic=tactic,
            severity=7.5, confidence=_bounded_conf(min(failed, users) / 8, 1.2),
            rationale=f"{int(failed)} failed logins across {int(users)} distinct "
                      f"usernames — a low-and-slow credential stuffing campaign "
                      f"using leaked credential lists.",
            recommended_actions=["Enforce MFA / step-up auth on /api/login",
                                 "Rate-limit per-IP and per-username",
                                 "Notify the identity team to rotate affected accounts"],
            source="offline",
        )
    if failed >= 5:
        tid, tname, tactic, _ = lookup_technique("brute_force")
        return ThreatVerdict(
            ip="", is_threat=True, threat_type="brute_force",
            mitre_technique_id=tid, mitre_technique_name=tname, mitre_tactic=tactic,
            severity=8.0, confidence=_bounded_conf(failed / 5 - 1, 1.5),
            rationale=f"{int(failed)} failed authentication attempts against "
                      f"login endpoints in a single window; password guessing "
                      f"against a single account.",
            recommended_actions=["Lock the account / IP temporarily",
                                 "Enforce account lockout and MFA",
                                 "Add CAPTCHA on repeated failures"],
            source="offline",
        )
    if ports >= 12 or scan_ratio >= 0.5:
        tid, tname, tactic, _ = lookup_technique("port_scan")
        return ThreatVerdict(
            ip="", is_threat=True, threat_type="port_scan",
            mitre_technique_id=tid, mitre_technique_name=tname, mitre_tactic=tactic,
            severity=4.0, confidence=_bounded_conf(max(ports / 12, scan_ratio), 1.2),
            rationale=f"{int(ports)} distinct destination ports "
                      f"(scan_ratio={scan_ratio:.2f}) — active service discovery, "
                      f"often a precursor to exploitation.",
            recommended_actions=["Log and monitor follow-up exploitation attempts",
                                 "Restrict exposed services via firewall rules"],
            source="offline",
        )
    if bytes_out >= 50_000_000:
        tid, tname, tactic, _ = lookup_technique("data_exfiltration")
        return ThreatVerdict(
            ip="", is_threat=True, threat_type="data_exfiltration",
            mitre_technique_id=tid, mitre_technique_name=tname, mitre_tactic=tactic,
            severity=9.0, confidence=_bounded_conf(bytes_out / 50e6 - 1, 1.5),
            rationale=f"Egress of {bytes_out / 1e6:.0f} MB in one window to a "
                      f"single client (backup/dump endpoints) — credential/data "
                      f"theft staging.",
            recommended_actions=["Quarantine the endpoint",
                                 "Revoke and rotate any exposed keys/tokens",
                                 "Conduct forensic review of exfiltrated data scope"],
            source="offline",
        )
    if n_req >= 150 or burst >= 40:
        tid, tname, tactic, _ = lookup_technique("ddos")
        return ThreatVerdict(
            ip="", is_threat=True, threat_type="ddos",
            mitre_technique_id=tid, mitre_technique_name=tname, mitre_tactic=tactic,
            severity=7.0, confidence=_bounded_conf(max(n_req / 150, burst / 40) - 1, 1.2),
            rationale=f"Request flood: {int(n_req)} requests per window with a "
                      f"peak burst of {int(burst)} requests in a single minute "
                      f"(baseline ~{float(f.get('req_rate', 0)):.0f}/min) — "
                      f"volumetric denial-of-service behaviour.",
            recommended_actions=["Enable rate limiting at the edge",
                                 "Trigger DDoS mitigation provider",
                                 "Validate traffic via challenge/CDN"],
            source="offline",
        )
    # --- statistical outlier, but no signature: likely benign or low-grade ---
    return ThreatVerdict(
        ip="", is_threat=False, threat_type="benign",
        mitre_technique_id="-", mitre_technique_name="Benign Traffic",
        mitre_tactic="None", severity=1.0, confidence=0.55,
        rationale="Statistical outlier (e.g. crawler, CDN, monitoring agent) "
                  "with no matching signature or behavioural attack pattern; "
                  "low-risk deviation from baseline.",
        recommended_actions=["Add IP to a watchlist; escalate if pattern persists"],
        source="offline",
    )
