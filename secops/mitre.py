"""MITRE ATT&CK knowledge base used by the agentic layer and the report writer.

Every attack scenario in the synthetic dataset maps to a concrete ATT&CK
technique so incident reports are taxonomy-aligned and paper-ready.
"""
from __future__ import annotations

from typing import Dict

# attack scenario key -> (technique_id, technique_name, tactic, severity_ground_truth)
ATTACK_TAXONOMY: Dict[str, tuple] = {
    "brute_force": (
        "T1110.001",
        "Brute Force: Password Guessing",
        "Credential Access",
        8.0,
    ),
    "credential_stuffing": (
        "T1110.004",
        "Brute Force: Credential Stuffing",
        "Credential Access",
        7.5,
    ),
    "port_scan": (
        "T1046",
        "Network Service Discovery",
        "Discovery",
        4.0,
    ),
    "ddos": (
        "T1499",
        "Endpoint Denial of Service",
        "Impact",
        7.0,
    ),
    "data_exfiltration": (
        "T1048.003",
        "Exfiltration Over Unencrypted Non-C2 Protocol",
        "Exfiltration",
        9.0,
    ),
    "sql_injection": (
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        8.5,
    ),
    "xss": (
        "T1189",
        "Drive-by Compromise",
        "Initial Access",
        6.0,
    ),
    "benign": ("-", "Benign Traffic", "None", 0.0),
}

# Human-readable labels for report titles
ATTACK_TITLES: Dict[str, str] = {
    "brute_force": "Suspected Brute-Force Attack on Login Endpoint",
    "credential_stuffing": "Credential Stuffing Campaign Against Authentication API",
    "port_scan": "Network Service Discovery / Port Scanning Activity",
    "ddos": "High-Volume Request Flood (Potential DoS)",
    "data_exfiltration": "Suspected Data Exfiltration via Oversized Egress Responses",
    "sql_injection": "SQL Injection Probing of Public-Facing Endpoints",
    "xss": "Cross-Site Scripting Probe Attempt",
    "benign": "Benign Traffic (No Threat Confirmed)",
}


def lookup_technique(attack_type: str) -> tuple:
    """Return (technique_id, technique_name, tactic, ground_truth_severity)."""
    return ATTACK_TAXONOMY.get(attack_type, ATTACK_TAXONOMY["benign"])


def all_attack_types() -> list:
    return [k for k in ATTACK_TAXONOMY if k != "benign"]
