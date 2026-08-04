"""Core data structures shared across the pipeline.

These dataclasses are the contract between the statistical layer, the agentic
layer and the reporting layer. They are JSON-serialisable so every stage of the
pipeline can be audited for the research paper.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AnomalyRecord:
    """A statistically-flagged (IP, window) pair with its feature vector."""

    ip: str
    window_start: str
    features: Dict[str, float]
    z_scores: Dict[str, float]
    anomaly_score: float
    top_feature: str
    source: str = "stats"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RuleHit:
    """A traditional signature-rule firing (the Phase-5 baseline)."""

    ip: str
    window_start: str
    rule_id: str
    rule_name: str
    technique_id: str
    severity: float
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatVerdict:
    """Output of the Agentic AI analyst for a single source IP."""

    ip: str
    is_threat: bool
    threat_type: str
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_tactic: str
    severity: float                  # 0-10
    confidence: float                # 0-1
    rationale: str
    recommended_actions: List[str] = field(default_factory=list)
    source: str = "offline"          # "llm" | "offline" | "rules"
    needs_human_review: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentReport:
    """A human-readable, paper-quality incident report."""

    incident_id: str
    title: str
    summary: str
    severity: float
    confidence: float
    source: str
    verdict: ThreatVerdict
    evidence: Dict[str, Any] = field(default_factory=dict)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    indicators: Dict[str, Any] = field(default_factory=dict)
    generated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_markdown(self) -> str:
        v = self.verdict
        lines = [
            f"# {self.incident_id} — {self.title}",
            "",
            f"**Severity:** {v.severity}/10   **Confidence:** {v.confidence:.0%}   "
            f"**Source:** {v.source}",
            "",
            "## Executive Summary",
            "",
            self.summary,
            "",
            "## Threat Classification",
            "",
            f"- **Type:** {v.threat_type}",
            f"- **MITRE ATT&CK:** {v.mitre_technique_id} — {v.mitre_technique_name} "
            f"({v.mitre_tactic})",
            f"- **Rationale:** {v.rationale}",
            "",
            "## Recommended Actions",
            "",
        ]
        lines += [f"- {action}" for action in v.recommended_actions] or ["- (none)"]
        if self.timeline:
            lines += ["", "## Observed Timeline (evidence)", ""]
            for row in self.timeline:
                lines.append(
                    f"- `{row.get('timestamp', '')}` {row.get('method', '')} "
                    f"{row.get('path', '')} -> {row.get('status', '')} "
                    f"({row.get('bytes', 0)} B, {row.get('latency_ms', 0)} ms)"
                )
        if self.indicators:
            lines += ["", "## Indicators of Compromise", ""]
            for key, value in self.indicators.items():
                lines.append(f"- **{key}:** {value}")
        return "\n".join(lines)


def dump_json(obj: Any, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=str)
