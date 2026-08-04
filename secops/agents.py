"""Phase 3/4 — The agentic layer.

Four cooperating agents implement the "Agentic Framework for Threat Profiling":

    EnrichmentAgent   builds a per-IP *dossier*: features, rule hits, evidence
                      timeline, indicators (an autonomous context gatherer).
    AnalystAgent      reasons over the dossier with an LLM (or deterministic
                      fallback) and returns a structured ThreatVerdict mapped
                      to MITRE ATT&CK.
    ReportAgent       turns verdicts into human-readable incident reports.
    Orchestrator      selects candidate IPs (fusion of statistical outliers and
                      signature hits) and drives the agent loop.

This layered design is the paper's novel contribution: the statistical stage
provides high-recall triage, the agent provides high-precision contextual
reasoning, and the report stage restores analyst readability (anti-alert-fatigue).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pandas as pd

from .llm_client import LLMClient
from .mitre import ATTACK_TITLES, ATTACK_TAXONOMY, lookup_technique
from .offline_classifier import classify_ip
from .threat_models import (
    AnomalyRecord,
    IncidentReport,
    RuleHit,
    ThreatVerdict,
)
from .utils import LOG

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst with 15 years \
of experience in threat hunting and incident response. You are part of an autonomous \
alert-triaging pipeline. You receive a JSON dossier describing a source IP flagged as a \
statistical outlier by the detection stage.

Your task: decide whether the IP represents a genuine cyber threat, classify it, and map \
it to MITRE ATT&CK. Be conservative: legitimate automation (search-engine crawlers, CDNs, \
monitoring agents, API clients) must be judged BENIGN even if statistically unusual. Only \
declare a threat when the evidence pattern is consistent with known attack behaviour.

Reference taxonomy:
- brute_force -> T1110.001 Password Guessing (Credential Access)
- credential_stuffing -> T1110.004 Credential Stuffing (Credential Access)
- port_scan -> T1046 Network Service Discovery (Discovery)
- ddos -> T1499 Endpoint Denial of Service (Impact)
- data_exfiltration -> T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol (Exfiltration)
- sql_injection -> T1190 Exploit Public-Facing Application (Initial Access)
- xss -> T1189 Drive-by Compromise (Initial Access)

Reply with ONLY a valid JSON object using EXACTLY these keys:
{
  "is_threat": <bool>,
  "threat_type": <one of the taxonomy values above or "benign">,
  "mitre_technique_id": <string, e.g. "T1110.001">,
  "mitre_technique_name": <string>,
  "mitre_tactic": <string>,
  "severity": <float 0-10>,
  "confidence": <float 0-1>,
  "rationale": <1-3 sentence reasoning citing concrete evidence from the dossier>,
  "recommended_actions": [<3 short actionable strings>]
}"""


# ---------------------------------------------------------------------------
# Enrichment agent
# ---------------------------------------------------------------------------

class EnrichmentAgent:
    """Gathers everything the analyst needs about one IP."""

    def __init__(self, max_evidence_rows: int = 25):
        self.max_evidence_rows = max_evidence_rows

    def build_dossier(
        self,
        ip: str,
        feature_frame: pd.DataFrame,
        raw_df: pd.DataFrame,
        rule_hits: List[RuleHit],
    ) -> Dict[str, Any]:
        rows = feature_frame[feature_frame["src_ip"] == ip].sort_values("anomaly_score",
                                                                       ascending=False)
        best = rows.iloc[0] if len(rows) else None
        evidence = raw_df[raw_df["src_ip"] == ip].sort_values("timestamp").tail(
            self.max_evidence_rows
        )
        ip_rules = [r.to_dict() for r in rule_hits if r.ip == ip]
        return {
            "ip": ip,
            "best_window": {
                "window_start": str(best["window"]) if best is not None else "",
                "anomaly_score": float(best["anomaly_score"]) if best is not None else 0.0,
                "top_feature": str(best["top_feature"]) if best is not None else "",
                "features": {c: float(best[c]) for c in
                             ["n_requests", "req_rate", "error_rate", "bytes_out",
                              "avg_latency_ms", "unique_paths", "failed_logins",
                              "distinct_usernames", "sql_patterns", "xss_patterns",
                              "path_entropy", "burst_max", "scan_ratio", "unique_ports"]
                             if best is not None} or {},
            },
            "windows_flagged": int(len(rows)),
            "rule_hits": ip_rules,
            "evidence": [
                {
                    "timestamp": str(e["timestamp"]), "method": e["method"],
                    "path": str(e["path"])[:120], "status": int(e["status"]),
                    "bytes": int(e["bytes"]), "latency_ms": float(e["latency_ms"]),
                    "user_agent": str(e["user_agent"])[:60], "dst_port": int(e["dst_port"]),
                }
                for _, e in evidence.iterrows()
            ],
        }


# ---------------------------------------------------------------------------
# Analyst agent
# ---------------------------------------------------------------------------

class AnalystAgent:
    """Reasons over a dossier and returns a ThreatVerdict."""

    SCHEMA_KEYS = ["is_threat", "threat_type", "mitre_technique_id",
                   "mitre_technique_name", "mitre_tactic", "severity",
                   "confidence", "rationale", "recommended_actions"]

    def __init__(self, settings, llm_client: Optional[LLMClient] = None):
        self.settings = settings
        self.llm = llm_client or LLMClient(
            provider=settings.llm_provider, model=settings.llm_model,
            base_url=settings.llm_base_url, temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens, prices=settings.llm_prices,
            json_retries=settings.llm_json_retries,
        )
        self.review_threshold = settings.confidence_review_threshold
        self.stats = {"llm_calls": 0, "fallbacks": 0}

    def analyze(self, dossier: Dict[str, Any]) -> ThreatVerdict:
        features = dossier["best_window"].get("features", {})
        rule_hits = [RuleHit(**r) for r in dossier["rule_hits"]]
        verdict = self._analyze_llm(dossier) if not self.llm.is_offline() else None
        if verdict is None:
            self.stats["fallbacks"] += 1
            verdict = classify_ip(features, rule_hits)
            verdict.source = "offline"
        verdict.ip = dossier["ip"]
        verdict.needs_human_review = verdict.confidence < self.review_threshold
        return verdict

    def _analyze_llm(self, dossier: Dict[str, Any]) -> Optional[ThreatVerdict]:
        try:
            self.stats["llm_calls"] += 1
            user = (
                "Here is the dossier for the flagged source IP. "
                "Triage it now.\n\n" + json.dumps(dossier, indent=2)
            )
            raw = self.llm.chat_json(SYSTEM_PROMPT, user, self.SCHEMA_KEYS)
            return self._map_verdict(raw)
        except Exception as exc:  # noqa: BLE001 - fall back on any LLM failure
            LOG.warning("LLM analysis failed (%s) — using offline fallback", exc)
            return None

    def _map_verdict(self, raw: Dict[str, Any]) -> ThreatVerdict:
        threat_type = str(raw.get("threat_type", "benign")).strip().lower()
        if threat_type not in ATTACK_TAXONOMY:
            threat_type = "benign"
        is_threat = bool(raw.get("is_threat", False))
        severity = max(0.0, min(10.0, float(raw.get("severity", 0.0))))
        confidence = max(0.0, min(1.0, float(raw.get("confidence", 0.0))))
        if not is_threat:
            threat_type = "benign"
        tid, tname, tactic, _ = lookup_technique(threat_type)
        if is_threat:
            tid = str(raw.get("mitre_technique_id") or tid)
            tname = str(raw.get("mitre_technique_name") or tname)
            tactic = str(raw.get("mitre_tactic") or tactic)
        return ThreatVerdict(
            ip="", is_threat=is_threat, threat_type=threat_type,
            mitre_technique_id=tid, mitre_technique_name=tname,
            mitre_tactic=tactic, severity=severity, confidence=confidence,
            rationale=str(raw.get("rationale", "")),
            recommended_actions=[str(a) for a in raw.get("recommended_actions", [])][:4],
            source="llm",
        )


# ---------------------------------------------------------------------------
# Report agent
# ---------------------------------------------------------------------------

class ReportAgent:
    """Formats verdicts into paper-quality, human-readable incident reports."""

    def build_report(self, verdict: ThreatVerdict, dossier: Dict[str, Any],
                     incident_id: str, generated_at: str) -> IncidentReport:
        title = ATTACK_TITLES.get(verdict.threat_type, "Network Security Incident")
        if not verdict.is_threat and verdict.needs_human_review:
            title = "REVIEW REQUIRED: " + title  # low-confidence case -> human queue
        f = dossier["best_window"].get("features", {})
        if not verdict.is_threat and verdict.needs_human_review:
            summary = (
                f"Source IP **{verdict.ip}** is a statistical outlier whose verdict has "
                f"low confidence ({verdict.confidence:.0%}) and requires human review. "
                f"The model currently assesses it as **{verdict.threat_type}**; if confirmed, "
                f"the pattern would map to {verdict.mitre_technique_id}. "
            )
        else:
            summary = (
                f"Source IP **{verdict.ip}** exhibited behaviour classified as "
                f"**{verdict.threat_type}** ({verdict.mitre_technique_id}). "
            )
        summary += (
            f"In the peak observation window it produced {int(f.get('n_requests', 0))} "
            f"requests ({float(f.get('req_rate', 0)):.0f}/min) with "
            f"{int(f.get('failed_logins', 0))} failed logins, "
            f"{int(f.get('distinct_usernames', 0))} distinct usernames, and "
            f"{int(f.get('sql_patterns', 0))} SQLi / {int(f.get('xss_patterns', 0))} XSS "
            f"probes; egress volume {float(f.get('bytes_out', 0)) / 1e6:.0f} MB."
        )
        timeline = [
            {
                "timestamp": e["timestamp"], "method": e["method"],
                "path": e["path"], "status": e["status"],
                "bytes": e["bytes"], "latency_ms": e["latency_ms"],
            }
            for e in dossier["evidence"]
        ]
        uas = sorted({e["user_agent"] for e in dossier["evidence"]})
        ports = sorted({e["dst_port"] for e in dossier["evidence"]})
        top_paths = [e["path"] for e in dossier["evidence"]][:6]
        return IncidentReport(
            incident_id=incident_id,
            title=title,
            summary=summary,
            severity=verdict.severity,
            confidence=verdict.confidence,
            source=verdict.source,
            verdict=verdict,
            evidence=dossier["best_window"],
            timeline=timeline,
            indicators={
                "source_ip": verdict.ip,
                "destination_ports": ports,
                "user_agents": uas,
                "notable_paths": top_paths,
                "windows_flagged": dossier["windows_flagged"],
                "rule_hits": [r["rule_id"] for r in dossier["rule_hits"]],
            },
            generated_at=generated_at,
        )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    """Fuses statistical outliers + signature hits and runs the agent loop."""

    def __init__(self, settings):
        self.settings = settings
        self.enricher = EnrichmentAgent(settings.enrich_max_evidence_rows)
        self.analyst = AnalystAgent(settings)
        self.reporter = ReportAgent()

    def run(
        self,
        raw_df: pd.DataFrame,
        anomalies: List[AnomalyRecord],
        rule_hits: List[RuleHit],
        feature_frame: pd.DataFrame,
    ) -> Dict[str, Any]:
        candidate_ips = {a.ip for a in anomalies}
        if self.settings.include_rule_hits:
            candidate_ips |= {h.ip for h in rule_hits}
        # deterministic order, cap LLM spend
        candidate_ips = sorted(candidate_ips)[: self.settings.max_agent_ips]

        verdicts: List[ThreatVerdict] = []
        dossiers: Dict[str, Dict[str, Any]] = {}
        for ip in candidate_ips:
            dossier = self.enricher.build_dossier(ip, feature_frame, raw_df, rule_hits)
            dossiers[ip] = dossier
            verdicts.append(self.analyst.analyze(dossier))

        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        reports: List[IncidentReport] = []
        for i, verdict in enumerate(verdicts, start=1):
            if verdict.is_threat or verdict.needs_human_review:
                reports.append(self.reporter.build_report(
                    verdict, dossiers[verdict.ip], f"INC-{i:04d}", generated_at
                ))

        return {
            "verdicts": verdicts,
            "reports": reports,
            "dossiers": dossiers,
            "candidate_ips": candidate_ips,
            "llm_cost_usd": round(self.analyst.llm.cost_usd, 6),
            "prompt_tokens": self.analyst.llm.prompt_tokens,
            "completion_tokens": self.analyst.llm.completion_tokens,
            "llm_calls": self.analyst.stats["llm_calls"],
            "offline_fallbacks": self.analyst.stats["fallbacks"],
            "provider": self.analyst.llm.provider,
        }
