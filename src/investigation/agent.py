"""Autonomous SecOps Investigation Agent for root-cause triage and hypothesis analysis."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from ..utils.config import get_settings
from ..utils.helpers import generate_id
from ..utils.models import (
    Detection,
    Incident,
    Investigation,
    InvestigationStep,
    Severity,
)
from ..utils.security import is_prompt_injection, sanitize_log_input
from .providers import LLMProvider, OfflineProvider, get_provider
from .tools import TOOL_REGISTRY

logger = logging.getLogger(__name__)

# System prompt defining agent persona and tool capabilities for LLM-driven mode
SYSTEM_INVESTIGATION_PROMPT = """You are an elite Autonomous SecOps Incident Responder.
Your role is to systematically investigate security incidents, evaluate telemetry evidence,
form competing hypotheses (malicious vs. benign), assess threat severity, and formulate mitigation plans.

You have access to the following allowlisted security tools:
1. get_incident_details: args {"incident_id": "<id>"} -> Inspect core incident attributes and detections.
2. get_related_events: args {"incident_id": "<id>", "source_event_ids": [...], "limit": 50} -> Fetch raw log events.
3. get_source_activity_summary: args {"source_ip": "<ip>"} -> Aggregate activity profile for a source address.
4. get_detection_evidence: args {"detection_id": "<id>"} -> Detailed telemetry metrics and rule trigger context.
5. get_baseline_comparison: args {"metric": "<metric>", "value": <num>, "detection_id": "<id>"} -> Anomaly deviation analysis.
6. search_similar_incidents: args {"incident_id": "<id>", "source_ip": "<ip>", "detection_type": "<type>"} -> Prior incident correlations.
7. generate_recommendations: args {"incident_id": "<id>", "detection_types": [...]} -> Mitigation playbooks.

TOOL CALL INSTRUCTIONS:
To invoke a tool, output a single JSON block formatted strictly as:
```json
{
  "tool_calls": [
    {
      "tool_name": "<name>",
      "tool_args": { ... },
      "reasoning": "<why this tool is needed>"
    }
  ]
}
```
When your investigation is complete, synthesize your conclusions into a final report using markdown headers:
- # Incident Investigation Report
- ## Executive Summary
- ## Malicious Hypothesis
- ## Benign Hypothesis
- ## Supporting & Contradictory Evidence
- ## Recommendations & Mitigations
"""


class InvestigationAgent:
    """Agent orchestrator conducting automated security investigations."""

    def __init__(
        self,
        provider: str = "offline",
        max_tool_calls: Optional[int] = None,
        timeout_seconds: Optional[int] = None,
    ) -> None:
        """Initialize investigation agent.

        Args:
            provider: LLM provider identifier ('offline', 'openai', 'anthropic', etc.).
            max_tool_calls: Maximum allowable tool invocations during an investigation.
            timeout_seconds: Timeout threshold for investigation execution.
        """
        settings = get_settings()
        self.provider_name = (provider or settings.llm_provider.value).strip().lower()
        self.max_tool_calls = (
            max_tool_calls
            if max_tool_calls is not None
            else settings.max_tool_calls_per_investigation
        )
        self.timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else settings.investigation_timeout_seconds
        )
        self.provider: LLMProvider = get_provider(self.provider_name)

    def investigate(self, incident: Incident, context: Optional[Dict[str, Any]] = None) -> Investigation:
        """Run an end-to-end investigation for a given incident.

        Args:
            incident: Target security incident to investigate.
            context: Context containing log records, detections, and baseline metrics.

        Returns:
            Fully populated Investigation model with findings and evidence.
        """
        ctx = dict(context or {})
        # Ensure target incident is accessible in context
        ctx["incident"] = incident
        if "incidents" not in ctx:
            ctx["incidents"] = [incident]
        elif isinstance(ctx["incidents"], list) and incident not in ctx["incidents"]:
            ctx["incidents"].append(incident)

        if isinstance(self.provider, OfflineProvider) or self.provider_name == "offline":
            return self._run_offline_investigation(incident, ctx)
        else:
            return self._run_llm_investigation(incident, ctx, self.provider)

    def _execute_tool(
        self,
        tool_name: str,
        args: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute a tool with safety controls and parameter sanitization.

        Args:
            tool_name: Name of tool from allowlist.
            args: Tool arguments dictionary.
            context: Investigation context.

        Returns:
            Structured dictionary tool output.
        """
        if not self._validate_tool_call(tool_name, args):
            return {
                "status": "error",
                "message": f"Tool call validation failed for '{tool_name}'",
                "data_source": "agent_validator",
            }

        tool_func = TOOL_REGISTRY.get(tool_name)
        if not tool_func:
            return {
                "status": "error",
                "message": f"Tool '{tool_name}' is not registered in TOOL_REGISTRY.",
                "data_source": "agent_validator",
            }

        try:
            return tool_func(args, context)
        except Exception as exc:
            logger.error(f"Error executing tool '{tool_name}': {exc}", exc_info=True)
            return {
                "status": "error",
                "message": f"Unhandled exception executing '{tool_name}': {str(exc)}",
                "data_source": "tool_executor",
            }

    def _validate_tool_call(self, tool_name: str, args: Dict[str, Any]) -> bool:
        """Validate tool name against allowlist and test arguments for security risks.

        Args:
            tool_name: Proposed tool name.
            args: Arguments dictionary.

        Returns:
            True if call is permitted, False otherwise.
        """
        # Strict allowlist check
        if tool_name not in TOOL_REGISTRY:
            logger.warning(f"Rejected tool call: '{tool_name}' not in TOOL_REGISTRY")
            return False

        if not isinstance(args, dict):
            return False

        # Prompt injection scan on string parameters
        for k, v in args.items():
            if isinstance(v, str):
                if is_prompt_injection(v):
                    logger.warning(
                        f"Prompt injection pattern detected in argument '{k}' for tool '{tool_name}'"
                    )
                    return False
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str) and is_prompt_injection(item):
                        logger.warning(
                            f"Prompt injection pattern detected in array argument '{k}' for tool '{tool_name}'"
                        )
                        return False

        return True

    def _run_offline_investigation(
        self, incident: Incident, context: Dict[str, Any]
    ) -> Investigation:
        """Execute deterministic, offline investigative workflow."""
        start_time = time.time()
        steps: List[InvestigationStep] = []
        step_idx = 1

        # Step 1: get_incident_details
        step1_res = self._execute_tool(
            "get_incident_details",
            {"incident_id": incident.incident_id},
            context,
        )
        steps.append(
            InvestigationStep(
                step_number=step_idx,
                tool_name="get_incident_details",
                tool_args={"incident_id": incident.incident_id},
                tool_result=step1_res,
                reasoning="Retrieve baseline incident attributes and detection roster.",
                timestamp=datetime.now(timezone.utc),
            )
        )
        step_idx += 1

        # Step 2: get_related_events for each detection
        for d in incident.detections:
            if step_idx > self.max_tool_calls:
                break
            step2_res = self._execute_tool(
                "get_related_events",
                {
                    "detection_id": d.detection_id,
                    "source_event_ids": d.source_event_ids[:20],
                    "limit": 50,
                },
                context,
            )
            steps.append(
                InvestigationStep(
                    step_number=step_idx,
                    tool_name="get_related_events",
                    tool_args={
                        "detection_id": d.detection_id,
                        "limit": 50,
                    },
                    tool_result=step2_res,
                    reasoning=f"Examine raw log events for detection {d.detection_type.value}.",
                    timestamp=datetime.now(timezone.utc),
                )
            )
            step_idx += 1

        # Step 3: get_source_activity_summary for each unique source IP
        unique_src_ips: Set[str] = set()
        for d in incident.detections:
            unique_src_ips.update(d.source_ips or [])

        for src_ip in sorted(list(unique_src_ips)):
            if step_idx > self.max_tool_calls:
                break
            step3_res = self._execute_tool(
                "get_source_activity_summary",
                {"source_ip": src_ip},
                context,
            )
            steps.append(
                InvestigationStep(
                    step_number=step_idx,
                    tool_name="get_source_activity_summary",
                    tool_args={"source_ip": src_ip},
                    tool_result=step3_res,
                    reasoning=f"Profile historical activity and endpoint access for source {src_ip}.",
                    timestamp=datetime.now(timezone.utc),
                )
            )
            step_idx += 1

        # Step 4: get_detection_evidence for each detection
        for d in incident.detections:
            if step_idx > self.max_tool_calls:
                break
            step4_res = self._execute_tool(
                "get_detection_evidence",
                {"detection_id": d.detection_id},
                context,
            )
            steps.append(
                InvestigationStep(
                    step_number=step_idx,
                    tool_name="get_detection_evidence",
                    tool_args={"detection_id": d.detection_id},
                    tool_result=step4_res,
                    reasoning=f"Extract telemetry metrics and thresholds for detection {d.detection_id}.",
                    timestamp=datetime.now(timezone.utc),
                )
            )
            step_idx += 1

        # Step 5: get_baseline_comparison
        for d in incident.detections:
            if step_idx > self.max_tool_calls:
                break
            if d.measured_value is not None or d.baseline_value is not None:
                step5_res = self._execute_tool(
                    "get_baseline_comparison",
                    {
                        "metric": d.detection_type.value,
                        "detection_id": d.detection_id,
                        "value": d.measured_value,
                    },
                    context,
                )
                steps.append(
                    InvestigationStep(
                        step_number=step_idx,
                        tool_name="get_baseline_comparison",
                        tool_args={
                            "metric": d.detection_type.value,
                            "detection_id": d.detection_id,
                        },
                        tool_result=step5_res,
                        reasoning=f"Assess baseline deviation for {d.detection_type.value}.",
                        timestamp=datetime.now(timezone.utc),
                    )
                )
                step_idx += 1
                break  # Evaluate primary baseline

        # Step 6: search_similar_incidents
        if step_idx <= self.max_tool_calls:
            step6_res = self._execute_tool(
                "search_similar_incidents",
                {"incident_id": incident.incident_id},
                context,
            )
            steps.append(
                InvestigationStep(
                    step_number=step_idx,
                    tool_name="search_similar_incidents",
                    tool_args={"incident_id": incident.incident_id},
                    tool_result=step6_res,
                    reasoning="Correlate with previous incidents sharing IOCs or attack vectors.",
                    timestamp=datetime.now(timezone.utc),
                )
            )
            step_idx += 1

        # Step 7: generate_recommendations
        rec_res = self._execute_tool(
            "generate_recommendations",
            {"incident_id": incident.incident_id},
            context,
        )
        if step_idx <= self.max_tool_calls:
            steps.append(
                InvestigationStep(
                    step_number=step_idx,
                    tool_name="generate_recommendations",
                    tool_args={"incident_id": incident.incident_id},
                    tool_result=rec_res,
                    reasoning="Synthesize incident remediation playbook and guidance.",
                    timestamp=datetime.now(timezone.utc),
                )
            )

        duration = time.time() - start_time
        recommendations = rec_res.get("recommendations", [])

        # Synthesize hypotheses and evidence from collected steps
        (
            malicious_hypo,
            benign_hypo,
            supporting_ev,
            contradictory_ev,
            missing_info,
            threat_assessment,
            confidence,
        ) = self._build_deterministic_findings(incident, steps)

        report_text = self._build_report_markdown(
            incident=incident,
            provider_name=self.provider_name,
            malicious_hypothesis=malicious_hypo,
            benign_hypothesis=benign_hypo,
            supporting_evidence=supporting_ev,
            contradictory_evidence=contradictory_ev,
            missing_info=missing_info,
            threat_assessment=threat_assessment,
            recommendations=recommendations,
            confidence=confidence,
            steps=steps,
        )

        return Investigation(
            investigation_id=generate_id(),
            incident_id=incident.incident_id,
            provider_used=self.provider_name,
            steps=steps,
            hypothesis_malicious=malicious_hypo,
            hypothesis_benign=benign_hypo,
            supporting_evidence=supporting_ev,
            contradictory_evidence=contradictory_ev,
            missing_info=missing_info,
            threat_assessment=threat_assessment,
            recommendations=recommendations,
            confidence=confidence,
            report_text=report_text,
            created_at=datetime.now(timezone.utc),
            duration_seconds=round(duration, 3),
            tool_call_count=len(steps),
        )

    def _run_llm_investigation(
        self,
        incident: Incident,
        context: Dict[str, Any],
        provider: LLMProvider,
    ) -> Investigation:
        """Run interactive agentic tool-calling loop driven by an LLM provider."""
        start_time = time.time()
        steps: List[InvestigationStep] = []
        conversation_history: List[str] = []

        incident_summary = {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity.value,
            "priority": incident.priority.value,
            "correlation_explanation": incident.correlation_explanation,
            "detections": [
                {
                    "detection_id": d.detection_id,
                    "type": d.detection_type.value,
                    "severity": d.severity.value,
                    "source_ips": d.source_ips,
                    "dest_ips": d.dest_ips,
                    "confidence": d.confidence,
                }
                for d in incident.detections
            ],
        }

        # Defend against prompt injection in incident summary
        clean_incident_json = sanitize_log_input(json.dumps(incident_summary, indent=2))
        conversation_history.append(
            f"Please investigate the following incident:\n```json\n{clean_incident_json}\n```"
        )

        final_response_text = ""
        tool_call_count = 0

        while tool_call_count < self.max_tool_calls:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed >= self.timeout_seconds:
                logger.warning("Investigation timeout reached during LLM execution.")
                break

            user_prompt = "\n\n".join(conversation_history)
            try:
                response = provider.generate(
                    system_prompt=SYSTEM_INVESTIGATION_PROMPT,
                    user_prompt=user_prompt,
                    max_tokens=1500,
                )
            except Exception as exc:
                logger.error(f"Provider generate call raised exception: {exc}")
                break

            # Defend against prompt injection in model reflection
            sanitized_response = sanitize_log_input(response)
            parsed_calls = provider.parse_tool_calls(sanitized_response)

            if not parsed_calls:
                # LLM finished or produced final narrative
                final_response_text = sanitized_response
                break

            executed_any = False
            for call in parsed_calls:
                if tool_call_count >= self.max_tool_calls:
                    break

                t_name = call.get("tool_name", "")
                t_args = call.get("tool_args", {})
                reasoning = call.get("reasoning", "Agent requested tool invocation.")

                if not self._validate_tool_call(t_name, t_args):
                    continue

                tool_res = self._execute_tool(t_name, t_args, context)
                tool_call_count += 1
                executed_any = True

                step = InvestigationStep(
                    step_number=tool_call_count,
                    tool_name=t_name,
                    tool_args=t_args,
                    tool_result=tool_res,
                    reasoning=reasoning,
                    timestamp=datetime.now(timezone.utc),
                )
                steps.append(step)

                # Feed result back to prompt history
                clean_result_str = sanitize_log_input(json.dumps(tool_res))[:1000]
                conversation_history.append(
                    f"Tool Result for `{t_name}`: {clean_result_str}"
                )

            if not executed_any:
                final_response_text = sanitized_response
                break

        # Fallback to offline heuristic findings if LLM did not complete fully
        (
            malicious_hypo,
            benign_hypo,
            supporting_ev,
            contradictory_ev,
            missing_info,
            threat_assessment,
            confidence,
        ) = self._build_deterministic_findings(incident, steps)

        # Retrieve rule-based recommendations as safety baseline
        rec_res = self._execute_tool(
            "generate_recommendations",
            {"incident_id": incident.incident_id},
            context,
        )
        recommendations = rec_res.get("recommendations", [])

        if not final_response_text or final_response_text.startswith("["):
            report_text = self._build_report_markdown(
                incident=incident,
                provider_name=self.provider_name,
                malicious_hypothesis=malicious_hypo,
                benign_hypothesis=benign_hypo,
                supporting_evidence=supporting_ev,
                contradictory_evidence=contradictory_ev,
                missing_info=missing_info,
                threat_assessment=threat_assessment,
                recommendations=recommendations,
                confidence=confidence,
                steps=steps,
            )
        else:
            report_text = final_response_text

        duration = time.time() - start_time
        return Investigation(
            investigation_id=generate_id(),
            incident_id=incident.incident_id,
            provider_used=self.provider_name,
            steps=steps,
            hypothesis_malicious=malicious_hypo,
            hypothesis_benign=benign_hypo,
            supporting_evidence=supporting_ev,
            contradictory_evidence=contradictory_ev,
            missing_info=missing_info,
            threat_assessment=threat_assessment,
            recommendations=recommendations,
            confidence=confidence,
            report_text=report_text,
            created_at=datetime.now(timezone.utc),
            duration_seconds=round(duration, 3),
            tool_call_count=len(steps),
        )

    def _build_deterministic_findings(
        self, incident: Incident, steps: List[InvestigationStep]
    ) -> tuple[str, str, List[str], List[str], List[str], str, float]:
        """Synthesize competing hypotheses, evidence lists, and risk metrics."""
        types = [d.detection_type.value for d in incident.detections]
        types_str = ", ".join(sorted(list(set(types))))
        src_ips = sorted(list({ip for d in incident.detections for ip in (d.source_ips or [])}))
        src_str = ", ".join(src_ips) if src_ips else "Unknown external source"
        dst_ips = sorted(list({ip for d in incident.detections for ip in (d.dest_ips or [])}))
        dst_str = ", ".join(dst_ips) if dst_ips else "Target assets"

        # Formulate Malicious Hypothesis
        malicious = (
            f"Adversary originating from {src_str} executed targeted attack campaign "
            f"utilizing [{types_str}] against {dst_str} to achieve unauthorized access or disrupt operations."
        )

        # Formulate Benign Hypothesis
        benign = (
            f"Anomalous telemetry from {src_str} could be attributed to administrative maintenance, "
            f"authorized automated vulnerability scanning, or misconfigured client integration."
        )

        # Extract supporting evidence
        supporting: List[str] = [
            f"Observed {len(incident.detections)} correlated security detections within incident window.",
            f"Correlation explanation confirms linked attack vectors: {incident.correlation_explanation}",
        ]
        for d in incident.detections:
            if d.measured_value is not None and d.threshold_value is not None:
                supporting.append(
                    f"{d.detection_type.value}: Measured value {d.measured_value} exceeded threshold {d.threshold_value}."
                )

        # Check source activity step for extra facts
        for s in steps:
            if s.tool_name == "get_source_activity_summary" and isinstance(s.tool_result, dict):
                tot = s.tool_result.get("total_requests", 0)
                dests = s.tool_result.get("unique_destinations_count", 0)
                if tot > 0:
                    supporting.append(
                        f"Source IP generated {tot} requests targeting {dests} destination(s)."
                    )

        # Contradictory evidence
        contradictory: List[str] = []
        is_private_src = any(
            ip.startswith(("10.", "192.168.", "172.16.", "127.")) for ip in src_ips
        )
        if is_private_src:
            contradictory.append(
                "Source IP is located in a private internal address space, consistent with internal tooling."
            )
        if incident.severity in (Severity.LOW, Severity.INFO):
            contradictory.append(
                "Overall incident severity is classified as Low/Info, indicating limited operational impact."
            )
        if not contradictory:
            contradictory.append(
                "No contradictory indicators found; traffic behaviors conform strictly to malicious patterns."
            )

        # Missing information
        missing: List[str] = [
            "Host-level endpoint telemetry (EDR process trees and parent-child execution logs).",
            "Internal network packet capture (PCAP) for detailed payload decoding.",
            "Identity provider access audit logs confirming whether authenticated session succeeded.",
        ]

        # Threat Assessment
        threat_assessment = (
            f"Incident '{incident.title}' represents a {incident.severity.value} threat priority "
            f"({incident.priority.value}). Immediate containment and source IP perimeter blocks are advised."
        )

        # Confidence calculation
        base_confidence = (
            sum(d.confidence for d in incident.detections) / len(incident.detections)
            if incident.detections
            else 0.6
        )
        if len(incident.detections) >= 3:
            base_confidence = min(0.98, base_confidence + 0.1)
        confidence = round(base_confidence, 2)

        return (
            malicious,
            benign,
            supporting,
            contradictory,
            missing,
            threat_assessment,
            confidence,
        )

    def _build_report_markdown(
        self,
        incident: Incident,
        provider_name: str,
        malicious_hypothesis: str,
        benign_hypothesis: str,
        supporting_evidence: List[str],
        contradictory_evidence: List[str],
        missing_info: List[str],
        threat_assessment: str,
        recommendations: List[str],
        confidence: float,
        steps: List[InvestigationStep],
    ) -> str:
        """Render a formatted markdown investigation report."""
        supp_lines = "\n".join([f"- {item}" for item in supporting_evidence])
        contra_lines = "\n".join([f"- {item}" for item in contradictory_evidence])
        missing_lines = "\n".join([f"- {item}" for item in missing_info])
        rec_lines = "\n".join([f"{i+1}. {r}" for i, r in enumerate(recommendations)])
        steps_summary = "\n".join(
            [
                f"- **Step {s.step_number}** (`{s.tool_name}`): {s.reasoning}"
                for s in steps
            ]
        )

        return f"""# Autonomous SecOps Investigation Report

**Incident ID:** `{incident.incident_id}`  
**Title:** {incident.title}  
**Severity:** {incident.severity.value} | **Priority:** {incident.priority.value} | **Status:** {incident.status.value}  
**Investigation Engine:** `{provider_name}` | **Confidence:** {int(confidence * 100)}%  
**Investigation Timestamp:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}  

---

## 1. Executive Summary
{threat_assessment}

**Correlation Rationale:**  
{incident.correlation_explanation}

---

## 2. Hypothesis Analysis

### Malicious Hypothesis (Primary)
{malicious_hypothesis}

### Benign Hypothesis (Alternative)
{benign_hypothesis}

---

## 3. Evidence Matrix

### Supporting Evidence
{supp_lines}

### Contradictory Evidence
{contra_lines}

### Information Gaps & Missing Telemetry
{missing_lines}

---

## 4. Investigative Tool Trail ({len(steps)} actions executed)
{steps_summary}

---

## 5. Security Recommendations & Mitigation Playbook
{rec_lines}
"""
