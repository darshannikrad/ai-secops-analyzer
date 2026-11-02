"""Investigation tool implementations and tool registry for SecOps agent."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Union

from ..utils.models import (
    Detection,
    DetectionType,
    Incident,
    IncidentPriority,
    IncidentStatus,
    LogRecord,
    Severity,
)
from ..utils.security import is_prompt_injection, sanitize_log_input, validate_ip

logger = logging.getLogger(__name__)

# Maximum event records returned by any query tool
MAX_EVENT_RESULTS = 50


def _extract_record_dict(rec: Union[LogRecord, Dict[str, Any]]) -> Dict[str, Any]:
    """Convert a LogRecord or dictionary into a normalized dictionary."""
    if isinstance(rec, LogRecord):
        return rec.model_dump(mode="json")
    if isinstance(rec, dict):
        return dict(rec)
    return {}


def _get_incident_from_context(
    incident_id: Optional[str], context: Dict[str, Any]
) -> Optional[Incident]:
    """Locate an incident in the investigation context."""
    if not incident_id:
        active = context.get("incident")
        if isinstance(active, Incident):
            return active
        return None

    active = context.get("incident")
    if isinstance(active, Incident) and active.incident_id == incident_id:
        return active

    incidents = context.get("incidents", [])
    if isinstance(incidents, dict):
        inc = incidents.get(incident_id)
        if isinstance(inc, Incident):
            return inc
    elif isinstance(incidents, list):
        for inc in incidents:
            if isinstance(inc, Incident) and inc.incident_id == incident_id:
                return inc

    return None


def _get_detections_from_context(context: Dict[str, Any]) -> List[Detection]:
    """Extract all available detections from the context."""
    all_detections: List[Detection] = []
    
    # Check context.incident
    active = context.get("incident")
    if isinstance(active, Incident):
        all_detections.extend(active.detections)

    # Check context.detections
    dets = context.get("detections", [])
    if isinstance(dets, list):
        for d in dets:
            if isinstance(d, Detection) and d not in all_detections:
                all_detections.append(d)
    elif isinstance(dets, dict):
        for d in dets.values():
            if isinstance(d, Detection) and d not in all_detections:
                all_detections.append(d)

    # Check context.incidents
    incs = context.get("incidents", [])
    if isinstance(incs, list):
        for inc in incs:
            if isinstance(inc, Incident):
                for d in inc.detections:
                    if d not in all_detections:
                        all_detections.append(d)

    return all_detections


def _get_records_from_context(context: Dict[str, Any]) -> List[Union[LogRecord, Dict[str, Any]]]:
    """Extract log records from the context."""
    records = context.get("records") or context.get("logs") or context.get("log_records") or []
    if isinstance(records, list):
        return records
    return []


# --- Tool Implementations ---


def get_incident_details(args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Retrieve structured information for a specified incident.

    Args:
        args: Dictionary containing 'incident_id' (string).
        context: Investigation context containing incidents.

    Returns:
        Structured dictionary with incident details and metadata.
    """
    raw_id = str(args.get("incident_id", "")).strip()
    incident_id = sanitize_log_input(raw_id)

    if not incident_id:
        active = context.get("incident")
        if isinstance(active, Incident):
            incident_id = active.incident_id
        else:
            return {
                "status": "error",
                "message": "Missing required 'incident_id' argument.",
                "data_source": "context:incidents",
            }

    if is_prompt_injection(incident_id):
        return {
            "status": "error",
            "message": "Security policy violation: detected prompt injection in incident_id.",
            "data_source": "security_filter",
        }

    incident = _get_incident_from_context(incident_id, context)
    if not incident:
        return {
            "status": "not_found",
            "message": f"Incident with ID '{incident_id}' was not found in context.",
            "data_source": "context:incidents",
        }

    detections_summary = [
        {
            "detection_id": d.detection_id,
            "detection_type": d.detection_type.value,
            "severity": d.severity.value,
            "confidence": d.confidence,
            "description": d.description,
            "source_ips": d.source_ips,
            "dest_ips": d.dest_ips,
            "source_event_count": len(d.source_event_ids),
            "timestamp_start": d.timestamp_start.isoformat(),
            "timestamp_end": d.timestamp_end.isoformat(),
        }
        for d in incident.detections
    ]

    return {
        "status": "success",
        "data_source": "context:incidents",
        "incident": {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity.value,
            "priority": incident.priority.value,
            "status": incident.status.value,
            "correlation_explanation": incident.correlation_explanation,
            "created_at": incident.created_at.isoformat(),
            "updated_at": incident.updated_at.isoformat(),
            "detection_count": len(incident.detections),
            "detections": detections_summary,
            "evidence_summary": incident.evidence_summary,
            "related_incident_ids": incident.related_incident_ids,
        },
    }


def get_related_events(args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Retrieve raw or parsed log records associated with an incident or detection.

    Args:
        args: Dictionary containing optional 'incident_id', 'detection_id',
              'source_event_ids', and 'limit'.
        context: Investigation context containing log records.

    Returns:
        Structured list of matching log events up to MAX_EVENT_RESULTS.
    """
    incident_id = sanitize_log_input(str(args.get("incident_id", "")).strip())
    detection_id = sanitize_log_input(str(args.get("detection_id", "")).strip())
    raw_event_ids = args.get("source_event_ids") or []
    limit = min(MAX_EVENT_RESULTS, max(1, int(args.get("limit", MAX_EVENT_RESULTS))))

    target_event_ids: Set[str] = set()

    if isinstance(raw_event_ids, list):
        for eid in raw_event_ids:
            clean_eid = sanitize_log_input(str(eid).strip())
            if clean_eid and not is_prompt_injection(clean_eid):
                target_event_ids.add(clean_eid)

    # If detection_id provided, find its event IDs
    if detection_id:
        detections = _get_detections_from_context(context)
        for d in detections:
            if d.detection_id == detection_id:
                target_event_ids.update(d.source_event_ids)

    # If incident_id provided, find all event IDs in incident
    if incident_id or (not target_event_ids and not detection_id):
        incident = _get_incident_from_context(incident_id or None, context)
        if incident:
            for d in incident.detections:
                target_event_ids.update(d.source_event_ids)

    records = _get_records_from_context(context)
    matching_events: List[Dict[str, Any]] = []

    for r in records:
        r_dict = _extract_record_dict(r)
        rid = str(r_dict.get("record_id", ""))
        if target_event_ids:
            if rid in target_event_ids:
                matching_events.append(r_dict)
                if len(matching_events) >= limit:
                    break
        else:
            # If no target event IDs specified, return initial records for context
            matching_events.append(r_dict)
            if len(matching_events) >= limit:
                break

    return {
        "status": "success",
        "data_source": "context:records",
        "matched_count": len(matching_events),
        "total_requested_event_ids": len(target_event_ids),
        "limit": limit,
        "events": matching_events,
    }


def get_source_activity_summary(args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Summarize all observed log activity for a specific source IP address.

    Args:
        args: Dictionary containing 'source_ip'.
        context: Investigation context containing log records.

    Returns:
        Summary metrics including request counts, destination IPs, protocols, and status codes.
    """
    raw_ip = str(args.get("source_ip", "")).strip()
    source_ip = sanitize_log_input(raw_ip)

    if not source_ip:
        return {
            "status": "error",
            "message": "Missing required 'source_ip' argument.",
            "data_source": "context:records",
        }

    if is_prompt_injection(source_ip):
        return {
            "status": "error",
            "message": "Security policy violation: prompt injection in source_ip.",
            "data_source": "security_filter",
        }

    records = _get_records_from_context(context)
    source_records: List[Dict[str, Any]] = []

    for r in records:
        r_dict = _extract_record_dict(r)
        if str(r_dict.get("source_ip", "")).strip() == source_ip:
            source_records.append(r_dict)

    if not source_records:
        return {
            "status": "not_found",
            "source_ip": source_ip,
            "message": f"No activity records found for source IP {source_ip}.",
            "data_source": "context:records",
        }

    # Aggregate statistics
    unique_dests: Set[str] = set()
    protocols: Dict[str, int] = {}
    methods: Dict[str, int] = {}
    status_codes: Dict[str, int] = {}
    urls: List[str] = []
    total_bytes_sent = 0
    total_bytes_received = 0
    timestamps: List[datetime] = []

    for rec in source_records:
        dst = rec.get("dest_ip")
        if dst:
            unique_dests.add(str(dst))

        proto = str(rec.get("protocol") or "UNKNOWN").upper()
        protocols[proto] = protocols.get(proto, 0) + 1

        meth = str(rec.get("method") or "UNKNOWN").upper()
        methods[meth] = methods.get(meth, 0) + 1

        status = str(rec.get("status_code") or "None")
        status_codes[status] = status_codes.get(status, 0) + 1

        total_bytes_sent += int(rec.get("bytes_sent") or 0)
        total_bytes_received += int(rec.get("bytes_received") or 0)

        url = rec.get("url")
        if url and url not in urls and len(urls) < 10:
            urls.append(str(url))

        ts = rec.get("timestamp")
        if isinstance(ts, datetime):
            timestamps.append(ts)
        elif isinstance(ts, str):
            try:
                timestamps.append(datetime.fromisoformat(ts))
            except ValueError:
                pass

    first_seen = min(timestamps).isoformat() if timestamps else None
    last_seen = max(timestamps).isoformat() if timestamps else None
    duration_seconds = (
        (max(timestamps) - min(timestamps)).total_seconds() if timestamps else 0.0
    )

    return {
        "status": "success",
        "data_source": "context:records",
        "source_ip": source_ip,
        "total_requests": len(source_records),
        "unique_destinations": sorted(list(unique_dests)),
        "unique_destinations_count": len(unique_dests),
        "protocol_distribution": protocols,
        "method_distribution": methods,
        "status_distribution": status_codes,
        "total_bytes_sent": total_bytes_sent,
        "total_bytes_received": total_bytes_received,
        "sample_urls": urls,
        "time_range": {
            "first_seen": first_seen,
            "last_seen": last_seen,
            "duration_seconds": duration_seconds,
        },
    }


def get_detection_evidence(args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Retrieve in-depth evidence and baseline metrics for a specific detection.

    Args:
        args: Dictionary containing 'detection_id'.
        context: Investigation context containing detections.

    Returns:
        Structured evidence dictionary including metrics and explanation.
    """
    raw_id = str(args.get("detection_id", "")).strip()
    detection_id = sanitize_log_input(raw_id)

    if not detection_id:
        return {
            "status": "error",
            "message": "Missing required 'detection_id' argument.",
            "data_source": "context:detections",
        }

    if is_prompt_injection(detection_id):
        return {
            "status": "error",
            "message": "Security policy violation: prompt injection in detection_id.",
            "data_source": "security_filter",
        }

    detections = _get_detections_from_context(context)
    target_detection: Optional[Detection] = None
    for d in detections:
        if d.detection_id == detection_id:
            target_detection = d
            break

    if not target_detection:
        return {
            "status": "not_found",
            "message": f"Detection with ID '{detection_id}' not found.",
            "data_source": "context:detections",
        }

    return {
        "status": "success",
        "data_source": "context:detections",
        "detection": {
            "detection_id": target_detection.detection_id,
            "detection_type": target_detection.detection_type.value,
            "severity": target_detection.severity.value,
            "confidence": target_detection.confidence,
            "description": target_detection.description,
            "evidence": target_detection.evidence,
            "measured_value": target_detection.measured_value,
            "threshold_value": target_detection.threshold_value,
            "baseline_value": target_detection.baseline_value,
            "explanation": target_detection.explanation,
            "timestamp_start": target_detection.timestamp_start.isoformat(),
            "timestamp_end": target_detection.timestamp_end.isoformat(),
            "source_ips": target_detection.source_ips,
            "dest_ips": target_detection.dest_ips,
            "source_event_count": len(target_detection.source_event_ids),
        },
    }


def get_baseline_comparison(args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Compare observed activity values against established statistical baselines.

    Args:
        args: Dictionary containing 'metric' and optional 'value' or 'detection_id'.
        context: Investigation context containing baselines or detections.

    Returns:
        Structured baseline comparison and anomaly factor analysis.
    """
    metric_raw = str(args.get("metric", "")).strip()
    metric = sanitize_log_input(metric_raw)

    detection_id = sanitize_log_input(str(args.get("detection_id", "")).strip())
    candidate_value = args.get("value")

    measured_val: Optional[float] = None
    baseline_val: Optional[float] = None
    threshold_val: Optional[float] = None

    if candidate_value is not None:
        try:
            measured_val = float(candidate_value)
        except (ValueError, TypeError):
            pass

    if detection_id:
        detections = _get_detections_from_context(context)
        for d in detections:
            if d.detection_id == detection_id:
                if measured_val is None:
                    measured_val = d.measured_value
                threshold_val = d.threshold_value
                baseline_val = d.baseline_value
                if not metric:
                    metric = d.detection_type.value
                break

    # Context baseline lookup
    baselines = context.get("baselines", {})
    if isinstance(baselines, dict) and metric in baselines:
        b_entry = baselines[metric]
        if isinstance(b_entry, (int, float)):
            baseline_val = baseline_val or float(b_entry)
        elif isinstance(b_entry, dict):
            baseline_val = baseline_val or float(b_entry.get("baseline", 0.0))
            threshold_val = threshold_val or float(b_entry.get("threshold", 0.0))

    # Fallback default baseline if not provided
    if baseline_val is None:
        baseline_val = 1.0
    if measured_val is None:
        measured_val = 0.0

    deviation = measured_val - baseline_val
    ratio = measured_val / baseline_val if baseline_val > 0 else 0.0
    percent_increase = (
        ((measured_val - baseline_val) / baseline_val) * 100.0 if baseline_val > 0 else 0.0
    )
    is_anomalous = (
        (measured_val > threshold_val) if threshold_val is not None else (ratio > 3.0)
    )

    return {
        "status": "success",
        "data_source": "context:baselines",
        "metric": metric or "unspecified_metric",
        "measured_value": measured_val,
        "baseline_value": baseline_val,
        "threshold_value": threshold_val,
        "absolute_deviation": round(deviation, 3),
        "ratio_to_baseline": round(ratio, 2),
        "percent_increase": round(percent_increase, 2),
        "is_anomalous": is_anomalous,
    }


def search_similar_incidents(args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Find other incidents with overlapping indicators, attack types, or targets.

    Args:
        args: Dictionary containing optional 'incident_id', 'detection_type', or 'source_ip'.
        context: Investigation context containing all incidents.

    Returns:
        Structured list of similar incidents and commonalities.
    """
    target_id = sanitize_log_input(str(args.get("incident_id", "")).strip())
    target_type = sanitize_log_input(str(args.get("detection_type", "")).strip()).upper()
    target_ip = sanitize_log_input(str(args.get("source_ip", "")).strip())

    incidents_raw = context.get("incidents", [])
    all_incidents: List[Incident] = []
    if isinstance(incidents_raw, list):
        all_incidents = [i for i in incidents_raw if isinstance(i, Incident)]
    elif isinstance(incidents_raw, dict):
        all_incidents = [i for i in incidents_raw.values() if isinstance(i, Incident)]

    # If target_id given, extract its parameters
    if target_id:
        target_inc = _get_incident_from_context(target_id, context)
        if target_inc:
            if not target_type and target_inc.detections:
                target_type = target_inc.detections[0].detection_type.value
            if not target_ip and target_inc.detections:
                first_src = target_inc.detections[0].source_ips
                if first_src:
                    target_ip = first_src[0]

    similar_incidents: List[Dict[str, Any]] = []

    for inc in all_incidents:
        if inc.incident_id == target_id:
            continue

        match_reasons: List[str] = []

        # Check detection type match
        inc_types = {d.detection_type.value for d in inc.detections}
        if target_type and target_type in inc_types:
            match_reasons.append(f"Shared detection type: {target_type}")

        # Check source IP match
        inc_srcs: Set[str] = set()
        for d in inc.detections:
            inc_srcs.update(d.source_ips or [])

        if target_ip and target_ip in inc_srcs:
            match_reasons.append(f"Shared source IP: {target_ip}")

        if match_reasons:
            similar_incidents.append(
                {
                    "incident_id": inc.incident_id,
                    "title": inc.title,
                    "severity": inc.severity.value,
                    "priority": inc.priority.value,
                    "status": inc.status.value,
                    "match_reasons": match_reasons,
                    "detection_count": len(inc.detections),
                    "created_at": inc.created_at.isoformat(),
                }
            )

        if len(similar_incidents) >= 10:
            break

    return {
        "status": "success",
        "data_source": "context:incidents",
        "count": len(similar_incidents),
        "similar_incidents": similar_incidents,
    }


def generate_recommendations(args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Generate rule-based security recommendations based on detection types and severity.

    Args:
        args: Dictionary containing optional 'incident_id' or 'detection_types'.
        context: Investigation context containing incident details.

    Returns:
        Structured list of recommendations, immediate actions, and long-term mitigations.
    """
    incident_id = sanitize_log_input(str(args.get("incident_id", "")).strip())
    raw_types = args.get("detection_types") or []

    types_set: Set[str] = set()
    if isinstance(raw_types, list):
        for t in raw_types:
            clean_t = sanitize_log_input(str(t)).upper()
            if clean_t:
                types_set.add(clean_t)

    severity_str = "MEDIUM"
    incident = _get_incident_from_context(incident_id or None, context)
    if incident:
        severity_str = incident.severity.value
        for d in incident.detections:
            types_set.add(d.detection_type.value)

    immediate_actions: List[str] = []
    remediation_steps: List[str] = []
    detection_guidance: List[str] = []

    # Recommendations per detection vector
    if DetectionType.PORT_SCAN.value in types_set:
        immediate_actions.append(
            "Add identified scanning source IPs to perimeter firewall / WAF drop list."
        )
        remediation_steps.append(
            "Review and minimize exposed public ports; enforce strict network ACLs."
        )
        detection_guidance.append(
            "Enable SYN flood protection and TCP connection rate limiting at edge gateways."
        )

    if DetectionType.BRUTE_FORCE.value in types_set or DetectionType.AUTH_ANOMALY.value in types_set:
        immediate_actions.append(
            "Temporarily lock targeted user accounts and force session revocation."
        )
        immediate_actions.append(
            "Rate-limit authentication endpoints and implement progressive CAPTCHA challenges."
        )
        remediation_steps.append(
            "Mandate Multi-Factor Authentication (MFA) across all authentication routes."
        )
        detection_guidance.append(
            "Implement automated account lockout thresholds after 5 consecutive failed attempts."
        )

    if DetectionType.INJECTION.value in types_set:
        immediate_actions.append(
            "Activate SQLi/CMDi inspection filters on Web Application Firewall (WAF) in blocking mode."
        )
        remediation_steps.append(
            "Conduct source code audit to enforce parameterized queries and ORM prepared statements."
        )
        remediation_steps.append(
            "Sanitize and validate all user inputs against strict allowlists."
        )

    if DetectionType.PATH_TRAVERSAL.value in types_set:
        immediate_actions.append(
            "Block path traversal character sequences (../, %2e%2e/) on reverse proxies."
        )
        remediation_steps.append(
            "Normalize and resolve canonical file paths before filesystem access; run processes in chroot."
        )

    if DetectionType.DATA_EXFIL.value in types_set:
        immediate_actions.append(
            "CRITICAL: Isolate originating internal host from network immediately."
        )
        immediate_actions.append(
            "Revoke compromised API keys, database credentials, and service tokens."
        )
        remediation_steps.append(
            "Inspect egress traffic logs for transferred volume, staging endpoints, and C2 channels."
        )

    if DetectionType.DOS.value in types_set:
        immediate_actions.append(
            "Enable DDoS mitigation profiles (Cloudflare / AWS Shield / upstream rate limiting)."
        )
        remediation_steps.append(
            "Implement application-level connection pooling and caching for expensive endpoints."
        )

    if DetectionType.HTTP_ANOMALY.value in types_set or DetectionType.STATISTICAL_ANOMALY.value in types_set:
        remediation_steps.append(
            "Verify web application server parsing behavior against RFC specifications."
        )
        detection_guidance.append(
            "Recalibrate baseline traffic profile to accommodate legitimate business traffic shifts."
        )

    # Escalated response for CRITICAL / HIGH
    if severity_str in ("CRITICAL", "HIGH"):
        immediate_actions.insert(
            0,
            "Activate SecOps Incident Response Team and preserve volatile memory/log artifacts.",
        )

    # Default fallback recommendations if none generated
    if not immediate_actions:
        immediate_actions.append(
            "Inspect related network telemetry and monitor source IP for subsequent anomalous activity."
        )
    if not remediation_steps:
        remediation_steps.append(
            "Perform vulnerability assessment on exposed services identified in the incident."
        )

    all_recommendations = list(
        dict.fromkeys(immediate_actions + remediation_steps + detection_guidance)
    )

    return {
        "status": "success",
        "data_source": "rule_based_security_engine",
        "severity": severity_str,
        "recommendations": all_recommendations,
        "immediate_actions": immediate_actions,
        "remediation_steps": remediation_steps,
        "detection_guidance": detection_guidance,
    }


# Tool Registry mapping tool names to callable implementations
TOOL_REGISTRY: Dict[str, Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]]] = {
    "get_incident_details": get_incident_details,
    "get_related_events": get_related_events,
    "get_source_activity_summary": get_source_activity_summary,
    "get_detection_evidence": get_detection_evidence,
    "get_baseline_comparison": get_baseline_comparison,
    "search_similar_incidents": search_similar_incidents,
    "generate_recommendations": generate_recommendations,
}
