"""Correlation engine for aggregating security detections into actionable incidents."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ..utils.helpers import generate_id
from ..utils.models import (
    Detection,
    DetectionType,
    Incident,
    IncidentPriority,
    IncidentStatus,
    Priority,
    Severity,
)

logger = logging.getLogger(__name__)

# Attack chain stages mapping detection types
ATTACK_STAGES: Dict[DetectionType, str] = {
    DetectionType.PORT_SCAN: "RECONNAISSANCE",
    DetectionType.HTTP_ANOMALY: "RECONNAISSANCE",
    DetectionType.STATISTICAL_ANOMALY: "RECONNAISSANCE",
    DetectionType.BRUTE_FORCE: "INITIAL_ACCESS",
    DetectionType.AUTH_ANOMALY: "INITIAL_ACCESS",
    DetectionType.PATH_TRAVERSAL: "EXPLOITATION",
    DetectionType.INJECTION: "EXPLOITATION",
    DetectionType.DOS: "IMPACT",
    DetectionType.DATA_EXFIL: "EXFILTRATION",
}

# Severity rank ordering for comparisons
SEVERITY_RANK: Dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}

RANK_TO_SEVERITY: Dict[int, Severity] = {
    1: Severity.INFO,
    2: Severity.LOW,
    3: Severity.MEDIUM,
    4: Severity.HIGH,
    5: Severity.CRITICAL,
}


class CorrelationEngine:
    """Correlates individual security detections into unified, prioritized incidents.

    Attributes:
        time_window_minutes: Maximum temporal gap (in minutes) allowed between detections
            for them to be considered part of the same incident candidate.
        ip_overlap_threshold: Minimum overlap ratio required for fuzzy IP association.
    """

    def __init__(
        self,
        time_window_minutes: int = 30,
        ip_overlap_threshold: float = 0.5,
    ) -> None:
        """Initialize the correlation engine with window and threshold configurations."""
        self.time_window_minutes = max(1, time_window_minutes)
        self.ip_overlap_threshold = max(0.0, min(1.0, ip_overlap_threshold))

    def correlate(self, detections: List[Detection]) -> List[Incident]:
        """Group detections into correlated incidents using multi-factor heuristics.

        Args:
            detections: List of detection models to correlate.

        Returns:
            List of correlated Incident models.
        """
        if not detections:
            return []

        # Sort detections chronologically by start timestamp
        sorted_detections = sorted(detections, key=lambda d: d.timestamp_start)
        n = len(sorted_detections)

        # Adjacency graph representing merge relationships
        adjacency: Dict[int, List[Tuple[int, str]]] = defaultdict(list)

        for i in range(n):
            for j in range(i + 1, n):
                d1 = sorted_detections[i]
                d2 = sorted_detections[j]
                should_merge, explanation = self._should_merge(d1, d2)
                if should_merge:
                    adjacency[i].append((j, explanation))
                    adjacency[j].append((i, explanation))

        # Find connected components (incident clusters)
        visited: Set[int] = set()
        incidents: List[Incident] = []

        for i in range(n):
            if i in visited:
                continue

            # Breadth-first search to collect component
            cluster_indices: List[int] = []
            cluster_explanations: List[str] = []
            queue = [i]
            visited.add(i)

            while queue:
                curr = queue.pop(0)
                cluster_indices.append(curr)
                for neighbor, reason in adjacency[curr]:
                    if reason and reason not in cluster_explanations:
                        cluster_explanations.append(reason)
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

            cluster_detections = [sorted_detections[idx] for idx in cluster_indices]

            # Construct consolidated explanation
            if cluster_explanations:
                combined_explanation = "; ".join(cluster_explanations)
            else:
                det = cluster_detections[0]
                combined_explanation = (
                    f"Isolated security detection of type {det.detection_type.value} "
                    f"from {', '.join(det.source_ips) or 'unknown source'}"
                )

            severity = self._calculate_incident_severity(cluster_detections)
            title = self._generate_title(cluster_detections)
            evidence_summary = self._build_evidence_summary(cluster_detections)

            # Determine timestamps for incident creation
            min_ts = min(d.timestamp_start for d in cluster_detections)
            max_ts = max(d.timestamp_end for d in cluster_detections)

            # Temporary incident to compute priority
            inc = Incident(
                incident_id=generate_id(),
                title=title,
                detections=cluster_detections,
                severity=severity,
                priority=IncidentPriority.P4,
                status=IncidentStatus.NEW,
                correlation_explanation=combined_explanation,
                created_at=min_ts,
                updated_at=max_ts,
                evidence_summary=evidence_summary,
                related_incident_ids=[],
            )

            # Compute priority dynamically based on incident metrics
            inc.priority = self._calculate_priority(inc)
            incidents.append(inc)

        # Sort incidents by priority (P1 highest) and then descending severity
        incidents.sort(
            key=lambda x: (
                x.priority.value,
                -SEVERITY_RANK.get(x.severity, 0),
                -len(x.detections),
            )
        )
        return incidents

    def _should_merge(self, d1: Detection, d2: Detection) -> Tuple[bool, str]:
        """Evaluate whether two detections should be merged into the same incident.

        Correlation Rules:
          a) Same source IP within time window.
          b) Related detection types (e.g. port scan + brute force from same source).
          c) Attack chain patterns (recon -> exploit -> exfil).
          d) Same target destination IP with multiple attack types within time window.

        Args:
            d1: First detection.
            d2: Second detection.

        Returns:
            Tuple of (boolean flag indicating merge, explanation string).
        """
        # Time window enforcement
        t1_start, t1_end = d1.timestamp_start, d1.timestamp_end
        t2_start, t2_end = d2.timestamp_start, d2.timestamp_end

        # Temporal distance in seconds
        if t2_start > t1_end:
            time_gap = (t2_start - t1_end).total_seconds()
        elif t1_start > t2_end:
            time_gap = (t1_start - t2_end).total_seconds()
        else:
            time_gap = 0.0

        max_window_sec = self.time_window_minutes * 60
        if time_gap > max_window_sec:
            return False, f"Time gap ({int(time_gap)}s) exceeds window ({max_window_sec}s)"

        src_ips1 = set(d1.source_ips or [])
        src_ips2 = set(d2.source_ips or [])
        dst_ips1 = set(d1.dest_ips or [])
        dst_ips2 = set(d2.dest_ips or [])

        common_src = src_ips1.intersection(src_ips2)
        common_dst = dst_ips1.intersection(dst_ips2)

        stage1 = ATTACK_STAGES.get(d1.detection_type, "UNKNOWN")
        stage2 = ATTACK_STAGES.get(d2.detection_type, "UNKNOWN")

        # Rule a & b: Same source IP with matching or related detection types
        if common_src:
            src_str = ", ".join(sorted(common_src))
            # Rule c: Attack chain patterns across stages from same source
            if stage1 != stage2 and stage1 != "UNKNOWN" and stage2 != "UNKNOWN":
                return True, (
                    f"Attack chain progression ({stage1} -> {stage2}) "
                    f"originating from common source IP(s) [{src_str}] within {int(time_gap)}s"
                )

            # Related attack types or identical detection type
            if d1.detection_type == d2.detection_type:
                return True, (
                    f"Repeated {d1.detection_type.value} activity "
                    f"from identical source IP(s) [{src_str}]"
                )

            # Co-occurring attacks from same attacker
            return True, (
                f"Related attack vectors ({d1.detection_type.value} + {d2.detection_type.value}) "
                f"from source IP(s) [{src_str}]"
            )

        # Rule d: Same target destination with multiple attack types within time window
        if common_dst:
            dst_str = ", ".join(sorted(common_dst))
            if d1.detection_type != d2.detection_type:
                return True, (
                    f"Coordinated multi-vector campaign targeting common destination [{dst_str}] "
                    f"involving {d1.detection_type.value} and {d2.detection_type.value}"
                )
            if src_ips1 and src_ips2:
                # Calculate source overlap ratio if both have IPs
                union_src = src_ips1.union(src_ips2)
                overlap_ratio = len(common_src) / len(union_src) if union_src else 0.0
                if overlap_ratio >= self.ip_overlap_threshold:
                    return True, (
                        f"Targeted attack on destination [{dst_str}] "
                        f"with source overlap ratio {overlap_ratio:.2f}"
                    )

        # Disconnected events must NEVER be merged
        return False, "Unrelated events: no source/target overlap and separate vectors"

    def _calculate_incident_severity(self, detections: List[Detection]) -> Severity:
        """Calculate aggregate severity for a group of detections.

        Severity is driven by the maximum individual detection severity, with potential
        escalation if multiple high-severity events or complete attack chains are present.

        Args:
            detections: List of member detections.

        Returns:
            Calculated Severity enum value.
        """
        if not detections:
            return Severity.INFO

        max_rank = max(SEVERITY_RANK.get(d.severity, 1) for d in detections)
        critical_count = sum(1 for d in detections if d.severity == Severity.CRITICAL)
        high_count = sum(1 for d in detections if d.severity == Severity.HIGH)

        # Check distinct attack stages
        stages = {
            ATTACK_STAGES.get(d.detection_type)
            for d in detections
            if d.detection_type in ATTACK_STAGES
        }

        # Escalation rules:
        # Multiple HIGH detections or multi-stage attacks elevate HIGH to CRITICAL
        if max_rank == 4 and (high_count >= 2 or len(stages) >= 3):
            max_rank = 5
        elif max_rank == 3 and len(detections) >= 3:
            max_rank = 4

        return RANK_TO_SEVERITY.get(max_rank, Severity.MEDIUM)

    def _calculate_priority(self, incident: Incident) -> Priority:
        """Calculate response priority ranking (P1 through P4) for an incident.

        Priority considers:
          - Aggregate severity
          - Number of correlated detections
          - Attack chain completeness
          - Scope of affected target assets

        Args:
            incident: Candidate Incident model.

        Returns:
            Priority enum value (P1, P2, P3, or P4).
        """
        score = 0.0

        # Base score from severity
        severity_points = {
            Severity.CRITICAL: 0.50,
            Severity.HIGH: 0.35,
            Severity.MEDIUM: 0.20,
            Severity.LOW: 0.10,
            Severity.INFO: 0.05,
        }
        score += severity_points.get(incident.severity, 0.10)

        # Multi-stage attack chain completeness bonus
        distinct_stages = {
            ATTACK_STAGES.get(d.detection_type)
            for d in incident.detections
            if d.detection_type in ATTACK_STAGES
        }
        if len(distinct_stages) >= 3:
            score += 0.25
        elif len(distinct_stages) == 2:
            score += 0.15

        # Detection volume bonus
        det_count = len(incident.detections)
        if det_count >= 5:
            score += 0.15
        elif det_count >= 2:
            score += 0.08

        # Target scope bonus
        dest_ips: Set[str] = set()
        for d in incident.detections:
            dest_ips.update(d.dest_ips or [])
        if len(dest_ips) >= 3:
            score += 0.10
        elif len(dest_ips) >= 1:
            score += 0.05

        # High confidence booster
        avg_confidence = (
            sum(d.confidence for d in incident.detections) / det_count
            if det_count > 0
            else 0.0
        )
        if avg_confidence >= 0.85:
            score += 0.10

        # Map aggregate score to priority level
        if score >= 0.70 or incident.severity == Severity.CRITICAL:
            return Priority.P1
        if score >= 0.50 or incident.severity == Severity.HIGH:
            return Priority.P2
        if score >= 0.30:
            return Priority.P3
        return Priority.P4

    def _generate_title(self, detections: List[Detection]) -> str:
        """Generate a concise, human-readable title describing the incident.

        Args:
            detections: List of detections in the incident.

        Returns:
            Formatted title string.
        """
        if not detections:
            return "Empty Security Incident"

        types = sorted(list({d.detection_type.value for d in detections}))
        source_ips = sorted(list({ip for d in detections for ip in (d.source_ips or [])}))
        dest_ips = sorted(list({ip for d in detections for ip in (d.dest_ips or [])}))

        src_str = ", ".join(source_ips[:2]) if source_ips else "Unknown Source"
        if len(source_ips) > 2:
            src_str += f" (+{len(source_ips) - 2} more)"

        dst_str = ", ".join(dest_ips[:2]) if dest_ips else "Infrastructure"
        if len(dest_ips) > 2:
            dst_str += f" (+{len(dest_ips) - 2} more)"

        if len(types) == 1:
            return f"{types[0]} Activity from {src_str} against {dst_str}"
        elif len(types) <= 3:
            types_str = " -> ".join(types)
            return f"Multi-Vector Attack ({types_str}) from {src_str}"
        else:
            return f"Complex Campaign ({len(types)} vectors) targeting {dst_str} from {src_str}"

    def _build_evidence_summary(self, detections: List[Detection]) -> Dict[str, Any]:
        """Aggregate evidence artifacts across detections into a summary structure.

        Args:
            detections: List of detections.

        Returns:
            Dictionary containing aggregated metrics, event IDs, and IOCs.
        """
        unique_sources = sorted(list({ip for d in detections for ip in (d.source_ips or [])}))
        unique_dests = sorted(list({ip for d in detections for ip in (d.dest_ips or [])}))
        all_event_ids = sorted(
            list({eid for d in detections for eid in (d.source_event_ids or [])})
        )
        detection_types = [d.detection_type.value for d in detections]

        evidence_artifacts: List[Dict[str, Any]] = []
        for d in detections:
            evidence_artifacts.append(
                {
                    "detection_id": d.detection_id,
                    "type": d.detection_type.value,
                    "severity": d.severity.value,
                    "confidence": d.confidence,
                    "measured_value": d.measured_value,
                    "threshold_value": d.threshold_value,
                    "baseline_value": d.baseline_value,
                    "evidence_data": d.evidence,
                    "explanation": d.explanation,
                }
            )

        stages = sorted(
            list(
                {
                    ATTACK_STAGES.get(d.detection_type, "UNKNOWN")
                    for d in detections
                }
            )
        )

        return {
            "total_detections": len(detections),
            "detection_types": detection_types,
            "attack_stages": stages,
            "source_ips": unique_sources,
            "dest_ips": unique_dests,
            "source_event_count": len(all_event_ids),
            "source_event_ids": all_event_ids[:50],  # Sample max 50 IDs
            "evidence_artifacts": evidence_artifacts,
        }
