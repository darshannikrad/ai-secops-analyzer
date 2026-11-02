"""
Prioritization engine for threat incidents.

Implements transparent severity and priority policies with separate dimensions
for severity, anomaly score, confidence, and priority.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class PriorityPolicy:
    """Configurable weights for priority calculation."""
    severity_weight: float = 0.35
    anomaly_score_weight: float = 0.20
    confidence_weight: float = 0.25
    recency_weight: float = 0.10
    affected_assets_weight: float = 0.10

    def validate(self) -> None:
        total = (self.severity_weight + self.anomaly_score_weight +
                 self.confidence_weight + self.recency_weight +
                 self.affected_assets_weight)
        if abs(total - 1.0) > 0.01:
            raise ValueError(f"Policy weights must sum to 1.0, got {total:.2f}")


# Severity to numeric mapping
SEVERITY_SCORES = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.25,
    "INFO": 0.1,
}

# Priority thresholds
PRIORITY_THRESHOLDS = {
    "P1": 0.80,  # Critical - immediate response
    "P2": 0.60,  # High - respond within 1 hour
    "P3": 0.35,  # Medium - respond within 4 hours
    "P4": 0.0,   # Low - respond within 24 hours
}


class PrioritizationEngine:
    """
    Calculates incident priority using a transparent, multi-dimensional scoring system.
    
    Priority is computed from separate dimensions:
    - Severity: inherent danger level of the detection types
    - Anomaly Score: how statistically unusual the activity is
    - Confidence: how certain we are this is a true positive
    - Recency: how recently the events occurred
    - Affected Assets: number of unique targets/sources involved
    """

    def __init__(self, policy: Optional[PriorityPolicy] = None):
        self.policy = policy or PriorityPolicy()
        self.policy.validate()

    def prioritize(self, incidents: list) -> list:
        """
        Calculate priority for each incident and return sorted by priority.
        
        Args:
            incidents: List of Incident objects (Pydantic models)
            
        Returns:
            Incidents sorted by priority (P1 first), with priority fields set
        """
        scored_incidents = []
        for incident in incidents:
            try:
                priority_info = self._calculate_priority(incident)
                # Update the incident priority
                incident.priority = priority_info["priority"]
                incident.priority_score = priority_info["score"]
                incident.priority_explanation = priority_info["explanation"]
                scored_incidents.append((priority_info["score"], incident))
            except Exception as e:
                logger.warning(f"Error prioritizing incident {getattr(incident, 'incident_id', '?')}: {e}")
                scored_incidents.append((0.0, incident))

        # Sort by score descending (highest priority first)
        scored_incidents.sort(key=lambda x: x[0], reverse=True)
        return [inc for _, inc in scored_incidents]

    def _calculate_priority(self, incident) -> dict:
        """Calculate priority score and assignment for an incident."""
        dimensions = {}

        # 1. Severity score
        severity_str = str(getattr(incident, 'severity', 'MEDIUM')).upper()
        if hasattr(incident.severity, 'value'):
            severity_str = incident.severity.value.upper()
        severity_score = SEVERITY_SCORES.get(severity_str, 0.5)
        dimensions["severity"] = severity_score

        # 2. Anomaly score (average confidence across detections as proxy)
        detections = getattr(incident, 'detections', [])
        if detections:
            confidences = [getattr(d, 'confidence', 0.5) for d in detections]
            anomaly_score = sum(confidences) / len(confidences)
        else:
            anomaly_score = 0.3
        dimensions["anomaly_score"] = anomaly_score

        # 3. Confidence (based on evidence strength)
        confidence = self._assess_confidence(incident)
        dimensions["confidence"] = confidence

        # 4. Recency score
        recency = self._calculate_recency(incident)
        dimensions["recency"] = recency

        # 5. Affected assets
        assets_score = self._calculate_assets_score(incident)
        dimensions["affected_assets"] = assets_score

        # Weighted combination
        total_score = (
            self.policy.severity_weight * dimensions["severity"] +
            self.policy.anomaly_score_weight * dimensions["anomaly_score"] +
            self.policy.confidence_weight * dimensions["confidence"] +
            self.policy.recency_weight * dimensions["recency"] +
            self.policy.affected_assets_weight * dimensions["affected_assets"]
        )

        # Map to priority level
        priority = "P4"
        for level, threshold in sorted(PRIORITY_THRESHOLDS.items()):
            if total_score >= threshold:
                priority = level

        # Fix: iterate in correct order
        if total_score >= PRIORITY_THRESHOLDS["P1"]:
            priority = "P1"
        elif total_score >= PRIORITY_THRESHOLDS["P2"]:
            priority = "P2"
        elif total_score >= PRIORITY_THRESHOLDS["P3"]:
            priority = "P3"
        else:
            priority = "P4"

        explanation = (
            f"Priority {priority} (score={total_score:.2f}): "
            f"severity={dimensions['severity']:.2f}, "
            f"anomaly={dimensions['anomaly_score']:.2f}, "
            f"confidence={dimensions['confidence']:.2f}, "
            f"recency={dimensions['recency']:.2f}, "
            f"assets={dimensions['affected_assets']:.2f}"
        )

        return {
            "priority": priority,
            "score": total_score,
            "dimensions": dimensions,
            "explanation": explanation,
        }

    def _assess_confidence(self, incident) -> float:
        """Assess confidence based on evidence quality."""
        detections = getattr(incident, 'detections', [])
        if not detections:
            return 0.3

        factors = []

        # Multiple corroborating detections increase confidence
        detection_count = len(detections)
        if detection_count >= 4:
            factors.append(0.9)
        elif detection_count >= 2:
            factors.append(0.7)
        else:
            factors.append(0.5)

        # High individual confidence detections
        high_conf = sum(1 for d in detections if getattr(d, 'confidence', 0) > 0.7)
        factors.append(min(1.0, high_conf / max(len(detections), 1)))

        # Evidence completeness (detections with source_event_ids)
        with_evidence = sum(
            1 for d in detections
            if getattr(d, 'source_event_ids', None) and len(d.source_event_ids) > 0
        )
        factors.append(with_evidence / max(len(detections), 1))

        return sum(factors) / len(factors)

    def _calculate_recency(self, incident) -> float:
        """Score recency - more recent = higher score."""
        now = datetime.now(timezone.utc)
        created = getattr(incident, 'created_at', None)
        if created is None:
            return 0.5

        if isinstance(created, str):
            try:
                from dateutil.parser import parse as parse_dt
                created = parse_dt(created)
            except Exception:
                return 0.5

        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)

        age_hours = (now - created).total_seconds() / 3600
        if age_hours < 1:
            return 1.0
        elif age_hours < 4:
            return 0.8
        elif age_hours < 24:
            return 0.6
        elif age_hours < 72:
            return 0.4
        else:
            return 0.2

    def _calculate_assets_score(self, incident) -> float:
        """Score based on number of affected assets."""
        detections = getattr(incident, 'detections', [])
        unique_ips = set()
        for d in detections:
            for ip in getattr(d, 'source_ips', []) or []:
                unique_ips.add(ip)
            for ip in getattr(d, 'dest_ips', []) or []:
                unique_ips.add(ip)

        count = len(unique_ips)
        if count >= 10:
            return 1.0
        elif count >= 5:
            return 0.8
        elif count >= 3:
            return 0.6
        elif count >= 2:
            return 0.4
        else:
            return 0.2
