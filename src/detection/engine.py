"""Core security detection engine orchestrating detectors and statistical baselines."""

import logging
from typing import Any, Callable, Dict, List, Optional

try:
    from ..utils.config import Settings, get_settings
    from ..utils.models import Detection, LogRecord, Severity
    from .baselines import (
        compute_auth_baselines,
        compute_request_baselines,
        compute_status_baselines,
        compute_traffic_baselines,
    )
    from .detectors import (
        detect_auth_anomalies,
        detect_brute_force,
        detect_data_exfiltration,
        detect_dos,
        detect_http_anomalies,
        detect_injection,
        detect_path_traversal,
        detect_port_scan,
        detect_statistical_anomalies,
    )
except ImportError:
    from src.utils.config import Settings, get_settings
    from src.utils.models import Detection, LogRecord, Severity
    from src.detection.baselines import (
        compute_auth_baselines,
        compute_request_baselines,
        compute_status_baselines,
        compute_traffic_baselines,
    )
    from src.detection.detectors import (
        detect_auth_anomalies,
        detect_brute_force,
        detect_data_exfiltration,
        detect_dos,
        detect_http_anomalies,
        detect_injection,
        detect_path_traversal,
        detect_port_scan,
        detect_statistical_anomalies,
    )

logger = logging.getLogger(__name__)

# Severity ordering for sorting output detections
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class DetectionEngine:
    """Orchestrates statistical baseline creation and executes security detectors on ingested logs."""

    def __init__(self, config: Optional[Settings] = None) -> None:
        """Initialize the DetectionEngine with configuration.

        Args:
            config: Optional application Settings override.
        """
        self.config = config or get_settings()
        self._detectors: List[Callable[[List[LogRecord], Dict[str, Any]], List[Detection]]] = [
            detect_dos,
            detect_brute_force,
            detect_port_scan,
            detect_http_anomalies,
            detect_path_traversal,
            detect_injection,
            detect_data_exfiltration,
            detect_auth_anomalies,
            detect_statistical_anomalies,
        ]

    def register_detector(
        self,
        detector_fn: Callable[[List[LogRecord], Dict[str, Any]], List[Detection]],
    ) -> None:
        """Register a custom detector function into the pipeline.

        Args:
            detector_fn: Callable taking (records, baselines) and returning List[Detection].
        """
        self._detectors.append(detector_fn)

    def _build_baselines(self, records: List[LogRecord]) -> Dict[str, Any]:
        """Compute statistical baselines across request, auth, traffic, and status distributions.

        Args:
            records: Ingested log records.

        Returns:
            Dictionary containing aggregated baseline models and statistical metrics.
        """
        if not records:
            return {}

        req_baselines = compute_request_baselines(records)
        auth_baselines = compute_auth_baselines(records)
        traffic_baselines = compute_traffic_baselines(records)
        status_baselines = compute_status_baselines(records)

        baselines: Dict[str, Any] = {}
        baselines.update(req_baselines)
        baselines.update(auth_baselines)
        baselines.update(traffic_baselines)
        baselines.update(status_baselines)

        return baselines

    def run_all_detectors(self, records: List[LogRecord], include_statistical: bool = True) -> List[Detection]:
        """Execute all registered security detectors against the provided log records.

        Computes statistical baselines first, then executes each detector in sequence,
        collecting and sorting all generated Detections.

        Args:
            records: List of ingested and normalized LogRecord objects.
            include_statistical: Whether to run statistical anomaly detection (Isolation Forest).

        Returns:
            List of detected security events, sorted by severity and timestamp.
        """
        if not records:
            logger.info("No records provided to DetectionEngine; returning empty detection list.")
            return []

        logger.info("Computing statistical baselines for %d records...", len(records))
        baselines = self._build_baselines(records)

        all_detections: List[Detection] = []

        for detector in self._detectors:
            detector_name = getattr(detector, "__name__", str(detector))
            # Skip statistical anomaly detector if not requested
            if not include_statistical and detector_name == "detect_statistical_anomalies":
                logger.debug("Skipping statistical anomaly detector (disabled)")
                continue
            try:
                logger.debug("Executing detector: %s", detector_name)
                detections = detector(records, baselines)
                if detections:
                    logger.info("Detector %s identified %d detection(s)", detector_name, len(detections))
                    all_detections.extend(detections)
            except Exception as e:
                logger.error("Error executing detector %s: %s", detector_name, e, exc_info=True)

        # Sort detections by severity priority, then timestamp
        all_detections.sort(
            key=lambda d: (
                SEVERITY_ORDER.get(d.severity, 99),
                d.timestamp_start,
            )
        )

        logger.info("DetectionEngine finished: %d total detection(s) found.", len(all_detections))
        return all_detections
