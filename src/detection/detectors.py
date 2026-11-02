"""Security detection rules and anomaly detectors for log analysis."""

import html
import logging
import math
import re
import urllib.parse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from ..utils.config import get_settings
    from ..utils.helpers import calculate_mad, calculate_percentile, generate_id, robust_zscore
    from ..utils.models import Detection, DetectionType, LogRecord, Severity
    from ..utils.security import BLOCKED_PATTERNS
except ImportError:
    from src.utils.config import get_settings
    from src.utils.helpers import calculate_mad, calculate_percentile, generate_id, robust_zscore
    from src.utils.models import Detection, DetectionType, LogRecord, Severity
    from src.utils.security import BLOCKED_PATTERNS

logger = logging.getLogger(__name__)

# Precompiled detection patterns
SQLI_PATTERNS = [
    re.compile(r"(\bUNION\b\s+(?:ALL\s+)?\bSELECT\b)", re.IGNORECASE),
    re.compile(r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)", re.IGNORECASE),
    re.compile(r"(\bAND\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)", re.IGNORECASE),
    re.compile(r"(';\s*DROP\s+TABLE\b)", re.IGNORECASE),
    re.compile(r"(\bWAITFOR\b\s+\bDELAY\b|\bSLEEP\s*\(\d+\)|\bBENCHMARK\s*\()", re.IGNORECASE),
    re.compile(r"(\bEXEC\b\s*\(|\bEXECUTE\b\s*\(|\bxp_cmdshell\b)", re.IGNORECASE),
    re.compile(r"(\bSELECT\b.*?\bFROM\b.*?information_schema)", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"(<script\b[^>]*>.*?</script>)", re.IGNORECASE),
    re.compile(r"(javascript\s*:\s*[^\s]+)", re.IGNORECASE),
    re.compile(r"(onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=)", re.IGNORECASE),
    re.compile(r"(<img\b[^>]*\bsrc\s*=\s*['\"]?javascript:)", re.IGNORECASE),
    re.compile(r"(alert\s*\(|prompt\s*\(|confirm\s*\()", re.IGNORECASE),
]

CMD_INJECTION_PATTERNS = [
    re.compile(r"(;\s*(?:cat|ls|rm|nc|curl|wget|bash|sh|powershell|whoami|id)\b)", re.IGNORECASE),
    re.compile(r"(\|\s*(?:cat|ls|rm|nc|curl|wget|bash|sh|powershell|whoami|id)\b)", re.IGNORECASE),
    re.compile(r"(&&\s*(?:cat|ls|rm|nc|curl|wget|bash|sh|powershell|whoami|id)\b)", re.IGNORECASE),
    re.compile(r"(`.*`|\$\(.*\))"),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\){2,}"),
    re.compile(r"(%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c)", re.IGNORECASE),
    re.compile(r"(%252e%252e%252f|%252e%252e\/)", re.IGNORECASE),
    re.compile(r"(/etc/passwd|/etc/shadow|/proc/self|/windows/system32|boot\.ini)", re.IGNORECASE),
]


def detect_dos(
    records: List[LogRecord],
    baselines: Optional[Dict[str, Any]] = None,
) -> List[Detection]:
    """Detect request flooding and Denial of Service (DoS) patterns.

    Uses requests-per-source-per-window analysis evaluated against statistical
    median + k*MAD thresholds or configured volume caps.

    Args:
        records: Ingested log records.
        baselines: Statistical baselines dict.

    Returns:
        List of Detection objects.
    """
    if not records:
        return []

    settings = get_settings()
    thresholds = settings.thresholds
    window_sec = thresholds.dos_window_seconds
    rate_threshold = thresholds.dos_request_rate_per_sec
    baseline_median = 0.0
    baseline_mad = 0.0

    if baselines and "requests_per_ip_window" in baselines:
        b_stats = baselines["requests_per_ip_window"]
        baseline_median = getattr(b_stats, "median", 0.0)
        baseline_mad = getattr(b_stats, "mad", 0.0)

    # Dynamic robust threshold: baseline median + 3 * MAD (or fallback to max(20.0, rate_threshold * window_sec))
    if baseline_mad > 0 or baseline_median > 0:
        effective_threshold = max(15.0, baseline_median + (3.0 * baseline_mad if baseline_mad > 0 else 10.0))
    else:
        effective_threshold = min(30.0, max(15.0, rate_threshold * window_sec))

    # Group records by source IP
    ip_records: Dict[str, List[LogRecord]] = defaultdict(list)
    for r in records:
        if r.source_ip:
            ip_records[r.source_ip].append(r)

    detections: List[Detection] = []

    for src_ip, recs in ip_records.items():
        if len(recs) < 5:
            continue

        sorted_recs = sorted(recs, key=lambda x: x.timestamp)
        # Sliding time window check
        left = 0
        n = len(sorted_recs)
        max_window_recs: List[LogRecord] = []

        for right in range(n):
            while (sorted_recs[right].timestamp - sorted_recs[left].timestamp).total_seconds() > window_sec:
                left += 1

            current_window = sorted_recs[left : right + 1]
            if len(current_window) > len(max_window_recs):
                max_window_recs = current_window

        count_in_window = len(max_window_recs)
        if count_in_window >= effective_threshold:
            t_start = max_window_recs[0].timestamp
            t_end = max_window_recs[-1].timestamp
            duration = max(1.0, (t_end - t_start).total_seconds())
            measured_rate = count_in_window / duration

            # Calculate confidence based on magnitude above threshold
            ratio = count_in_window / effective_threshold
            conf = min(0.99, max(0.65, 0.65 + 0.1 * min(3.0, ratio - 1.0)))

            severity = Severity.CRITICAL if ratio >= 3.0 else Severity.HIGH

            dest_ips = list({r.dest_ip for r in max_window_recs if r.dest_ip})
            event_ids = [r.record_id for r in max_window_recs]

            detections.append(
                Detection(
                    detection_id=generate_id(),
                    detection_type=DetectionType.DOS,
                    severity=severity,
                    confidence=round(conf, 2),
                    description=f"Potential DoS request flooding from {src_ip} ({count_in_window} reqs / {duration:.1f}s)",
                    evidence={
                        "request_count": count_in_window,
                        "time_window_seconds": duration,
                        "measured_rate_per_sec": round(measured_rate, 2),
                        "threshold_count": effective_threshold,
                        "sample_urls": list({r.url for r in max_window_recs if r.url})[:5],
                    },
                    measured_value=float(count_in_window),
                    threshold_value=float(effective_threshold),
                    baseline_value=float(baseline_median),
                    source_event_ids=event_ids,
                    timestamp_start=t_start,
                    timestamp_end=t_end,
                    source_ips=[src_ip],
                    dest_ips=dest_ips,
                    explanation=(
                        f"Source IP {src_ip} initiated {count_in_window} requests in {duration:.1f}s, "
                        f"exceeding the calculated volumetric ceiling of {effective_threshold:.0f}. "
                        "This significant volume anomaly indicates potential Denial of Service (DoS) flooding or "
                        "high-intensity automated scraping rather than normal user interaction."
                    ),
                )
            )

    return detections


def detect_brute_force(
    records: List[LogRecord],
    baselines: Optional[Dict[str, Any]] = None,
) -> List[Detection]:
    """Detect authentication brute force attacks and password spraying.

    Identifies repeated failed logins from a single source targeting one account
    (brute force) or targeting many accounts (password spraying).

    Args:
        records: Ingested log records.
        baselines: Statistical baselines dict.

    Returns:
        List of Detection objects.
    """
    if not records:
        return []

    settings = get_settings()
    threshold_attempts = settings.thresholds.brute_force_failed_attempts
    window_sec = settings.thresholds.brute_force_window_seconds

    # Filter auth failure records
    failures_by_ip: Dict[str, List[LogRecord]] = defaultdict(list)
    for r in records:
        is_failure = False
        if r.action and any(w in r.action.upper() for w in ("FAIL", "DENY", "BLOCK", "REJECT", "INVALID")):
            is_failure = True
        elif r.status_code in (401, 403):
            is_failure = True

        if is_failure and r.source_ip:
            failures_by_ip[r.source_ip].append(r)

    detections: List[Detection] = []

    for src_ip, fail_recs in failures_by_ip.items():
        if len(fail_recs) < threshold_attempts:
            continue

        sorted_recs = sorted(fail_recs, key=lambda x: x.timestamp)
        left = 0
        n = len(sorted_recs)

        for right in range(n):
            while (sorted_recs[right].timestamp - sorted_recs[left].timestamp).total_seconds() > window_sec:
                left += 1

            window_recs = sorted_recs[left : right + 1]
            if len(window_recs) >= threshold_attempts:
                # Found cluster of failed attempts
                t_start = window_recs[0].timestamp
                t_end = window_recs[-1].timestamp
                targeted_users = list({r.username for r in window_recs if r.username})
                dest_ips = list({r.dest_ip for r in window_recs if r.dest_ip})
                event_ids = [r.record_id for r in window_recs]

                is_spraying = len(targeted_users) >= 3
                attack_label = "Password Spraying" if is_spraying else "Credential Brute Force"

                # Confidence and severity
                severity = Severity.CRITICAL if len(window_recs) >= 15 or is_spraying else Severity.HIGH
                conf = min(0.98, max(0.70, 0.70 + 0.05 * (len(window_recs) - threshold_attempts)))

                detections.append(
                    Detection(
                        detection_id=generate_id(),
                        detection_type=DetectionType.BRUTE_FORCE,
                        severity=severity,
                        confidence=round(conf, 2),
                        description=f"{attack_label} detected from {src_ip} ({len(window_recs)} failed auth events)",
                        evidence={
                            "failure_count": len(window_recs),
                            "unique_users_targeted": targeted_users,
                            "user_count": len(targeted_users),
                            "attack_subtype": "password_spray" if is_spraying else "single_account_bruteforce",
                            "window_seconds": window_sec,
                        },
                        measured_value=float(len(window_recs)),
                        threshold_value=float(threshold_attempts),
                        baseline_value=0.0,
                        source_event_ids=event_ids,
                        timestamp_start=t_start,
                        timestamp_end=t_end,
                        source_ips=[src_ip],
                        dest_ips=dest_ips,
                        explanation=(
                            f"Source IP {src_ip} generated {len(window_recs)} failed authentication attempts within "
                            f"{window_sec} seconds targeting {len(targeted_users)} account(s): {targeted_users[:5]}. "
                            f"This exceeds the threshold of {threshold_attempts} attempts. "
                            f"The concentrated pattern strongly indicates a confirmed {attack_label.lower()} attack."
                        ),
                    )
                )
                break  # Alert once per IP in this run

    return detections


def detect_port_scan(
    records: List[LogRecord],
    baselines: Optional[Dict[str, Any]] = None,
) -> List[Detection]:
    """Detect horizontal or vertical port scanning activity.

    Identifies source IPs probing numerous unique destination ports within a short window.

    Args:
        records: Ingested log records.
        baselines: Statistical baselines dict.

    Returns:
        List of Detection objects.
    """
    if not records:
        return []

    settings = get_settings()
    threshold_ports = settings.thresholds.port_scan_unique_ports
    window_sec = settings.thresholds.port_scan_window_seconds

    # Group records by source IP
    ip_records: Dict[str, List[LogRecord]] = defaultdict(list)
    for r in records:
        if r.source_ip and r.dest_port is not None:
            ip_records[r.source_ip].append(r)

    detections: List[Detection] = []

    for src_ip, recs in ip_records.items():
        sorted_recs = sorted(recs, key=lambda x: x.timestamp)
        left = 0
        n = len(sorted_recs)

        max_unique_ports: Set[int] = set()
        max_window_recs: List[LogRecord] = []

        for right in range(n):
            while (sorted_recs[right].timestamp - sorted_recs[left].timestamp).total_seconds() > window_sec:
                left += 1

            window_recs = sorted_recs[left : right + 1]
            ports = {r.dest_port for r in window_recs if r.dest_port is not None}
            if len(ports) > len(max_unique_ports):
                max_unique_ports = ports
                max_window_recs = window_recs

        if len(max_unique_ports) >= threshold_ports:
            t_start = max_window_recs[0].timestamp
            t_end = max_window_recs[-1].timestamp
            duration = max(1.0, (t_end - t_start).total_seconds())
            dest_ips = list({r.dest_ip for r in max_window_recs if r.dest_ip})
            sorted_ports = sorted(list(max_unique_ports))

            severity = Severity.HIGH if len(max_unique_ports) >= 30 else Severity.MEDIUM
            conf = min(0.99, max(0.75, 0.75 + 0.02 * (len(max_unique_ports) - threshold_ports)))

            detections.append(
                Detection(
                    detection_id=generate_id(),
                    detection_type=DetectionType.PORT_SCAN,
                    severity=severity,
                    confidence=round(conf, 2),
                    description=f"Port scanning activity detected from {src_ip} ({len(max_unique_ports)} unique ports)",
                    evidence={
                        "unique_ports_count": len(max_unique_ports),
                        "sampled_ports": sorted_ports[:15],
                        "scan_duration_seconds": round(duration, 1),
                        "target_dest_ips": dest_ips[:5],
                    },
                    measured_value=float(len(max_unique_ports)),
                    threshold_value=float(threshold_ports),
                    baseline_value=1.0,
                    source_event_ids=[r.record_id for r in max_window_recs],
                    timestamp_start=t_start,
                    timestamp_end=t_end,
                    source_ips=[src_ip],
                    dest_ips=dest_ips,
                    explanation=(
                        f"Source IP {src_ip} probed {len(max_unique_ports)} unique destination ports within {duration:.1f}s. "
                        f"Targeted ports include: {sorted_ports[:8]}. "
                        f"Reconnaissance behavior exceeding {threshold_ports} unique ports indicates automated network mapping."
                    ),
                )
            )

    return detections


def detect_http_anomalies(
    records: List[LogRecord],
    baselines: Optional[Dict[str, Any]] = None,
) -> List[Detection]:
    """Detect anomalous HTTP response status distributions (high 4xx or 5xx rates).

    Args:
        records: Ingested log records.
        baselines: Statistical baselines dict.

    Returns:
        List of Detection objects.
    """
    if not records:
        return []

    http_recs = [r for r in records if r.status_code is not None]
    if len(http_recs) < 10:
        return []

    baseline_err_rate = 0.05
    if baselines and "rates" in baselines:
        rates = baselines["rates"]
        baseline_err_rate = rates.get("4xx", 0.0) + rates.get("5xx", 0.0)

    # Check per source IP
    ip_records: Dict[str, List[LogRecord]] = defaultdict(list)
    for r in http_recs:
        if r.source_ip:
            ip_records[r.source_ip].append(r)

    detections: List[Detection] = []

    for src_ip, recs in ip_records.items():
        if len(recs) < 10:
            continue

        errors = [r for r in recs if r.status_code is not None and 400 <= r.status_code <= 599]
        error_rate = len(errors) / len(recs)

        # Threshold: > 50% error rate and at least 3x baseline error rate
        if error_rate >= 0.50 and error_rate > (baseline_err_rate * 2.0):
            sorted_errs = sorted(errors, key=lambda x: x.timestamp)
            status_breakdown = defaultdict(int)
            for r in recs:
                if r.status_code:
                    status_breakdown[r.status_code] += 1

            dest_ips = list({r.dest_ip for r in recs if r.dest_ip})
            event_ids = [r.record_id for r in errors]

            conf = min(0.95, max(0.60, float(error_rate)))
            severity = Severity.HIGH if error_rate >= 0.80 else Severity.MEDIUM

            detections.append(
                Detection(
                    detection_id=generate_id(),
                    detection_type=DetectionType.HTTP_ANOMALY,
                    severity=severity,
                    confidence=round(conf, 2),
                    description=f"Elevated HTTP error rate ({error_rate * 100:.1f}%) from {src_ip}",
                    evidence={
                        "total_requests": len(recs),
                        "error_count": len(errors),
                        "error_rate": round(error_rate, 4),
                        "baseline_error_rate": round(baseline_err_rate, 4),
                        "status_distribution": dict(status_breakdown),
                        "sample_error_urls": list({r.url for r in errors if r.url})[:5],
                    },
                    measured_value=float(error_rate),
                    threshold_value=0.50,
                    baseline_value=float(baseline_err_rate),
                    source_event_ids=event_ids,
                    timestamp_start=sorted_errs[0].timestamp,
                    timestamp_end=sorted_errs[-1].timestamp,
                    source_ips=[src_ip],
                    dest_ips=dest_ips,
                    explanation=(
                        f"Traffic from {src_ip} produced a {error_rate * 100:.1f}% HTTP error response rate across {len(recs)} requests. "
                        f"Compared to normal baseline error rate ({baseline_err_rate * 100:.1f}%), this deviation indicates "
                        "active vulnerability scanning, content enumeration, or severe application misconfiguration."
                    ),
                )
            )

    return detections


def detect_path_traversal(
    records: List[LogRecord],
    baselines: Optional[Dict[str, Any]] = None,
) -> List[Detection]:
    """Detect directory and path traversal exploitation attempts in URLs.

    Args:
        records: Ingested log records.
        baselines: Statistical baselines dict.

    Returns:
        List of Detection objects.
    """
    if not records:
        return []

    detections: List[Detection] = []
    matched_events_by_ip: Dict[str, List[Tuple[LogRecord, str]]] = defaultdict(list)

    for r in records:
        target_str = r.url or ""
        if not target_str and r.raw_line:
            target_str = r.raw_line

        # Check raw and URL-decoded forms
        decoded = urllib.parse.unquote(urllib.parse.unquote(target_str))
        candidates = [target_str, decoded]

        for cand in candidates:
            hit = False
            for pat in PATH_TRAVERSAL_PATTERNS:
                m = pat.search(cand)
                if m:
                    src_key = r.source_ip or "unknown"
                    matched_events_by_ip[src_key].append((r, m.group(0)))
                    hit = True
                    break
            if hit:
                break

    for src_ip, matches in matched_events_by_ip.items():
        recs = [m[0] for m in matches]
        pattern_samples = list({m[1] for m in matches})
        matched_urls = list({r.url for r in recs if r.url})
        dest_ips = list({r.dest_ip for r in recs if r.dest_ip})
        sorted_recs = sorted(recs, key=lambda x: x.timestamp)

        has_critical_files = any(
            "/etc/" in (r.url or "").lower()
            or "windows" in (r.url or "").lower()
            or "boot.ini" in (r.url or "").lower()
            or "/etc/" in p.lower()
            or "windows" in p.lower()
            or "boot.ini" in p.lower()
            for p in pattern_samples
            for r in recs
        )
        severity = Severity.CRITICAL if has_critical_files else Severity.HIGH

        detections.append(
            Detection(
                detection_id=generate_id(),
                detection_type=DetectionType.PATH_TRAVERSAL,
                severity=severity,
                confidence=0.95,
                description=f"Path traversal attempts detected from {src_ip} ({len(recs)} events)",
                evidence={
                    "matched_patterns": pattern_samples[:5],
                    "matched_urls": matched_urls[:5],
                    "total_attempts": len(recs),
                    "target_dest_ips": dest_ips[:5],
                },
                measured_value=float(len(recs)),
                threshold_value=1.0,
                baseline_value=0.0,
                source_event_ids=[r.record_id for r in recs],
                timestamp_start=sorted_recs[0].timestamp,
                timestamp_end=sorted_recs[-1].timestamp,
                source_ips=[src_ip] if src_ip != "unknown" else [],
                dest_ips=dest_ips,
                explanation=(
                    f"Identified {len(recs)} path traversal sequences originating from {src_ip}. "
                    f"Signatures such as '{pattern_samples[0]}' were present in requested URLs: {matched_urls[:3]}. "
                    "This confirmed exploitation attempt seeks unauthorized access to system files outside web roots."
                ),
            )
        )

    return detections


def detect_injection(
    records: List[LogRecord],
    baselines: Optional[Dict[str, Any]] = None,
) -> List[Detection]:
    """Detect SQL Injection (SQLi), Cross-Site Scripting (XSS), and Command Injection attacks.

    Args:
        records: Ingested log records.
        baselines: Statistical baselines dict.

    Returns:
        List of Detection objects.
    """
    if not records:
        return []

    detections: List[Detection] = []
    matches_by_ip: Dict[str, List[Tuple[LogRecord, str, str]]] = defaultdict(list)

    for r in records:
        test_strings = [s for s in (r.url, r.raw_line, r.user_agent) if s]
        found = False

        for text in test_strings:
            decoded = urllib.parse.unquote(urllib.parse.unquote(text))
            for candidate in (text, decoded):
                # 1. SQLi
                for pat in SQLI_PATTERNS:
                    m = pat.search(candidate)
                    if m:
                        src = r.source_ip or "unknown"
                        matches_by_ip[src].append((r, "SQL_INJECTION", m.group(0)))
                        found = True
                        break
                if found:
                    break

                # 2. XSS
                for pat in XSS_PATTERNS:
                    m = pat.search(candidate)
                    if m:
                        src = r.source_ip or "unknown"
                        matches_by_ip[src].append((r, "XSS", m.group(0)))
                        found = True
                        break
                if found:
                    break

                # 3. Command Injection
                for pat in CMD_INJECTION_PATTERNS:
                    m = pat.search(candidate)
                    if m:
                        src = r.source_ip or "unknown"
                        matches_by_ip[src].append((r, "COMMAND_INJECTION", m.group(0)))
                        found = True
                        break
                if found:
                    break
            if found:
                break

    for src_ip, match_list in matches_by_ip.items():
        recs = [m[0] for m in match_list]
        sorted_recs = sorted(recs, key=lambda x: x.timestamp)
        types = list({m[1] for m in match_list})
        sanitized_payloads = [html.escape(m[2][:80]) for m in match_list]
        dest_ips = list({r.dest_ip for r in recs if r.dest_ip})

        severity = Severity.CRITICAL if ("SQL_INJECTION" in types or "COMMAND_INJECTION" in types) else Severity.HIGH

        detections.append(
            Detection(
                detection_id=generate_id(),
                detection_type=DetectionType.INJECTION,
                severity=severity,
                confidence=0.92,
                description=f"Injection attacks ({', '.join(types)}) detected from {src_ip}",
                evidence={
                    "attack_types": types,
                    "matched_payload_samples": list(set(sanitized_payloads))[:5],
                    "event_count": len(recs),
                    "sample_urls": list({r.url for r in recs if r.url})[:5],
                },
                measured_value=float(len(recs)),
                threshold_value=1.0,
                baseline_value=0.0,
                source_event_ids=[r.record_id for r in recs],
                timestamp_start=sorted_recs[0].timestamp,
                timestamp_end=sorted_recs[-1].timestamp,
                source_ips=[src_ip] if src_ip != "unknown" else [],
                dest_ips=dest_ips,
                explanation=(
                    f"Detected {len(recs)} injection attempt(s) originating from {src_ip}. "
                    f"Payload signatures matching {types} were extracted from request parameters or URLs. "
                    f"Sample sanitized payload: '{sanitized_payloads[0]}'. "
                    "This confirmed exploit payload indicates an active web application attack."
                ),
            )
        )

    return detections


def detect_data_exfiltration(
    records: List[LogRecord],
    baselines: Optional[Dict[str, Any]] = None,
) -> List[Detection]:
    """Detect abnormal outbound data volumes and possible exfiltration.

    Uses configured byte transfer caps and baseline statistical percentiles.

    Args:
        records: Ingested log records.
        baselines: Statistical baselines dict.

    Returns:
        List of Detection objects.
    """
    if not records:
        return []

    settings = get_settings()
    byte_threshold = settings.thresholds.data_exfil_bytes_threshold
    window_sec = settings.thresholds.data_exfil_window_seconds
    baseline_p99 = 1_000_000.0

    if baselines and "bytes_sent" in baselines:
        b_stats = baselines["bytes_sent"]
        p99 = getattr(b_stats, "p99", 0.0)
        if p99 > 0:
            baseline_p99 = p99

    # Aggregate by (source_ip, dest_ip)
    pair_records: Dict[Tuple[str, str], List[LogRecord]] = defaultdict(list)
    for r in records:
        bytes_val = r.bytes_sent or 0
        if bytes_val > 0 and r.source_ip:
            dst = r.dest_ip or "external"
            pair_records[(r.source_ip, dst)].append(r)

    detections: List[Detection] = []

    for (src_ip, dst_ip), recs in pair_records.items():
        sorted_recs = sorted(recs, key=lambda x: x.timestamp)
        left = 0
        n = len(sorted_recs)

        for right in range(n):
            while (sorted_recs[right].timestamp - sorted_recs[left].timestamp).total_seconds() > window_sec:
                left += 1

            window_recs = sorted_recs[left : right + 1]
            total_bytes = sum(r.bytes_sent or 0 for r in window_recs)

            if total_bytes >= byte_threshold:
                t_start = window_recs[0].timestamp
                t_end = window_recs[-1].timestamp
                ratio = total_bytes / max(1.0, baseline_p99)

                severity = Severity.CRITICAL if total_bytes >= (byte_threshold * 3) else Severity.HIGH
                conf = min(0.95, max(0.70, 0.70 + 0.05 * min(5.0, total_bytes / byte_threshold)))

                detections.append(
                    Detection(
                        detection_id=generate_id(),
                        detection_type=DetectionType.DATA_EXFIL,
                        severity=severity,
                        confidence=round(conf, 2),
                        description=f"High outbound data transfer ({total_bytes / (1024*1024):.2f} MB) to {dst_ip}",
                        evidence={
                            "total_bytes_transferred": total_bytes,
                            "threshold_bytes": byte_threshold,
                            "baseline_p99": baseline_p99,
                            "ratio_to_baseline": round(ratio, 2),
                            "window_seconds": window_sec,
                            "event_count": len(window_recs),
                        },
                        measured_value=float(total_bytes),
                        threshold_value=float(byte_threshold),
                        baseline_value=float(baseline_p99),
                        source_event_ids=[r.record_id for r in window_recs],
                        timestamp_start=t_start,
                        timestamp_end=t_end,
                        source_ips=[src_ip],
                        dest_ips=[dst_ip] if dst_ip != "external" else [],
                        explanation=(
                            f"Identified {total_bytes / (1024*1024):.2f} MB of outbound data transfer from {src_ip} "
                            f"to {dst_ip} within {window_sec}s, exceeding the policy threshold of {byte_threshold / (1024*1024):.1f} MB. "
                            f"This anomalous volume ({ratio:.1f}x baseline P99) warrants investigation for unauthorized data exfiltration."
                        ),
                    )
                )
                break

    return detections


def detect_auth_anomalies(
    records: List[LogRecord],
    baselines: Optional[Dict[str, Any]] = None,
) -> List[Detection]:
    """Detect anomalous authentication events such as off-hours access or impossible travel.

    Args:
        records: Ingested log records.
        baselines: Statistical baselines dict.

    Returns:
        List of Detection objects.
    """
    if not records:
        return []

    detections: List[Detection] = []
    user_records: Dict[str, List[LogRecord]] = defaultdict(list)

    for r in records:
        if r.username:
            user_records[r.username].append(r)

    # 1. Impossible travel / multi-IP concurrent access anomaly
    for username, recs in user_records.items():
        if len(recs) < 2:
            continue

        sorted_recs = sorted(recs, key=lambda x: x.timestamp)
        for i in range(len(sorted_recs) - 1):
            r1 = sorted_recs[i]
            r2 = sorted_recs[i + 1]

            if r1.source_ip and r2.source_ip and r1.source_ip != r2.source_ip:
                delta_sec = abs((r2.timestamp - r1.timestamp).total_seconds())
                # If same user authenticates from different IPs in under 5 minutes (300s)
                if delta_sec < 300:
                    detections.append(
                        Detection(
                            detection_id=generate_id(),
                            detection_type=DetectionType.AUTH_ANOMALY,
                            severity=Severity.HIGH,
                            confidence=0.88,
                            description=f"Rapid multi-IP access detected for user '{username}'",
                            evidence={
                                "username": username,
                                "source_ip_1": r1.source_ip,
                                "source_ip_2": r2.source_ip,
                                "time_delta_seconds": delta_sec,
                                "timestamp_1": r1.timestamp.isoformat(),
                                "timestamp_2": r2.timestamp.isoformat(),
                            },
                            measured_value=float(delta_sec),
                            threshold_value=300.0,
                            baseline_value=0.0,
                            source_event_ids=[r1.record_id, r2.record_id],
                            timestamp_start=min(r1.timestamp, r2.timestamp),
                            timestamp_end=max(r1.timestamp, r2.timestamp),
                            source_ips=[r1.source_ip, r2.source_ip],
                            dest_ips=list({r.dest_ip for r in (r1, r2) if r.dest_ip}),
                            explanation=(
                                f"User account '{username}' was accessed from distinct IP addresses "
                                f"({r1.source_ip} and {r2.source_ip}) within {delta_sec:.0f} seconds. "
                                "This temporal anomaly strongly suggests concurrent credential sharing, "
                                "session hijacking, or an impossible physical travel scenario."
                            ),
                        )
                    )
                    break

    # 2. Off-hours access anomaly based on baselines
    hourly_counts = {}
    if baselines and "hourly_counts" in baselines:
        hourly_counts = baselines["hourly_counts"]

    if hourly_counts:
        quiet_hours = {h for h, cnt in hourly_counts.items() if cnt == 0 and (0 <= h <= 5 or 22 <= h <= 23)}
        if quiet_hours:
            off_hour_recs = [r for r in records if r.username and r.timestamp.hour in quiet_hours]
            if off_hour_recs:
                sorted_off = sorted(off_hour_recs, key=lambda x: x.timestamp)
                users = list({r.username for r in off_hour_recs if r.username})
                src_ips = list({r.source_ip for r in off_hour_recs if r.source_ip})
                dest_ips = list({r.dest_ip for r in off_hour_recs if r.dest_ip})

                detections.append(
                    Detection(
                        detection_id=generate_id(),
                        detection_type=DetectionType.AUTH_ANOMALY,
                        severity=Severity.MEDIUM,
                        confidence=0.72,
                        description=f"Off-hours authentication activity during baseline quiet period ({len(off_hour_recs)} events)",
                        evidence={
                            "users_involved": users,
                            "quiet_hours_utc": sorted(list(quiet_hours)),
                            "event_count": len(off_hour_recs),
                        },
                        measured_value=float(len(off_hour_recs)),
                        threshold_value=1.0,
                        baseline_value=0.0,
                        source_event_ids=[r.record_id for r in off_hour_recs],
                        timestamp_start=sorted_off[0].timestamp,
                        timestamp_end=sorted_off[-1].timestamp,
                        source_ips=src_ips,
                        dest_ips=dest_ips,
                        explanation=(
                            f"Observed authentication events for accounts {users[:5]} during baseline quiet hours "
                            f"(hours {sorted(list(quiet_hours))[:4]} UTC). "
                            "While potentially authorized maintenance, unexpected off-hours access warrants verification."
                        ),
                    )
                )

    return detections


def detect_statistical_anomalies(
    records: List[LogRecord],
    baselines: Optional[Dict[str, Any]] = None,
) -> List[Detection]:
    """Detect multivariate statistical anomalies using Isolation Forest or robust Z-score metrics.

    Args:
        records: Ingested log records.
        baselines: Statistical baselines dict.

    Returns:
        List of Detection objects.
    """
    if len(records) < 15:
        return []

    settings = get_settings()
    z_threshold = settings.thresholds.statistical_anomaly_zscore

    # Feature extraction: [bytes_sent, bytes_received, status_code]
    numeric_features: List[List[float]] = []
    valid_recs: List[LogRecord] = []

    for r in records:
        bs = float(r.bytes_sent or 0)
        br = float(r.bytes_received or 0)
        sc = float(r.status_code or 200)
        numeric_features.append([bs, br, sc])
        valid_recs.append(r)

    detections: List[Detection] = []

    # Attempt scikit-learn IsolationForest with fixed seed for reproducibility
    try:
        from sklearn.ensemble import IsolationForest
        import numpy as np

        X = np.array(numeric_features)
        # Check variance: if all columns have 0 variance, skip
        if np.all(np.std(X, axis=0) == 0):
            return []

        # Train Isolation Forest with fixed random seed
        clf = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
        )
        preds = clf.fit_predict(X)
        scores = clf.decision_function(X)

        # Identify anomalous records (preds == -1)
        anomalous_indices = [i for i, p in enumerate(preds) if p == -1]

        if anomalous_indices:
            # Group or alert top anomalies
            sorted_indices = sorted(anomalous_indices, key=lambda i: scores[i])[:10]
            anomalous_records = [valid_recs[i] for i in sorted_indices]
            worst_score = float(scores[sorted_indices[0]])

            src_ips = list({r.source_ip for r in anomalous_records if r.source_ip})
            dest_ips = list({r.dest_ip for r in anomalous_records if r.dest_ip})
            sorted_by_time = sorted(anomalous_records, key=lambda x: x.timestamp)

            conf = min(0.92, max(0.65, 0.65 + abs(worst_score)))

            detections.append(
                Detection(
                    detection_id=generate_id(),
                    detection_type=DetectionType.STATISTICAL_ANOMALY,
                    severity=Severity.MEDIUM,
                    confidence=round(conf, 2),
                    description=f"Multivariate statistical outliers detected via Isolation Forest ({len(sorted_indices)} events)",
                    evidence={
                        "algorithm": "IsolationForest",
                        "anomaly_score_min": round(worst_score, 4),
                        "contamination_rate": 0.05,
                        "anomalous_count": len(sorted_indices),
                        "sample_feature_values": [numeric_features[i] for i in sorted_indices[:3]],
                    },
                    measured_value=abs(worst_score),
                    threshold_value=0.0,
                    baseline_value=0.5,
                    source_event_ids=[r.record_id for r in anomalous_records],
                    timestamp_start=sorted_by_time[0].timestamp,
                    timestamp_end=sorted_by_time[-1].timestamp,
                    source_ips=src_ips,
                    dest_ips=dest_ips,
                    explanation=(
                        f"Unsupervised Isolation Forest algorithm flagged {len(sorted_indices)} records with abnormal "
                        f"multivariate feature profiles (decision score: {worst_score:.4f}). "
                        "These events deviate substantially from background log traffic distributions."
                    ),
                )
            )
            return detections
    except ImportError:
        logger.debug("scikit-learn not available, falling back to univariate robust Z-score")

    # Fallback to robust Z-score calculation on bytes_sent
    bytes_vals = [f[0] for f in numeric_features]
    med = calculate_percentile(bytes_vals, 50)
    mad = 0.0
    if baselines and "bytes_sent" in baselines:
        mad = getattr(baselines["bytes_sent"], "mad", 0.0)

    if mad <= 0.0:
        mad = calculate_mad(bytes_vals)
    effective_mad = mad if mad > 0.0 else max(1.0, med * 0.1)

    anomalies: List[LogRecord] = []
    for i, val in enumerate(bytes_vals):
        z = robust_zscore(val, med, effective_mad)
        if z > z_threshold or (mad == 0.0 and val > med * 10):
            anomalies.append(valid_recs[i])

        if anomalies:
            sorted_anom = sorted(anomalies, key=lambda x: x.timestamp)
            src_ips = list({r.source_ip for r in anomalies if r.source_ip})
            dest_ips = list({r.dest_ip for r in anomalies if r.dest_ip})

            detections.append(
                Detection(
                    detection_id=generate_id(),
                    detection_type=DetectionType.STATISTICAL_ANOMALY,
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    description=f"Robust Z-score traffic volume anomalies ({len(anomalies)} events)",
                    evidence={
                        "algorithm": "RobustZScore",
                        "z_threshold": z_threshold,
                        "median": med,
                        "mad": mad,
                    },
                    measured_value=float(len(anomalies)),
                    threshold_value=float(z_threshold),
                    baseline_value=float(med),
                    source_event_ids=[r.record_id for r in anomalies],
                    timestamp_start=sorted_anom[0].timestamp,
                    timestamp_end=sorted_anom[-1].timestamp,
                    source_ips=src_ips,
                    dest_ips=dest_ips,
                    explanation=(
                        f"Identified {len(anomalies)} records exceeding modified Z-score threshold of {z_threshold} "
                        f"based on payload size deviation from median {med:.1f}."
                    ),
                )
            )

    return detections
