"""Statistical baseline computation using robust metrics (Median, MAD, Percentiles)."""

import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from pydantic import BaseModel, Field

try:
    from ..utils.helpers import calculate_mad, calculate_percentile
    from ..utils.models import LogRecord
except ImportError:
    from src.utils.helpers import calculate_mad, calculate_percentile
    from src.utils.models import LogRecord


class BaselineStats(BaseModel):
    """Container for robust statistical baseline metrics."""

    median: float = Field(default=0.0, description="Median of values")
    mad: float = Field(default=0.0, description="Median Absolute Deviation")
    p95: float = Field(default=0.0, description="95th percentile")
    p99: float = Field(default=0.0, description="99th percentile")
    mean: float = Field(default=0.0, description="Arithmetic mean")
    std: float = Field(default=0.0, description="Standard deviation")
    count: int = Field(default=0, ge=0, description="Number of observations")
    time_window: str = Field(default="5m", description="Observation aggregation window")

    @classmethod
    def from_values(cls, values: Sequence[float], time_window: str = "5m") -> "BaselineStats":
        """Compute robust baseline statistics from a sequence of numeric values.

        Args:
            values: Sequence of numbers.
            time_window: Label for the time aggregation window.

        Returns:
            BaselineStats instance.
        """
        clean = [float(v) for v in values if v is not None and not math.isnan(v)]
        if not clean:
            return cls(time_window=time_window)

        n = len(clean)
        med = float(calculate_percentile(clean, 50))
        mad_val = float(calculate_mad(clean))
        p95_val = float(calculate_percentile(clean, 95))
        p99_val = float(calculate_percentile(clean, 99))
        mean_val = float(sum(clean) / n)
        var = sum((x - mean_val) ** 2 for x in clean) / n
        std_val = float(math.sqrt(var))

        return cls(
            median=med,
            mad=mad_val,
            p95=p95_val,
            p99=p99_val,
            mean=mean_val,
            std=std_val,
            count=n,
            time_window=time_window,
        )


def _get_window_bucket(ts: datetime, window_minutes: int) -> int:
    """Compute epoch bucket index for a timestamp."""
    epoch_sec = int(ts.timestamp())
    bucket_sec = window_minutes * 60
    return epoch_sec // bucket_sec


def compute_request_baselines(
    records: List[LogRecord],
    window_minutes: int = 5,
) -> Dict[str, Any]:
    """Compute baseline statistics for request volume and traffic frequency.

    Args:
        records: Ingested log records.
        window_minutes: Window size for bucketing in minutes.

    Returns:
        Dictionary containing request volume baselines and breakdown.
    """
    if not records:
        empty_stats = BaselineStats(time_window=f"{window_minutes}m")
        return {
            "requests_per_window": empty_stats,
            "requests_per_ip_window": empty_stats,
            "total_records": 0,
            "window_minutes": window_minutes,
        }

    # Bucket requests per time window
    window_counts: Dict[int, int] = defaultdict(int)
    # Bucket requests per (IP, time window)
    ip_window_counts: Dict[Tuple[str, int], int] = defaultdict(int)

    for r in records:
        bucket = _get_window_bucket(r.timestamp, window_minutes)
        window_counts[bucket] += 1
        if r.source_ip:
            ip_window_counts[(r.source_ip, bucket)] += 1

    window_vals = list(window_counts.values()) if window_counts else [0.0]
    ip_window_vals = list(ip_window_counts.values()) if ip_window_counts else [0.0]

    return {
        "requests_per_window": BaselineStats.from_values(window_vals, f"{window_minutes}m"),
        "requests_per_ip_window": BaselineStats.from_values(ip_window_vals, f"{window_minutes}m"),
        "total_records": len(records),
        "window_minutes": window_minutes,
    }


def compute_auth_baselines(records: List[LogRecord]) -> Dict[str, Any]:
    """Compute baseline statistics for authentication events and access patterns.

    Args:
        records: Ingested log records.

    Returns:
        Dictionary containing auth failure baselines and hour-of-day distribution.
    """
    if not records:
        empty_stats = BaselineStats(time_window="all")
        return {
            "failed_per_ip": empty_stats,
            "failed_per_user": empty_stats,
            "hourly_counts": {h: 0 for h in range(24)},
            "total_auth_events": 0,
        }

    failed_by_ip: Dict[str, int] = defaultdict(int)
    failed_by_user: Dict[str, int] = defaultdict(int)
    hourly_counts: Dict[int, int] = {h: 0 for h in range(24)}
    auth_events = 0

    for r in records:
        is_auth = False
        is_failure = False

        if r.action and any(w in r.action.upper() for w in ("LOGIN", "AUTH", "LOGON", "SIGNIN")):
            is_auth = True
            if any(f in r.action.upper() for f in ("FAIL", "DENY", "BLOCK", "REJECT")):
                is_failure = True
        elif r.status_code in (401, 403):
            is_auth = True
            is_failure = True

        if is_auth:
            auth_events += 1
            hr = r.timestamp.hour
            hourly_counts[hr] = hourly_counts.get(hr, 0) + 1

        if is_failure:
            if r.source_ip:
                failed_by_ip[r.source_ip] += 1
            if r.username:
                failed_by_user[r.username] += 1

    ip_vals = list(failed_by_ip.values()) if failed_by_ip else [0.0]
    user_vals = list(failed_by_user.values()) if failed_by_user else [0.0]

    return {
        "failed_per_ip": BaselineStats.from_values(ip_vals, "all"),
        "failed_per_user": BaselineStats.from_values(user_vals, "all"),
        "hourly_counts": hourly_counts,
        "total_auth_events": auth_events,
    }


def compute_traffic_baselines(records: List[LogRecord]) -> Dict[str, Any]:
    """Compute baseline statistics for network payload sizes and outbound data.

    Args:
        records: Ingested log records.

    Returns:
        Dictionary containing traffic byte distribution baselines.
    """
    if not records:
        empty_stats = BaselineStats(time_window="all")
        return {
            "bytes_sent": empty_stats,
            "bytes_received": empty_stats,
            "bytes_sent_per_ip": empty_stats,
            "total_bytes_sent": 0,
        }

    bytes_sent_vals = [float(r.bytes_sent or 0) for r in records]
    bytes_rcvd_vals = [float(r.bytes_received or 0) for r in records]

    sent_by_ip: Dict[str, int] = defaultdict(int)
    for r in records:
        if r.source_ip and r.bytes_sent:
            sent_by_ip[r.source_ip] += r.bytes_sent

    sent_ip_vals = [float(v) for v in sent_by_ip.values()] if sent_by_ip else [0.0]

    return {
        "bytes_sent": BaselineStats.from_values(bytes_sent_vals, "per_record"),
        "bytes_received": BaselineStats.from_values(bytes_rcvd_vals, "per_record"),
        "bytes_sent_per_ip": BaselineStats.from_values(sent_ip_vals, "per_source_ip"),
        "total_bytes_sent": sum(bytes_sent_vals),
    }


def compute_status_baselines(records: List[LogRecord]) -> Dict[str, Any]:
    """Compute baseline statistics for HTTP response code distributions.

    Args:
        records: Ingested log records.

    Returns:
        Dictionary containing status code distributions and error rate baselines.
    """
    if not records:
        empty_stats = BaselineStats(time_window="all")
        return {
            "rates": {"2xx": 0.0, "3xx": 0.0, "4xx": 0.0, "5xx": 0.0},
            "counts": {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0},
            "total_http": 0,
            "error_rate_per_ip": empty_stats,
        }

    counts = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    total_http = 0
    ip_errors: Dict[str, int] = defaultdict(int)
    ip_totals: Dict[str, int] = defaultdict(int)

    for r in records:
        if r.status_code is None:
            continue
        code = r.status_code
        total_http += 1
        cat = f"{code // 100}xx"
        if cat in counts:
            counts[cat] += 1

        if r.source_ip:
            ip_totals[r.source_ip] += 1
            if 400 <= code <= 599:
                ip_errors[r.source_ip] += 1

    rates = {}
    for cat, cnt in counts.items():
        rates[cat] = float(cnt / total_http) if total_http > 0 else 0.0

    ip_error_rates = [
        float(ip_errors[ip] / ip_totals[ip])
        for ip in ip_totals
    ] if ip_totals else [0.0]

    return {
        "rates": rates,
        "counts": counts,
        "total_http": total_http,
        "error_rate_per_ip": BaselineStats.from_values(ip_error_rates, "per_ip"),
    }
