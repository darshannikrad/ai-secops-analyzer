"""Common helper functions for data manipulation, statistical calculations, and parsing."""

import math
import uuid
from datetime import datetime, timezone
from typing import Any, Generator, List, Optional, Sequence

from dateutil import parser as date_parser


def generate_id() -> str:
    """Generate a unique UUID4 string identifier.

    Returns:
        UUID4 hex string.
    """
    return str(uuid.uuid4())


def safe_parse_timestamp(ts_string: Any) -> Optional[datetime]:
    """Parse various timestamp representations into a UTC timezone-aware datetime.

    Supports ISO 8601, Apache log format, Syslog format, and Unix epoch seconds/milliseconds.

    Args:
        ts_string: Raw string, integer, float, or datetime.

    Returns:
        timezone-aware datetime in UTC, or None if parsing fails.
    """
    if ts_string is None:
        return None

    if isinstance(ts_string, datetime):
        if ts_string.tzinfo is None:
            return ts_string.replace(tzinfo=timezone.utc)
        return ts_string.astimezone(timezone.utc)

    # Check for Unix epoch numeric types or numeric string
    if isinstance(ts_string, (int, float)):
        try:
            val = float(ts_string)
            # If greater than 1e11, likely milliseconds
            if val > 1e11:
                val = val / 1000.0
            return datetime.fromtimestamp(val, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None

    if not isinstance(ts_string, str):
        return None

    s = ts_string.strip(" []\"'")
    if not s:
        return None

    # Check if purely digits (epoch)
    try:
        val = float(s)
        if val > 1e11:
            val = val / 1000.0
        return datetime.fromtimestamp(val, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass

    # Try Apache / Nginx Common Log Format: '10/Oct/2000:13:55:36 -0700'
    for clf_fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            dt = datetime.strptime(s, clf_fmt)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

    # Generic dateutil parsing fallback
    try:
        dt = date_parser.parse(s)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, OverflowError, TypeError):
        return None


def calculate_mad(values: Sequence[float]) -> float:
    """Calculate the Median Absolute Deviation (MAD) of a numeric sequence.

    MAD = median(|X_i - median(X)|)

    Args:
        values: Sequence of numeric values.

    Returns:
        The median absolute deviation as a float, or 0.0 if empty.
    """
    clean_vals = [float(v) for v in values if v is not None and not math.isnan(v)]
    if not clean_vals:
        return 0.0

    sorted_vals = sorted(clean_vals)
    n = len(sorted_vals)

    def _median(arr: List[float]) -> float:
        m = len(arr)
        mid = m // 2
        if m % 2 == 1:
            return arr[mid]
        return (arr[mid - 1] + arr[mid]) / 2.0

    med = _median(sorted_vals)
    abs_deviations = sorted(abs(x - med) for x in sorted_vals)
    return _median(abs_deviations)


def calculate_percentile(values: Sequence[float], p: float) -> float:
    """Calculate the p-th percentile of a sequence using linear interpolation.

    Args:
        values: Sequence of numeric values.
        p: Percentile value between 0 and 100 inclusive.

    Returns:
        Percentile value as float, or 0.0 if sequence is empty.
    """
    clean_vals = [float(v) for v in values if v is not None and not math.isnan(v)]
    if not clean_vals:
        return 0.0

    if p <= 0:
        return min(clean_vals)
    if p >= 100:
        return max(clean_vals)

    sorted_vals = sorted(clean_vals)
    n = len(sorted_vals)
    k = (n - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)

    if f == c:
        return sorted_vals[int(k)]

    d0 = sorted_vals[int(f)] * (c - k)
    d1 = sorted_vals[int(c)] * (k - f)
    return d0 + d1


def robust_zscore(value: float, median: float, mad: float) -> float:
    """Calculate the modified robust Z-score based on median and MAD.

    Score = 0.6745 * (value - median) / MAD
    The 0.6745 scaling factor makes MAD an estimator of normal distribution standard deviation.

    Args:
        value: Candidate metric value.
        median: Baseline median.
        mad: Baseline Median Absolute Deviation.

    Returns:
        Calculated modified z-score, or 0.0 if MAD is zero.
    """
    if mad <= 0.0:
        return 0.0
    return 0.6745 * (value - median) / mad


def chunk_list(lst: Sequence[Any], size: int) -> Generator[Sequence[Any], None, None]:
    """Yield successive chunks of given size from a list or sequence.

    Args:
        lst: Sequence to slice.
        size: Maximum size of each chunk (must be >= 1).

    Yields:
        Chunks of length up to `size`.
    """
    if size <= 0:
        raise ValueError("Chunk size must be positive and non-zero")

    for i in range(0, len(lst), size):
        yield lst[i : i + size]
