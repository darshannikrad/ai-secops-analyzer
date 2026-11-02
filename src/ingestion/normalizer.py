"""Schema normalization and standardization for ingested log records."""

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from ..utils.helpers import safe_parse_timestamp
    from ..utils.models import LogRecord
    from ..utils.security import sanitize_log_input, validate_ip
except ImportError:
    from src.utils.helpers import safe_parse_timestamp
    from src.utils.models import LogRecord
    from src.utils.security import sanitize_log_input, validate_ip

logger = logging.getLogger(__name__)

# Mapping of common raw field name variants to canonical LogRecord field names
FIELD_NAME_VARIANTS: Dict[str, str] = {
    # Source IP
    "src": "source_ip",
    "src_ip": "source_ip",
    "srcip": "source_ip",
    "source": "source_ip",
    "source_ip": "source_ip",
    "source_address": "source_ip",
    "sourceip": "source_ip",
    "client_ip": "source_ip",
    "clientip": "source_ip",
    "c_ip": "source_ip",
    "c-ip": "source_ip",
    "remote_ip": "source_ip",
    "remote_addr": "source_ip",
    "origin_ip": "source_ip",
    "ip": "source_ip",
    "host": "source_ip",
    # Destination IP
    "dst": "dest_ip",
    "dst_ip": "dest_ip",
    "dstip": "dest_ip",
    "dest": "dest_ip",
    "dest_ip": "dest_ip",
    "destination": "dest_ip",
    "destination_ip": "dest_ip",
    "destination_address": "dest_ip",
    "server_ip": "dest_ip",
    "serverip": "dest_ip",
    "s_ip": "dest_ip",
    "s-ip": "dest_ip",
    "target_ip": "dest_ip",
    # Source Port
    "src_port": "source_port",
    "srcport": "source_port",
    "source_port": "source_port",
    "s_port": "source_port",
    "s-port": "source_port",
    "client_port": "source_port",
    "clientport": "source_port",
    "sport": "source_port",
    # Destination Port
    "dst_port": "dest_port",
    "dstport": "dest_port",
    "dest_port": "dest_port",
    "destination_port": "dest_port",
    "d_port": "dest_port",
    "d-port": "dest_port",
    "server_port": "dest_port",
    "serverport": "dest_port",
    "dport": "dest_port",
    "port": "dest_port",
    # Protocol
    "proto": "protocol",
    "protocol": "protocol",
    "transport": "protocol",
    "network_protocol": "protocol",
    # HTTP Method
    "http_method": "method",
    "req_method": "method",
    "request_method": "method",
    "verb": "method",
    "method": "method",
    # URL / URI
    "uri": "url",
    "request_uri": "url",
    "request_url": "url",
    "path": "url",
    "request_path": "url",
    "request": "url",
    "endpoint": "url",
    "url": "url",
    "cs_uri_stem": "url",
    "cs-method": "method",
    "cs-uri-stem": "url",
    "cs-uri-query": "query",
    # Status Code
    "status": "status_code",
    "http_status": "status_code",
    "sc_status": "status_code",
    "sc-status": "status_code",
    "response_code": "status_code",
    "status_code": "status_code",
    "code": "status_code",
    # Bytes Sent (outbound / server to client)
    "bytes_out": "bytes_sent",
    "bytesout": "bytes_sent",
    "sent_bytes": "bytes_sent",
    "sc_bytes": "bytes_sent",
    "sc-bytes": "bytes_sent",
    "out_bytes": "bytes_sent",
    "tx_bytes": "bytes_sent",
    "bytes_sent": "bytes_sent",
    "body_bytes_sent": "bytes_sent",
    # Bytes Received (inbound / client to server)
    "bytes_in": "bytes_received",
    "bytesin": "bytes_received",
    "rcvd_bytes": "bytes_received",
    "cs_bytes": "bytes_received",
    "cs-bytes": "bytes_received",
    "in_bytes": "bytes_received",
    "rx_bytes": "bytes_received",
    "bytes_received": "bytes_received",
    # User Agent
    "user_agent": "user_agent",
    "useragent": "user_agent",
    "http_user_agent": "user_agent",
    "cs_user_agent": "user_agent",
    "cs(user-agent)": "user_agent",
    "agent": "user_agent",
    # Username / Account
    "user": "username",
    "user_name": "username",
    "username": "username",
    "login": "username",
    "account": "username",
    "src_user": "username",
    "usr": "username",
    "principal": "username",
    # Action
    "act": "action",
    "action": "action",
    "event_action": "action",
    "result": "action",
    "status_message": "action",
    "outcome": "action",
    "decision": "action",
    # Timestamp
    "time": "timestamp",
    "timestamp": "timestamp",
    "event_time": "timestamp",
    "datetime": "timestamp",
    "@timestamp": "timestamp",
    "date": "timestamp",
    "log_time": "timestamp",
}


def normalize_ip(ip_val: Optional[Any]) -> Optional[str]:
    """Normalize IP address string into canonical format.

    Args:
        ip_val: Raw IP string or object.

    Returns:
        Canonical IP address string, or None if invalid/empty.
    """
    if ip_val is None:
        return None

    raw_ip = str(ip_val).strip().strip("[]\"'")
    if not raw_ip or raw_ip in ("-", "null", "none", "unknown"):
        return None

    try:
        parsed = ipaddress.ip_address(raw_ip)
        return str(parsed)
    except ValueError:
        if validate_ip(raw_ip):
            return raw_ip
        return raw_ip


def normalize_timestamp(ts_val: Any) -> Optional[datetime]:
    """Ensure timestamp is a timezone-aware UTC datetime.

    Args:
        ts_val: Raw timestamp value (str, int, float, or datetime).

    Returns:
        Timezone-aware datetime in UTC, or None if unparseable.
    """
    if ts_val is None:
        return None

    if isinstance(ts_val, datetime):
        if ts_val.tzinfo is None:
            return ts_val.replace(tzinfo=timezone.utc)
        return ts_val.astimezone(timezone.utc)

    return safe_parse_timestamp(ts_val)


def normalize_port(port_val: Any) -> Optional[int]:
    """Normalize port value to integer in range 0..65535.

    Args:
        port_val: Raw port value.

    Returns:
        Integer port or None if invalid.
    """
    if port_val is None:
        return None

    try:
        p = int(port_val)
        if 0 <= p <= 65535:
            return p
    except (ValueError, TypeError):
        pass
    return None


def normalize_int(val: Any, default: Optional[int] = 0) -> Optional[int]:
    """Safely convert value to non-negative integer.

    Args:
        val: Raw input value.
        default: Default fallback value.

    Returns:
        Integer value or default.
    """
    if val is None or val == "" or val == "-":
        return default

    try:
        converted = int(val)
        return max(0, converted)
    except (ValueError, TypeError):
        try:
            return max(0, int(float(val)))
        except (ValueError, TypeError):
            return default


def normalize_raw_dict(raw_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Map raw dictionary keys using common field name variants.

    Args:
        raw_dict: Arbitrary raw log dictionary.

    Returns:
        Dictionary with mapped canonical keys.
    """
    normalized: Dict[str, Any] = {}

    for k, v in raw_dict.items():
        clean_key = k.strip().lower()
        canonical_key = FIELD_NAME_VARIANTS.get(clean_key, clean_key)
        # Avoid overwriting already matched canonical keys with lower priority variants
        if canonical_key not in normalized or normalized[canonical_key] is None:
            normalized[canonical_key] = v

    # Special handling: if 'bytes' was present but neither bytes_sent nor bytes_received
    if "bytes" in raw_dict and "bytes_sent" not in normalized:
        normalized["bytes_sent"] = raw_dict["bytes"]

    return normalized


def normalize_record(record: LogRecord) -> LogRecord:
    """Normalize a single LogRecord in-place or returning updated copy.

    Args:
        record: Input LogRecord.

    Returns:
        Normalized LogRecord instance.
    """
    # 1. Timestamp UTC normalization
    norm_ts = normalize_timestamp(record.timestamp) or record.timestamp

    # 2. IP normalization
    norm_src_ip = normalize_ip(record.source_ip)
    norm_dst_ip = normalize_ip(record.dest_ip)

    # 3. Ports normalization
    norm_src_port = normalize_port(record.source_port)
    norm_dst_port = normalize_port(record.dest_port)

    # 4. String cleaning
    norm_protocol = record.protocol.strip().upper() if record.protocol else None
    norm_method = record.method.strip().upper() if record.method else None
    norm_url = record.url.strip() if record.url else None
    norm_user_agent = sanitize_log_input(record.user_agent) if record.user_agent else None
    norm_username = record.username.strip() if record.username else None
    norm_action = record.action.strip().upper() if record.action else None

    # Status code
    norm_status = normalize_int(record.status_code, default=None)
    if norm_status is not None and not (100 <= norm_status <= 599):
        norm_status = None

    # Bytes
    norm_bytes_sent = normalize_int(record.bytes_sent, default=0)
    norm_bytes_rcvd = normalize_int(record.bytes_received, default=0)

    return record.model_copy(
        update={
            "timestamp": norm_ts,
            "source_ip": norm_src_ip,
            "dest_ip": norm_dst_ip,
            "source_port": norm_src_port,
            "dest_port": norm_dst_port,
            "protocol": norm_protocol,
            "method": norm_method,
            "url": norm_url,
            "status_code": norm_status,
            "bytes_sent": norm_bytes_sent,
            "bytes_received": norm_bytes_rcvd,
            "user_agent": norm_user_agent,
            "username": norm_username,
            "action": norm_action,
        }
    )


def normalize_records(records: List[LogRecord]) -> List[LogRecord]:
    """Normalize a list of LogRecord models.

    Standardizes timestamps to UTC, IPs to canonical format, and cleans string fields.

    Args:
        records: List of LogRecord models.

    Returns:
        List of normalized LogRecord models.
    """
    normalized_list: List[LogRecord] = []
    for rec in records:
        try:
            normalized_list.append(normalize_record(rec))
        except Exception as e:
            logger.warning("Failed to normalize record %s: %s", getattr(rec, "record_id", "unknown"), e)
            normalized_list.append(rec)
    return normalized_list
