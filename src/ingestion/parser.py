"""Log file ingestion and parsing module supporting CSV, JSON, and JSONL formats."""

import csv
import hashlib
import io
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    from ..utils.helpers import generate_id, safe_parse_timestamp
    from ..utils.models import LogRecord, ValidationResult
    from ..utils.security import sanitize_log_input, validate_ip
    from .normalizer import normalize_raw_dict, normalize_record
except ImportError:
    from src.utils.helpers import generate_id, safe_parse_timestamp
    from src.utils.models import LogRecord, ValidationResult
    from src.utils.security import sanitize_log_input, validate_ip
    from src.ingestion.normalizer import normalize_raw_dict, normalize_record

logger = logging.getLogger(__name__)

# Ensure backwards-compatibility aliases for ValidationResult
if not hasattr(ValidationResult, "valid_count"):
    setattr(ValidationResult, "valid_count", property(lambda self: self.valid_records))
if not hasattr(ValidationResult, "invalid_count"):
    setattr(ValidationResult, "invalid_count", property(lambda self: self.invalid_records))


def _read_content_and_name(
    file_path_or_content: Union[str, bytes, Path, io.IOBase],
    source_name: str = "",
) -> Tuple[str, str]:
    """Resolve file_path_or_content into raw text string and source name."""
    if isinstance(file_path_or_content, Path):
        name = source_name or file_path_or_content.name
        content = file_path_or_content.read_text(encoding="utf-8", errors="replace")
        return content, name

    if isinstance(file_path_or_content, str):
        # Check if it looks like a file path on disk without newline
        if "\n" not in file_path_or_content and "\r" not in file_path_or_content:
            p = Path(file_path_or_content)
            if p.is_file():
                name = source_name or p.name
                content = p.read_text(encoding="utf-8", errors="replace")
                return content, name

        return file_path_or_content, (source_name or "in_memory")

    if isinstance(file_path_or_content, bytes):
        return file_path_or_content.decode("utf-8", errors="replace"), (source_name or "in_memory")

    if isinstance(file_path_or_content, io.IOBase):
        raw = file_path_or_content.read()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        return raw, (source_name or getattr(file_path_or_content, "name", "stream"))

    return str(file_path_or_content), (source_name or "unknown")


def _record_hash(raw_line: str, norm_dict: Dict[str, Any]) -> str:
    """Compute content hash for deduplication."""
    core_parts = [
        str(norm_dict.get("timestamp", "")),
        str(norm_dict.get("source_ip", "")),
        str(norm_dict.get("dest_ip", "")),
        str(norm_dict.get("source_port", "")),
        str(norm_dict.get("dest_port", "")),
        str(norm_dict.get("method", "")),
        str(norm_dict.get("url", "")),
        str(norm_dict.get("status_code", "")),
        str(norm_dict.get("username", "")),
    ]
    key = "|".join(core_parts)
    if not any(core_parts):
        key = raw_line.strip()
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _build_log_record(
    norm_dict: Dict[str, Any],
    raw_line: str,
    source_name: str,
    line_number: int,
) -> LogRecord:
    """Construct and validate a LogRecord from normalized field dictionary."""
    ts_val = norm_dict.get("timestamp")
    parsed_ts = safe_parse_timestamp(ts_val)
    if parsed_ts is None:
        raise ValueError(f"Malformed or missing timestamp: {ts_val}")

    src_ip = norm_dict.get("source_ip")
    if src_ip and not validate_ip(str(src_ip)):
        raise ValueError(f"Invalid source IP address: {src_ip}")

    dst_ip = norm_dict.get("dest_ip")
    if dst_ip and not validate_ip(str(dst_ip)):
        raise ValueError(f"Invalid destination IP address: {dst_ip}")

    # Build record without fabricating missing values
    rec = LogRecord(
        record_id=generate_id(),
        timestamp=parsed_ts,
        source_ip=str(src_ip).strip() if src_ip else None,
        dest_ip=str(dst_ip).strip() if dst_ip else None,
        source_port=norm_dict.get("source_port"),
        dest_port=norm_dict.get("dest_port"),
        protocol=norm_dict.get("protocol"),
        method=norm_dict.get("method"),
        url=norm_dict.get("url"),
        status_code=norm_dict.get("status_code"),
        bytes_sent=norm_dict.get("bytes_sent") or 0,
        bytes_received=norm_dict.get("bytes_received") or 0,
        user_agent=norm_dict.get("user_agent"),
        username=norm_dict.get("username"),
        action=norm_dict.get("action"),
        severity_source=norm_dict.get("severity_source"),
        raw_line=raw_line.strip() or json.dumps(norm_dict),
        source_file=source_name,
        line_number=line_number,
    )
    return normalize_record(rec)


def parse_csv(
    file_path_or_content: Union[str, bytes, Path, io.IOBase],
    source_name: str = "",
) -> List[LogRecord]:
    """Parse CSV format log data into LogRecord models.

    Args:
        file_path_or_content: File path, path object, or raw CSV string/bytes.
        source_name: Optional origin identifier.

    Returns:
        List of successfully parsed and normalized LogRecord objects.
    """
    records, _ = _parse_csv_internal(file_path_or_content, source_name)
    return records


def _parse_csv_internal(
    file_path_or_content: Union[str, bytes, Path, io.IOBase],
    source_name: str = "",
) -> Tuple[List[LogRecord], ValidationResult]:
    """Internal CSV parser returning records and detailed ValidationResult."""
    content, name = _read_content_and_name(file_path_or_content, source_name)

    records: List[LogRecord] = []
    malformed: List[Dict[str, Any]] = []
    seen_hashes: Set[str] = set()
    dup_count = 0
    headers_found: List[str] = []

    lines = content.splitlines()
    if not lines:
        return [], ValidationResult(
            valid_records=0,
            invalid_records=0,
            malformed_details=[],
            duplicate_count=0,
            schema_info={"format": "csv", "total_lines": 0},
        )

    # Sniff dialect or fallback to standard comma delimiter
    sample = "\n".join(lines[:10])
    try:
        sniffer = csv.Sniffer()
        dialect = sniffer.sniff(sample)
    except Exception:
        dialect = csv.excel

    reader = csv.DictReader(lines, dialect=dialect)
    headers_found = list(reader.fieldnames or [])

    for line_idx, row in enumerate(reader, start=2):
        raw_line = lines[line_idx - 1] if line_idx - 1 < len(lines) else str(row)
        if not any(v for v in row.values() if v is not None and v.strip() != ""):
            continue

        try:
            norm_dict = normalize_raw_dict(row)
            rec_hash = _record_hash(raw_line, norm_dict)
            if rec_hash in seen_hashes:
                dup_count += 1
                continue
            seen_hashes.add(rec_hash)

            record = _build_log_record(norm_dict, raw_line, name, line_idx)
            records.append(record)
        except Exception as e:
            malformed.append(
                {
                    "line_number": line_idx,
                    "raw_line": raw_line[:200],
                    "reason": str(e),
                }
            )

    result = ValidationResult(
        valid_records=len(records),
        invalid_records=len(malformed),
        malformed_details=malformed,
        duplicate_count=dup_count,
        schema_info={
            "format": "csv",
            "source": name,
            "headers": headers_found,
            "total_lines": len(lines),
        },
    )
    return records, result


def parse_json(
    file_path_or_content: Union[str, bytes, Path, io.IOBase],
    source_name: str = "",
) -> List[LogRecord]:
    """Parse JSON format log data into LogRecord models.

    Args:
        file_path_or_content: File path, path object, or raw JSON string/bytes.
        source_name: Optional origin identifier.

    Returns:
        List of successfully parsed LogRecord objects.
    """
    records, _ = _parse_json_internal(file_path_or_content, source_name)
    return records


def _parse_json_internal(
    file_path_or_content: Union[str, bytes, Path, io.IOBase],
    source_name: str = "",
) -> Tuple[List[LogRecord], ValidationResult]:
    """Internal JSON parser returning records and detailed ValidationResult."""
    content, name = _read_content_and_name(file_path_or_content, source_name)

    records: List[LogRecord] = []
    malformed: List[Dict[str, Any]] = []
    seen_hashes: Set[str] = set()
    dup_count = 0

    stripped = content.strip()
    if not stripped:
        return [], ValidationResult(
            valid_records=0,
            invalid_records=0,
            malformed_details=[],
            duplicate_count=0,
            schema_info={"format": "json", "total_records": 0},
        )

    try:
        parsed_data = json.loads(stripped)
    except Exception as e:
        return [], ValidationResult(
            valid_records=0,
            invalid_records=1,
            malformed_details=[{"line_number": 1, "raw_line": stripped[:200], "reason": f"Invalid JSON syntax: {e}"}],
            duplicate_count=0,
            schema_info={"format": "json", "source": name, "parse_error": str(e)},
        )

    # Normalize parsed data into a list of dictionaries
    if isinstance(parsed_data, list):
        items = parsed_data
    elif isinstance(parsed_data, dict):
        for candidate_key in ("records", "logs", "events", "data", "items"):
            if candidate_key in parsed_data and isinstance(parsed_data[candidate_key], list):
                items = parsed_data[candidate_key]
                break
        else:
            items = [parsed_data]
    else:
        items = []

    for idx, item in enumerate(items, start=1):
        raw_repr = json.dumps(item) if isinstance(item, (dict, list)) else str(item)
        if not isinstance(item, dict):
            malformed.append(
                {
                    "line_number": idx,
                    "raw_line": raw_repr[:200],
                    "reason": "Expected JSON object for log item",
                }
            )
            continue

        try:
            norm_dict = normalize_raw_dict(item)
            rec_hash = _record_hash(raw_repr, norm_dict)
            if rec_hash in seen_hashes:
                dup_count += 1
                continue
            seen_hashes.add(rec_hash)

            record = _build_log_record(norm_dict, raw_repr, name, idx)
            records.append(record)
        except Exception as e:
            malformed.append(
                {
                    "line_number": idx,
                    "raw_line": raw_repr[:200],
                    "reason": str(e),
                }
            )

    result = ValidationResult(
        valid_records=len(records),
        invalid_records=len(malformed),
        malformed_details=malformed,
        duplicate_count=dup_count,
        schema_info={
            "format": "json",
            "source": name,
            "total_items": len(items),
        },
    )
    return records, result


def parse_jsonl(
    file_path_or_content: Union[str, bytes, Path, io.IOBase],
    source_name: str = "",
) -> List[LogRecord]:
    """Parse JSONL (JSON Lines) log data into LogRecord models.

    Args:
        file_path_or_content: File path, path object, or raw JSONL string/bytes.
        source_name: Optional origin identifier.

    Returns:
        List of parsed LogRecord objects.
    """
    records, _ = _parse_jsonl_internal(file_path_or_content, source_name)
    return records


def _parse_jsonl_internal(
    file_path_or_content: Union[str, bytes, Path, io.IOBase],
    source_name: str = "",
) -> Tuple[List[LogRecord], ValidationResult]:
    """Internal JSONL parser returning records and detailed ValidationResult."""
    content, name = _read_content_and_name(file_path_or_content, source_name)

    records: List[LogRecord] = []
    malformed: List[Dict[str, Any]] = []
    seen_hashes: Set[str] = set()
    dup_count = 0

    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        clean_line = line.strip()
        if not clean_line:
            continue

        try:
            item = json.loads(clean_line)
            if not isinstance(item, dict):
                raise ValueError("JSON line is not an object/dictionary")

            norm_dict = normalize_raw_dict(item)
            rec_hash = _record_hash(clean_line, norm_dict)
            if rec_hash in seen_hashes:
                dup_count += 1
                continue
            seen_hashes.add(rec_hash)

            record = _build_log_record(norm_dict, clean_line, name, line_idx)
            records.append(record)
        except Exception as e:
            malformed.append(
                {
                    "line_number": line_idx,
                    "raw_line": clean_line[:200],
                    "reason": str(e),
                }
            )

    result = ValidationResult(
        valid_records=len(records),
        invalid_records=len(malformed),
        malformed_details=malformed,
        duplicate_count=dup_count,
        schema_info={
            "format": "jsonl",
            "source": name,
            "total_lines": len(lines),
        },
    )
    return records, result


def _detect_file_type(content: str, filename: str, file_type: Optional[str] = None) -> str:
    """Infer file type from user hint, filename, or content."""
    if file_type:
        fmt = file_type.strip().lower().lstrip(".")
        if fmt in ("csv", "json", "jsonl", "ndjson"):
            return "jsonl" if fmt == "ndjson" else fmt

    lower_name = filename.lower()
    if lower_name.endswith(".csv"):
        return "csv"
    if lower_name.endswith(".jsonl") or lower_name.endswith(".ndjson"):
        return "jsonl"
    if lower_name.endswith(".json"):
        return "json"

    # Content heuristic
    stripped = content.strip()
    if stripped.startswith("["):
        return "json"
    if stripped.startswith("{"):
        first_line = stripped.split("\n", 1)[0].strip()
        try:
            json.loads(first_line)
            if "\n" in stripped:
                return "jsonl"
            return "json"
        except Exception:
            return "json"

    return "csv"


def ingest_file(
    file_path: Union[str, Path],
    file_type: Optional[str] = None,
) -> Tuple[List[LogRecord], ValidationResult]:
    """Ingest a log file from disk and return parsed records and validation metrics.

    Args:
        file_path: Filesystem path to log file.
        file_type: Optional explicit file type ("csv", "json", "jsonl").

    Returns:
        Tuple of (list of LogRecords, ValidationResult).
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    content = path.read_text(encoding="utf-8", errors="replace")
    resolved_type = _detect_file_type(content, path.name, file_type)

    if resolved_type == "csv":
        return _parse_csv_internal(content, path.name)
    elif resolved_type == "jsonl":
        return _parse_jsonl_internal(content, path.name)
    elif resolved_type == "json":
        return _parse_json_internal(content, path.name)
    else:
        return _parse_csv_internal(content, path.name)


def ingest_content(
    content: Union[str, bytes],
    filename: str,
    file_type: Optional[str] = None,
) -> Tuple[List[LogRecord], ValidationResult]:
    """Ingest raw log text or bytes in memory with validation report.

    Args:
        content: Raw log content string or bytes.
        filename: Associated source filename.
        file_type: Optional explicit file type ("csv", "json", "jsonl").

    Returns:
        Tuple of (list of LogRecords, ValidationResult).
    """
    if isinstance(content, bytes):
        text_content = content.decode("utf-8", errors="replace")
    else:
        text_content = content

    resolved_type = _detect_file_type(text_content, filename, file_type)

    if resolved_type == "csv":
        return _parse_csv_internal(text_content, filename)
    elif resolved_type == "jsonl":
        return _parse_jsonl_internal(text_content, filename)
    elif resolved_type == "json":
        return _parse_json_internal(text_content, filename)
    else:
        return _parse_csv_internal(text_content, filename)
