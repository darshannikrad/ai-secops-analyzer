"""Unit tests for log ingestion, normalization, and parsing."""

import json
from datetime import datetime, timezone
from pathlib import Path

from src.ingestion.normalizer import normalize_record, normalize_records
from src.ingestion.parser import (
    ingest_content,
    ingest_file,
    parse_csv,
    parse_json,
    parse_jsonl,
)
from src.utils.models import LogRecord, ValidationResult


def test_parse_csv_basic():
    csv_content = """timestamp,src_ip,dst_ip,method,url,status,bytes_out
2026-10-12T10:00:00Z,192.168.1.10,10.0.0.1,GET,/index.html,200,1024
2026-10-12T10:00:01Z,192.168.1.11,10.0.0.1,POST,/login,401,512
"""
    records = parse_csv(csv_content, source_name="test.csv")
    assert len(records) == 2
    assert records[0].source_ip == "192.168.1.10"
    assert records[0].dest_ip == "10.0.0.1"
    assert records[0].method == "GET"
    assert records[0].status_code == 200
    assert records[0].bytes_sent == 1024
    assert records[0].source_file == "test.csv"
    assert records[0].line_number == 2
    assert records[1].status_code == 401


def test_parse_json_array_and_envelope():
    json_array = json.dumps([
        {"timestamp": "2026-10-12T10:00:00Z", "source_ip": "1.2.3.4", "url": "/api/v1"},
        {"timestamp": "2026-10-12T10:00:05Z", "source_ip": "1.2.3.5", "url": "/api/v2"},
    ])
    recs = parse_json(json_array, source_name="array.json")
    assert len(recs) == 2
    assert recs[0].source_ip == "1.2.3.4"

    json_envelope = json.dumps({
        "events": [
            {"timestamp": "2026-10-12T10:00:10Z", "src": "10.10.10.1", "action": "ALLOW"}
        ]
    })
    recs_env = parse_json(json_envelope, source_name="env.json")
    assert len(recs_env) == 1
    assert recs_env[0].source_ip == "10.10.10.1"
    assert recs_env[0].action == "ALLOW"


def test_parse_jsonl():
    lines = "\n".join([
        json.dumps({"timestamp": "2026-10-12T10:00:00Z", "src_ip": "172.16.0.5", "dport": 80}),
        json.dumps({"timestamp": "2026-10-12T10:00:01Z", "src_ip": "172.16.0.6", "dport": 443}),
    ])
    recs = parse_jsonl(lines, source_name="stream.jsonl")
    assert len(recs) == 2
    assert recs[0].source_ip == "172.16.0.5"
    assert recs[0].dest_port == 80
    assert recs[1].dest_port == 443


def test_ingest_content_with_validation_and_deduplication():
    # Duplicate line included
    csv_data = """timestamp,src_ip,method,url
2026-10-12T10:00:00Z,192.168.1.100,GET,/test
2026-10-12T10:00:00Z,192.168.1.100,GET,/test
INVALID_LINE_NO_TIMESTAMP
"""
    records, val = ingest_content(csv_data, filename="sample.csv", file_type="csv")
    assert len(records) == 1
    assert val.valid_records == 1
    assert val.duplicate_count == 1
    assert val.invalid_records == 1
    assert len(val.malformed_details) == 1
    assert val.malformed_details[0]["line_number"] == 4


def test_normalization():
    rec = LogRecord(
        timestamp="2026-10-12 12:00:00",
        source_ip="  192.168.1.1  ",
        protocol="tcp",
        method="get",
        url="/test/path  ",
        status_code=200,
        raw_line="sample line",
    )
    normalized = normalize_record(rec)
    assert normalized.source_ip == "192.168.1.1"
    assert normalized.protocol == "TCP"
    assert normalized.method == "GET"
    assert normalized.url == "/test/path"
    assert normalized.timestamp.tzinfo == timezone.utc
