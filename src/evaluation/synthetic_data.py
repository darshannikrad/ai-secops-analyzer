"""
Synthetic dataset generator with ground-truth labels.

Generates deterministic test datasets with known attack patterns embedded
in normal traffic. Ground-truth labels are stored separately to prevent leakage.
Uses fixed random seeds for reproducibility.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import random
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Fixed seed for reproducibility
DEFAULT_SEED = 42


def generate_normal_traffic(
    count: int = 500,
    start_time: datetime | None = None,
    seed: int = DEFAULT_SEED,
) -> list[dict]:
    """Generate normal web traffic log records."""
    rng = random.Random(seed)
    if start_time is None:
        start_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)

    normal_ips = [f"192.168.1.{i}" for i in range(10, 60)]
    server_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    normal_urls = [
        "/index.html", "/api/users", "/api/products", "/login",
        "/dashboard", "/api/orders", "/static/css/main.css",
        "/static/js/app.js", "/api/health", "/about", "/contact",
        "/api/v1/search", "/api/v1/profile", "/favicon.ico",
    ]
    methods = ["GET", "GET", "GET", "GET", "POST", "POST", "PUT", "DELETE"]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1",
        "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
    ]
    usernames = [f"user_{i}" for i in range(1, 21)]

    records = []
    for i in range(count):
        ts = start_time + timedelta(seconds=rng.randint(0, 28800))  # 8 hours
        records.append({
            "timestamp": ts.isoformat(),
            "source_ip": rng.choice(normal_ips),
            "dest_ip": rng.choice(server_ips),
            "source_port": rng.randint(1024, 65535),
            "dest_port": rng.choice([80, 443, 8080]),
            "protocol": "TCP",
            "method": rng.choice(methods),
            "url": rng.choice(normal_urls),
            "status_code": rng.choices([200, 200, 200, 301, 304, 404], weights=[50, 20, 10, 5, 10, 5])[0],
            "bytes_sent": rng.randint(100, 5000),
            "bytes_received": rng.randint(200, 15000),
            "user_agent": rng.choice(user_agents),
            "username": rng.choice(usernames) if rng.random() > 0.3 else "",
            "action": "request",
        })

    return records


def generate_dos_attack(
    start_time: datetime | None = None,
    seed: int = DEFAULT_SEED + 1,
) -> tuple[list[dict], list[dict]]:
    """
    Generate DoS attack pattern.
    Returns (attack_records, ground_truth_labels).
    """
    rng = random.Random(seed)
    if start_time is None:
        start_time = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

    attacker_ip = "203.0.113.50"
    target_ip = "10.0.0.1"
    records = []
    labels = []

    # Rapid requests from single IP (200 requests in 2 minutes)
    for i in range(200):
        ts = start_time + timedelta(seconds=rng.uniform(0, 120))
        record_id = f"dos_{i}"
        records.append({
            "timestamp": ts.isoformat(),
            "source_ip": attacker_ip,
            "dest_ip": target_ip,
            "source_port": rng.randint(1024, 65535),
            "dest_port": 80,
            "protocol": "TCP",
            "method": "GET",
            "url": f"/api/heavy-endpoint?id={rng.randint(1, 1000)}",
            "status_code": rng.choices([200, 503, 429], weights=[30, 50, 20])[0],
            "bytes_sent": rng.randint(100, 300),
            "bytes_received": rng.randint(50, 500),
            "user_agent": "python-requests/2.31.0",
            "username": "",
            "action": "request",
            "_record_id_hint": record_id,
        })
        labels.append({
            "record_id_hint": record_id,
            "is_malicious": True,
            "attack_type": "DOS",
            "attacker_ip": attacker_ip,
            "description": "DoS flood from single source",
        })

    return records, labels


def generate_brute_force_attack(
    start_time: datetime | None = None,
    seed: int = DEFAULT_SEED + 2,
) -> tuple[list[dict], list[dict]]:
    """Generate brute force authentication attack pattern."""
    rng = random.Random(seed)
    if start_time is None:
        start_time = datetime(2024, 1, 15, 11, 0, 0, tzinfo=timezone.utc)

    attacker_ip = "198.51.100.23"
    target_ip = "10.0.0.2"
    target_users = [f"admin", "root", "administrator", "test", "user", "guest"]
    records = []
    labels = []

    # 80 failed login attempts, then 1 success
    for i in range(80):
        ts = start_time + timedelta(seconds=rng.uniform(0, 600))
        record_id = f"bf_{i}"
        records.append({
            "timestamp": ts.isoformat(),
            "source_ip": attacker_ip,
            "dest_ip": target_ip,
            "source_port": rng.randint(1024, 65535),
            "dest_port": 443,
            "protocol": "TCP",
            "method": "POST",
            "url": "/api/auth/login",
            "status_code": 401,
            "bytes_sent": rng.randint(200, 400),
            "bytes_received": rng.randint(100, 200),
            "user_agent": "curl/8.4.0",
            "username": rng.choice(target_users),
            "action": "login_failed",
            "_record_id_hint": record_id,
        })
        labels.append({
            "record_id_hint": record_id,
            "is_malicious": True,
            "attack_type": "BRUTE_FORCE",
            "attacker_ip": attacker_ip,
            "description": "Brute force authentication attempt",
        })

    # Successful login after brute force
    ts = start_time + timedelta(seconds=620)
    records.append({
        "timestamp": ts.isoformat(),
        "source_ip": attacker_ip,
        "dest_ip": target_ip,
        "source_port": rng.randint(1024, 65535),
        "dest_port": 443,
        "protocol": "TCP",
        "method": "POST",
        "url": "/api/auth/login",
        "status_code": 200,
        "bytes_sent": 350,
        "bytes_received": 1200,
        "user_agent": "curl/8.4.0",
        "username": "admin",
        "action": "login_success",
        "_record_id_hint": "bf_success",
    })
    labels.append({
        "record_id_hint": "bf_success",
        "is_malicious": True,
        "attack_type": "BRUTE_FORCE",
        "attacker_ip": attacker_ip,
        "description": "Successful login after brute force",
    })

    return records, labels


def generate_port_scan(
    start_time: datetime | None = None,
    seed: int = DEFAULT_SEED + 3,
) -> tuple[list[dict], list[dict]]:
    """Generate port scanning pattern."""
    rng = random.Random(seed)
    if start_time is None:
        start_time = datetime(2024, 1, 15, 9, 15, 0, tzinfo=timezone.utc)

    scanner_ip = "192.0.2.100"
    target_ip = "10.0.0.1"
    common_ports = list(range(1, 1025)) + [3306, 5432, 6379, 8080, 8443, 9200]
    records = []
    labels = []

    # Scan 100 ports
    scanned_ports = rng.sample(common_ports, min(100, len(common_ports)))
    for i, port in enumerate(scanned_ports):
        ts = start_time + timedelta(seconds=i * 0.5)
        record_id = f"scan_{i}"
        records.append({
            "timestamp": ts.isoformat(),
            "source_ip": scanner_ip,
            "dest_ip": target_ip,
            "source_port": rng.randint(1024, 65535),
            "dest_port": port,
            "protocol": "TCP",
            "method": "",
            "url": "",
            "status_code": 0,
            "bytes_sent": rng.randint(40, 80),
            "bytes_received": rng.choices([0, 40], weights=[70, 30])[0],
            "user_agent": "",
            "username": "",
            "action": "connection_attempt",
            "_record_id_hint": record_id,
        })
        labels.append({
            "record_id_hint": record_id,
            "is_malicious": True,
            "attack_type": "PORT_SCAN",
            "attacker_ip": scanner_ip,
            "description": f"Port scan probe to port {port}",
        })

    return records, labels


def generate_path_traversal_attack(
    start_time: datetime | None = None,
    seed: int = DEFAULT_SEED + 4,
) -> tuple[list[dict], list[dict]]:
    """Generate path traversal attack pattern."""
    rng = random.Random(seed)
    if start_time is None:
        start_time = datetime(2024, 1, 15, 14, 0, 0, tzinfo=timezone.utc)

    attacker_ip = "203.0.113.75"
    target_ip = "10.0.0.3"
    traversal_urls = [
        "/files/../../../etc/passwd",
        "/download?file=../../../etc/shadow",
        "/api/read?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/static/..%2f..%2f..%2fetc%2fhosts",
        "/files/....//....//etc/passwd",
        "/download?file=..\\..\\..\\windows\\system32\\config\\sam",
        "/api/file?name=../../config/database.yml",
        "/images/../../../proc/self/environ",
    ]
    records = []
    labels = []

    for i, url in enumerate(traversal_urls):
        ts = start_time + timedelta(seconds=rng.uniform(0, 300))
        record_id = f"trav_{i}"
        records.append({
            "timestamp": ts.isoformat(),
            "source_ip": attacker_ip,
            "dest_ip": target_ip,
            "source_port": rng.randint(1024, 65535),
            "dest_port": 443,
            "protocol": "TCP",
            "method": "GET",
            "url": url,
            "status_code": rng.choices([200, 403, 404, 500], weights=[10, 40, 30, 20])[0],
            "bytes_sent": rng.randint(100, 300),
            "bytes_received": rng.randint(50, 5000),
            "user_agent": "Mozilla/5.0 (compatible; attacker/1.0)",
            "username": "",
            "action": "request",
            "_record_id_hint": record_id,
        })
        labels.append({
            "record_id_hint": record_id,
            "is_malicious": True,
            "attack_type": "PATH_TRAVERSAL",
            "attacker_ip": attacker_ip,
            "description": f"Path traversal attempt: {url[:80]}",
        })

    return records, labels


def generate_sql_injection_attack(
    start_time: datetime | None = None,
    seed: int = DEFAULT_SEED + 5,
) -> tuple[list[dict], list[dict]]:
    """Generate SQL injection attack pattern."""
    rng = random.Random(seed)
    if start_time is None:
        start_time = datetime(2024, 1, 15, 15, 30, 0, tzinfo=timezone.utc)

    attacker_ip = "198.51.100.99"
    target_ip = "10.0.0.2"
    injection_urls = [
        "/api/users?id=1' OR '1'='1",
        "/api/search?q=test' UNION SELECT username,password FROM users--",
        "/api/products?category=1; DROP TABLE users;--",
        "/login?user=admin'--&pass=anything",
        "/api/orders?id=1 AND 1=1",
        "/api/users?name='; INSERT INTO admins VALUES('hacker','pass');--",
    ]
    records = []
    labels = []

    for i, url in enumerate(injection_urls):
        ts = start_time + timedelta(seconds=rng.uniform(0, 180))
        record_id = f"sqli_{i}"
        records.append({
            "timestamp": ts.isoformat(),
            "source_ip": attacker_ip,
            "dest_ip": target_ip,
            "source_port": rng.randint(1024, 65535),
            "dest_port": 443,
            "protocol": "TCP",
            "method": "GET",
            "url": url,
            "status_code": rng.choices([200, 500, 403], weights=[20, 50, 30])[0],
            "bytes_sent": rng.randint(200, 500),
            "bytes_received": rng.randint(100, 3000),
            "user_agent": "sqlmap/1.7",
            "username": "",
            "action": "request",
            "_record_id_hint": record_id,
        })
        labels.append({
            "record_id_hint": record_id,
            "is_malicious": True,
            "attack_type": "INJECTION",
            "attacker_ip": attacker_ip,
            "description": f"SQL injection attempt",
        })

    return records, labels


def generate_data_exfiltration(
    start_time: datetime | None = None,
    seed: int = DEFAULT_SEED + 6,
) -> tuple[list[dict], list[dict]]:
    """Generate data exfiltration pattern."""
    rng = random.Random(seed)
    if start_time is None:
        start_time = datetime(2024, 1, 15, 16, 0, 0, tzinfo=timezone.utc)

    insider_ip = "192.168.1.55"
    external_ip = "203.0.113.200"
    records = []
    labels = []

    # Large data transfers to external IP
    for i in range(15):
        ts = start_time + timedelta(minutes=rng.uniform(0, 60))
        record_id = f"exfil_{i}"
        records.append({
            "timestamp": ts.isoformat(),
            "source_ip": insider_ip,
            "dest_ip": external_ip,
            "source_port": rng.randint(1024, 65535),
            "dest_port": 443,
            "protocol": "TCP",
            "method": "POST",
            "url": "/upload",
            "status_code": 200,
            "bytes_sent": rng.randint(500000, 5000000),  # 500KB-5MB per request
            "bytes_received": rng.randint(100, 500),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            "username": "user_42",
            "action": "upload",
            "_record_id_hint": record_id,
        })
        labels.append({
            "record_id_hint": record_id,
            "is_malicious": True,
            "attack_type": "DATA_EXFIL",
            "attacker_ip": insider_ip,
            "description": "Large data transfer to external IP",
        })

    return records, labels


def generate_full_dataset(
    normal_count: int = 500,
    seed: int = DEFAULT_SEED,
    output_dir: str | None = None,
) -> tuple[list[dict], list[dict]]:
    """
    Generate complete dataset with normal traffic and all attack types.
    
    Returns (all_records, ground_truth_labels).
    Ground truth is stored separately from records.
    """
    base_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)

    # Normal traffic (not malicious)
    normal = generate_normal_traffic(normal_count, base_time, seed)
    normal_labels = [{"record_id_hint": f"normal_{i}", "is_malicious": False,
                       "attack_type": None} for i in range(len(normal))]

    # Attack patterns
    dos_records, dos_labels = generate_dos_attack(base_time + timedelta(hours=2), seed + 1)
    bf_records, bf_labels = generate_brute_force_attack(base_time + timedelta(hours=3), seed + 2)
    scan_records, scan_labels = generate_port_scan(base_time + timedelta(hours=1), seed + 3)
    trav_records, trav_labels = generate_path_traversal_attack(base_time + timedelta(hours=6), seed + 4)
    sqli_records, sqli_labels = generate_sql_injection_attack(base_time + timedelta(hours=7), seed + 5)
    exfil_records, exfil_labels = generate_data_exfiltration(base_time + timedelta(hours=8), seed + 6)

    all_records = (normal + dos_records + bf_records + scan_records +
                   trav_records + sqli_records + exfil_records)
    all_labels = (normal_labels + dos_labels + bf_labels + scan_labels +
                  trav_labels + sqli_labels + exfil_labels)

    # Shuffle deterministically
    rng = random.Random(seed)
    combined = list(zip(all_records, all_labels))
    rng.shuffle(combined)
    all_records, all_labels = zip(*combined)
    all_records = list(all_records)
    all_labels = list(all_labels)

    # Save to files if output_dir specified
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "..", "ground_truth"), exist_ok=True)

        # Save dataset as CSV
        csv_path = os.path.join(output_dir, "synthetic_secops_dataset.csv")
        if all_records:
            fieldnames = [k for k in all_records[0].keys() if not k.startswith("_")]
            with open(csv_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for rec in all_records:
                    cleaned = {k: v for k, v in rec.items() if not k.startswith("_")}
                    writer.writerow(cleaned)

        # Save as JSON
        json_path = os.path.join(output_dir, "synthetic_secops_dataset.json")
        clean_records = [{k: v for k, v in r.items() if not k.startswith("_")} for r in all_records]
        with open(json_path, "w") as f:
            json.dump(clean_records, f, indent=2, default=str)

        # Save as JSONL
        jsonl_path = os.path.join(output_dir, "synthetic_secops_dataset.jsonl")
        with open(jsonl_path, "w") as f:
            for rec in clean_records:
                f.write(json.dumps(rec, default=str) + "\n")

        # Save ground truth SEPARATELY
        gt_path = os.path.join(output_dir, "..", "ground_truth", "synthetic_labels.json")
        with open(gt_path, "w") as f:
            json.dump(all_labels, f, indent=2)

        gt_summary_path = os.path.join(output_dir, "..", "ground_truth", "synthetic_summary.json")
        attack_counts = {}
        for lbl in all_labels:
            at = lbl.get("attack_type", "NORMAL")
            attack_counts[at or "NORMAL"] = attack_counts.get(at or "NORMAL", 0) + 1
        with open(gt_summary_path, "w") as f:
            json.dump({
                "total_records": len(all_records),
                "malicious_records": sum(1 for l in all_labels if l.get("is_malicious")),
                "benign_records": sum(1 for l in all_labels if not l.get("is_malicious")),
                "attack_type_counts": attack_counts,
                "seed": seed,
            }, f, indent=2)

        logger.info(f"Dataset saved to {output_dir}")
        logger.info(f"Ground truth saved separately from dataset")

    return all_records, all_labels


if __name__ == "__main__":
    import sys
    output = sys.argv[1] if len(sys.argv) > 1 else "data/sample"
    records, labels = generate_full_dataset(output_dir=output)
    print(f"Generated {len(records)} records ({sum(1 for l in labels if l.get('is_malicious'))} malicious)")
