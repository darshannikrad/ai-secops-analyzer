"""Phase 1 — Synthetic server-log generator with embedded, labelled threats.

Why synthetic data?
--------------------
Public labelled traffic datasets (CIC-IDS, NSL-KDD) exist, but they are (a)
years old, (b) not server-access-log shaped, and (c) hard to attribute to
individual attacker IPs. This generator emits *labelled ground-truth* access
logs so the hybrid statistical + agentic pipeline can be evaluated rigorously:
precision, recall, F1, latency, cost — all reproducible with a fixed seed.

Every generated event carries ``is_attack`` and ``attack_type`` columns, and a
separate ``ground_truth.json`` lists each attack window (attacker IP, time
range, type). This makes Phase 5 (evaluation vs. rule-based IDS) tractable.
"""
from __future__ import annotations

import json
import random
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd

from .utils import ensure_dir

# ---------------------------------------------------------------------------
# Static realism pools
# ---------------------------------------------------------------------------

PATHS = {
    "/": 0.20, "/index.html": 0.08, "/about": 0.02, "/contact": 0.02,
    "/products": 0.04, "/product/42": 0.03, "/product/7": 0.03,
    "/product/1337": 0.02, "/api/products": 0.06, "/api/cart": 0.05,
    "/login": 0.02, "/register": 0.02, "/search?q=shoes": 0.03,
    "/search?q=laptop": 0.02, "/static/css/main.css": 0.10,
    "/static/js/app.js": 0.10, "/images/logo.png": 0.08,
    "/blog/post/1": 0.02, "/blog/post/2": 0.02, "/api/user/profile": 0.02,
    "/api/orders": 0.01, "/health": 0.01,
}

STATUSES: List[Tuple[int, float]] = [
    (200, 0.84), (301, 0.04), (304, 0.04), (404, 0.04),
    (401, 0.005), (403, 0.005), (500, 0.01), (503, 0.02),
]

USER_AGENTS: List[Tuple[str, float]] = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0", 0.35),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15", 0.20),
    ("Mozilla/5.0 (X11; Linux x86_64) Firefox/123.0", 0.15),
    ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", 0.10),
    ("Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)", 0.06),
    ("python-requests/2.31.0", 0.04),
    ("curl/8.5.0", 0.03),
    ("Go-http-client/1.1", 0.02),
    ("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", 0.02),
    ("Mozilla/5.0 (compatible; SemrushBot/7.0)", 0.01),
    ("sqlmap/1.8.2#stable", 0.004),
    ("Nessus/10.4.0", 0.004),
    ("Mozilla/5.0 (compatible; masscan/1.3)", 0.003),
]

METHODS = ["GET", "POST", "HEAD", "PUT", "DELETE"]

# Attack scenarios: type -> (attacker_ip, duration_s, intensity_per_second)
ATTACKS: List[Tuple[str, str, int, float]] = [
    ("brute_force", "185.220.101.34", 600, 0.45),
    ("credential_stuffing", "185.220.102.5", 480, 0.40),
    ("port_scan", "45.155.205.233", 300, 0.08),
    ("ddos", "91.240.118.30", 240, 3.0),
    ("ddos", "193.32.162.100", 200, 2.6),
    ("ddos", "46.161.41.60", 220, 2.8),
    ("data_exfiltration", "94.102.61.120", 300, 0.20),
    ("sql_injection", "103.75.190.45", 180, 0.30),
    ("xss", "5.188.206.10", 150, 0.25),
]

USERNAME_POOL = [
    "admin", "root", "bob", "alice", "carol", "dave", "erin", "frank",
    "grace", "heidi", "ivan", "judy", "mallory", "olivia", "oscar", "peggy",
    "trent", "walter", "victor", "wendy", "xavier", "yvonne", "zara",
]

# SQLi / XSS probe signatures (mirror Snort-style content match rules)
SQLI_PATTERNS = [
    "' OR '1'='1", "UNION SELECT", "OR 1=1--", "'; DROP TABLE", "WAITFOR DELAY",
    "1' AND '1'='1", "admin'--", "';SELECT", "OR SLEEP(5)",
]
XSS_PATTERNS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "javascript:alert(1)", "<svg/onload=alert(1)>", "\\x3cscript\\x3e",
]


# ---------------------------------------------------------------------------
# Event builders
# ---------------------------------------------------------------------------

def _background_event(rng: random.Random, ip: str, t: int) -> Dict[str, Any]:
    path = rng.choices(list(PATHS.keys()), weights=list(PATHS.values()))[0]
    status = rng.choices([s for s, _ in STATUSES], weights=[w for _, w in STATUSES])[0]
    ua = rng.choices([u for u, _ in USER_AGENTS], weights=[w for _, w in USER_AGENTS])[0]
    bytes_out = max(0, int(rng.lognormvariate(6.5, 1.1)))
    latency = max(0.1, round(rng.gammavariate(2.0, 18.0), 1))
    method = rng.choice(METHODS)
    port = 443 if rng.random() < 0.7 else 80
    return {
        "timestamp": t, "src_ip": ip, "method": method, "path": path,
        "status": status, "bytes": bytes_out, "latency_ms": latency,
        "user_agent": ua, "dst_port": port, "is_attack": 0, "attack_type": "",
    }


def _attack_event(rng: random.Random, attack_type: str, ip: str) -> Dict[str, Any]:
    """Generate an event belonging to a specific attack scenario."""
    if attack_type == "brute_force":
        # Repeated password guesses against POST /login; success at the end.
        success = rng.random() < 0.015
        status = 200 if success else 401
        return {
            "timestamp": 0, "src_ip": ip, "method": "POST",
            "path": f"/login?user=admin&pass={rng.randint(100000, 999999)}",
            "status": status, "bytes": rng.randint(120, 900),
            "latency_ms": round(rng.uniform(8, 90), 1),
            "user_agent": "python-requests/2.31.0", "dst_port": 443,
            "is_attack": 1, "attack_type": attack_type,
        }
    if attack_type == "credential_stuffing":
        user = rng.choice(USERNAME_POOL)
        status = 200 if rng.random() < 0.01 else 401
        return {
            "timestamp": 0, "src_ip": ip, "method": "POST",
            "path": f"/api/login?username={user}&password=Letmein{user}",
            "status": status, "bytes": rng.randint(80, 700),
            "latency_ms": round(rng.uniform(6, 70), 1),
            "user_agent": "Go-http-client/1.1", "dst_port": 443,
            "is_attack": 1, "attack_type": attack_type,
        }
    if attack_type == "port_scan":
        return {
            "timestamp": 0, "src_ip": ip, "method": rng.choice(["GET", "HEAD"]),
            "path": rng.choice(["/", "/health", "/.git/config", "/admin", "/wp-login.php"]),
            "status": rng.choice([200, 403, 404, 500]),
            "bytes": rng.randint(0, 1200),
            "latency_ms": round(rng.uniform(1, 40), 1),
            "user_agent": "Mozilla/5.0 (compatible; masscan/1.3)", "dst_port": rng.randint(1, 1024),
            "is_attack": 1, "attack_type": attack_type,
        }
    if attack_type == "ddos":
        return {
            "timestamp": 0, "src_ip": ip, "method": "GET",
            "path": rng.choice(["/", "/index.html", "/api/products", "/static/js/app.js"]),
            "status": 503 if rng.random() < 0.35 else 200,
            "bytes": rng.randint(60, 4000),
            "latency_ms": round(rng.uniform(0.5, 15), 1),
            "user_agent": rng.choice(["python-requests/2.31.0", "Go-http-client/1.1"]),
            "dst_port": 80, "is_attack": 1, "attack_type": attack_type,
        }
    if attack_type == "data_exfiltration":
        return {
            "timestamp": 0, "src_ip": ip, "method": "GET",
            "path": rng.choice([
                "/files/backup-2024.tar.gz", "/api/export?data=full",
                "/api/users/dump", "/files/db-dump.sql", "/api/payments/export",
            ]),
            "status": 200, "bytes": rng.randint(4_000_000, 40_000_000),
            "latency_ms": round(rng.uniform(400, 3000), 1),
            "user_agent": "curl/8.5.0", "dst_port": 443,
            "is_attack": 1, "attack_type": attack_type,
        }
    if attack_type == "sql_injection":
        payload = rng.choice(SQLI_PATTERNS).replace("'", "%27").replace(" ", "+")
        path = rng.choice(["/product?id=", "/search?q="]) + payload
        return {
            "timestamp": 0, "src_ip": ip, "method": "GET", "path": path,
            "status": 500 if rng.random() < 0.4 else 200,
            "bytes": rng.randint(100, 3000),
            "latency_ms": round(rng.uniform(10, 120), 1),
            "user_agent": "sqlmap/1.8.2#stable", "dst_port": 80,
            "is_attack": 1, "attack_type": attack_type,
        }
    if attack_type == "xss":
        payload = rng.choice(XSS_PATTERNS).replace(" ", "%20")
        path = rng.choice(["/search?q=", "/blog/post/1?comment="]) + payload
        return {
            "timestamp": 0, "src_ip": ip, "method": "GET", "path": path,
            "status": 200, "bytes": rng.randint(200, 2500),
            "latency_ms": round(rng.uniform(5, 60), 1),
            "user_agent": "curl/8.5.0", "dst_port": 80,
            "is_attack": 1, "attack_type": attack_type,
        }
    raise ValueError(f"unknown attack type: {attack_type}")


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

def generate_logs(
    seed: int = 42,
    minutes: int = 90,
    base_rate_per_min: float = 18.0,
    background_ips: int = 40,
    out_dir: str = "data",
    start_ts: str = "2024-11-01T08:00:00",
) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
    """Generate a labelled access-log dataset and its ground-truth manifest.

    Returns (logs_df, ground_truth) where ground_truth is a list of dicts:
        {attack_type, attacker_ip, start_ts, end_ts, severity, description}
    """
    rng = random.Random(seed)
    rng_ts = random.Random(seed + 1)

    bg_ips = [f"10.20.{rng.randint(1, 254)}.{rng.randint(1, 254)}" for _ in range(background_ips)]
    # sprinkle a couple of well-known benign bots / crawlers
    bg_ips += ["66.249.65.12", "40.77.167.250", "157.55.39.101", "5.45.207.153"]

    total_seconds = int(minutes * 60)
    base_second = 1 / (base_rate_per_min / 60.0) if base_rate_per_min > 0 else 1e9

    # Schedule attacks deterministically across the observation window
    attack_schedule: List[Dict[str, Any]] = []
    n = len(ATTACKS)
    for idx, (atype, ip, duration, intensity) in enumerate(ATTACKS):
        slot = int((idx + 1) * (total_seconds / (n + 1)))
        start = max(60, slot - duration // 2)
        end = min(total_seconds - 1, start + duration)
        if end <= start:
            end = start + min(duration, total_seconds - 1)
        attack_schedule.append({
            "type": atype, "ip": ip, "intensity": intensity,
            "start": start, "end": end, "duration": duration,
        })

    # Active attack windows -> for fast lookup group by second
    active_by_second: Dict[int, List[Dict[str, Any]]] = {}
    for a in attack_schedule:
        for t in range(a["start"], a["end"]):
            active_by_second.setdefault(t, []).append(a)

    events: List[Dict[str, Any]] = []
    ground_truth: List[Dict[str, Any]] = []

    for t in range(total_seconds):
        # --- background traffic (Poisson-ish arrivals) ---
        n_bg = 0
        p_bg = 1.0 / base_second
        while rng_ts.random() < p_bg:
            n_bg += 1
            if n_bg > 12:
                break
        for _ in range(n_bg):
            ev = _background_event(rng_ts, rng_ts.choice(bg_ips), t)
            events.append(ev)

        # --- attack traffic ---
        for a in active_by_second.get(t, []):
            ev = _attack_event(rng_ts, a["type"], a["ip"])
            ev["timestamp"] = t
            if rng_ts.random() < a["intensity"]:
                events.append(ev)

    # Convert to DataFrame with ISO timestamps
    df = pd.DataFrame(events)
    if df.empty:
        raise RuntimeError("generator produced no events — check configuration")
    start_dt = pd.Timestamp(start_ts)
    df["timestamp"] = start_dt + pd.to_timedelta(df["timestamp"], unit="s")
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%S")

    # Ground truth manifest
    start_dt64 = start_dt
    for a in attack_schedule:
        severity = {"ddos": 7.0, "data_exfiltration": 9.0, "brute_force": 8.0,
                    "credential_stuffing": 7.5, "port_scan": 4.0,
                    "sql_injection": 8.5, "xss": 6.0}.get(a["type"], 5.0)
        ground_truth.append({
            "attack_type": a["type"],
            "attacker_ip": a["ip"],
            "start_ts": (start_dt64 + pd.to_timedelta(a["start"], unit="s")).strftime("%Y-%m-%dT%H:%M:%S"),
            "end_ts": (start_dt64 + pd.to_timedelta(a["end"], unit="s")).strftime("%Y-%m-%dT%H:%M:%S"),
            "severity": severity,
            "description": f"Simulated {a['type']} campaign from {a['ip']}",
        })

    ensure_dir(out_dir)
    df.to_csv(f"{out_dir}/logs.csv", index=False)
    with open(f"{out_dir}/ground_truth.json", "w", encoding="utf-8") as fh:
        json.dump(ground_truth, fh, indent=2)

    return df, ground_truth


def summarize(df: pd.DataFrame, ground_truth: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Print-friendly summary of the generated dataset."""
    attack_rows = df[df["is_attack"] == 1]
    per_type = attack_rows.groupby("attack_type").size().to_dict()
    return {
        "total_events": int(len(df)),
        "benign_events": int(len(df) - len(attack_rows)),
        "attack_events": int(len(attack_rows)),
        "attacks_by_type": per_type,
        "distinct_src_ips": int(df["src_ip"].nunique()),
        "ground_truth_incidents": len(ground_truth),
    }
