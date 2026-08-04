"""Generate ready-to-upload sample access logs for testing the dashboard.

Run:  python sample_inputs/make_samples.py
Out:  sample_inputs/*.csv

Each file uses the exact schema the analyzer accepts:
    timestamp, src_ip, method, path, status, bytes,
    latency_ms, user_agent, dst_port

Scenarios (drag & drop any of these into the dashboard's upload box):
    clean_log.csv        — normal weekday traffic, no attacks
    brute_sqli_log.csv   — brute force + SQL injection + XSS probes
    ddos_scan_log.csv    — DDoS request flood + port scanning
    full_mixed_log.csv   — all 7 attack types (the paper's standard corpus)
"""
from __future__ import annotations

import os
import random
import shutil
from typing import List, Tuple

import pandas as pd

import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secops.data_generator import (  # noqa: E402
    ATTACKS,
    _attack_event,
    _background_event,
)

HERE = os.path.dirname(os.path.abspath(__file__))
START = "2024-11-05T09:00:00"

# scenario -> (minutes, seed, background_ips, list of attack_type names)
SCENARIOS: List[Tuple[str, int, int, int, List[str]]] = [
    ("clean_log", 20, 11, 24, []),
    ("brute_sqli_log", 30, 23, 24, ["brute_force", "sql_injection", "xss"]),
    ("ddos_scan_log", 25, 31, 24, ["ddos", "port_scan"]),
]


def _attacks_table() -> dict:
    return {a[0]: {"ip": a[1], "duration": a[2], "intensity": a[3]} for a in ATTACKS}


def generate(minutes: int, seed: int, bg_ips: int,
             attack_types: List[str]) -> pd.DataFrame:
    rng = random.Random(seed)
    rng_ts = random.Random(seed + 1)
    table = _attacks_table()
    ips = [f"10.20.{rng.randint(1, 254)}.{rng.randint(1, 254)}" for _ in range(bg_ips)]
    ips += ["66.249.65.12", "40.77.167.250"]  # Googlebot + Bingbot

    total = int(minutes * 60)
    # schedule selected attacks evenly across the window
    schedule = []
    n = len(attack_types)
    for idx, atype in enumerate(attack_types):
        meta = table[atype]
        slot = int((idx + 1) * (total / (n + 1)))
        start = max(60, slot - meta["duration"] // 2)
        end = min(total - 1, start + meta["duration"])
        schedule.append({**meta, "type": atype, "start": start, "end": end})

    active: dict = {}
    for a in schedule:
        for t in range(a["start"], a["end"]):
            active.setdefault(t, []).append(a)

    base_second = 60.0 / 18.0  # ~18 requests per minute of background
    events = []
    for t in range(total):
        n_bg = 0
        while rng_ts.random() < 1 / base_second:
            n_bg += 1
            if n_bg > 10:
                break
        for _ in range(n_bg):
            ev = _background_event(rng_ts, rng_ts.choice(ips), t)
            events.append(ev)
        for a in active.get(t, []):
            ev = _attack_event(rng_ts, a["type"], a["ip"])
            ev["timestamp"] = t
            if rng_ts.random() < a["intensity"]:
                events.append(ev)

    df = pd.DataFrame(events).sort_values("timestamp").reset_index(drop=True)
    start_dt = pd.Timestamp(START)
    df["timestamp"] = start_dt + pd.to_timedelta(df["timestamp"], unit="s")
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%S")
    return df[["timestamp", "src_ip", "method", "path", "status", "bytes",
               "latency_ms", "user_agent", "dst_port"]]


def main() -> None:
    os.makedirs(HERE, exist_ok=True)
    for name, minutes, seed, bg, attacks in SCENARIOS:
        df = generate(minutes, seed, bg, attacks)
        path = os.path.join(HERE, f"{name}.csv")
        df.to_csv(path, index=False)
        print(f"  {name}.csv  ->  {len(df)} events, {df['src_ip'].nunique()} IPs")

    # full mixed corpus: copy the standard generated dataset
    src = os.path.join(os.path.dirname(HERE), "data", "logs.csv")
    dst = os.path.join(HERE, "full_mixed_log.csv")
    if os.path.exists(src):
        shutil.copyfile(src, dst)
        print(f"  full_mixed_log.csv -> copied from data/logs.csv")
    else:
        from secops.data_generator import generate_logs

        df, _ = generate_logs(seed=7, minutes=90, base_rate_per_min=18,
                              background_ips=40,
                              out_dir=os.path.join(os.path.dirname(HERE), "data"))
        df[["timestamp", "src_ip", "method", "path", "status", "bytes",
            "latency_ms", "user_agent", "dst_port"]].to_csv(dst, index=False)
        print(f"  full_mixed_log.csv -> generated ({len(df)} events)")
    print("Done — files ready in sample_inputs/")


if __name__ == "__main__":
    main()
