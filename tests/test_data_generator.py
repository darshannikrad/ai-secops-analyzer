"""Tests for the synthetic log generator."""
import json
import os

import pandas as pd
import pytest

from secops.data_generator import generate_logs, summarize


def test_generator_deterministic(tmp_path):
    df1, gt1 = generate_logs(seed=42, minutes=30, base_rate_per_min=10,
                             background_ips=20, out_dir=str(tmp_path / "a"))
    df2, gt2 = generate_logs(seed=42, minutes=30, base_rate_per_min=10,
                             background_ips=20, out_dir=str(tmp_path / "b"))
    assert df1.equals(df2)
    assert gt1 == gt2


def test_generator_contains_attack_events():
    df, gt = generate_logs(seed=42, minutes=60, base_rate_per_min=12,
                           background_ips=25, out_dir="/tmp/secops_test_gen")
    assert (df["is_attack"] == 1).sum() > 0
    assert len(gt) >= 8  # all scenarios present
    types = {a["attack_type"] for a in gt}
    assert {"brute_force", "ddos", "data_exfiltration", "sql_injection"} <= types


def test_attack_rows_carry_labels():
    df, _ = generate_logs(seed=1, minutes=45, base_rate_per_min=12,
                          background_ips=20, out_dir="/tmp/secops_test_gen2")
    attacks = df[df["is_attack"] == 1]
    assert (attacks["attack_type"] != "").all()
    # every attack row belongs to a known attacker IP
    known = {"185.220.101.34", "185.220.102.5", "45.155.205.233", "91.240.118.30",
             "193.32.162.100", "46.161.41.60", "94.102.61.120", "103.75.190.45",
             "5.188.206.10"}
    assert set(attacks["src_ip"]) <= known


def test_summarize_counts():
    df, gt = generate_logs(seed=3, minutes=20, base_rate_per_min=8,
                           background_ips=15, out_dir="/tmp/secops_test_gen3")
    s = summarize(df, gt)
    assert s["total_events"] == len(df)
    assert s["attack_events"] == int((df["is_attack"] == 1).sum())
    assert s["ground_truth_incidents"] == len(gt)
