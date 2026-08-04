"""Configuration loading with sensible defaults + optional YAML overlay.

The YAML file is optional: if PyYAML is unavailable or the file is missing,
the built-in defaults are used so the project always runs out of the box.
"""
from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

DEFAULTS: Dict[str, Any] = {
    "dataset": {
        "seed": 42,
        "minutes": 90,
        "base_rate_per_min": 18,
        "background_ips": 40,
        "output_dir": "data",
    },
    "stats": {
        "window_minutes": 5,
        "z_threshold": 3.0,
        "robust": False,
        "min_baseline_samples": 8,
    },
    "rules": {
        "brute_force_min_failures": 5,
        "cred_stuffing_min_users": 8,
        "port_scan_min_ports": 12,
        "ddos_min_requests": 150,
        "exfil_min_bytes": 50_000_000,
        "sqli_min_patterns": 1,
        "xss_min_patterns": 1,
    },
    "llm": {
        "provider": "auto",
        "model": "gpt-4o-mini",
        "temperature": 0.0,
        "max_tokens": 900,
        "base_url": None,
        "input_price_per_mtok": 0.15,
        "output_price_per_mtok": 0.60,
        "json_retries": 2,
        "confidence_review_threshold": 0.6,
    },
    "pipeline": {
        "include_rule_hits_in_agent": True,
        "max_agent_ips": 60,
        "enrich_max_evidence_rows": 25,
        "output_dir": "outputs",
    },
}


@dataclass
class Settings:
    """Typed view over the merged configuration dict."""

    data: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

    # ---- dataset ----
    @property
    def seed(self) -> int:
        return int(self.data["dataset"]["seed"])

    @property
    def minutes(self) -> int:
        return int(self.data["dataset"]["minutes"])

    @property
    def base_rate_per_min(self) -> float:
        return float(self.data["dataset"]["base_rate_per_min"])

    @property
    def background_ips(self) -> int:
        return int(self.data["dataset"]["background_ips"])

    @property
    def dataset_output_dir(self) -> str:
        return str(self.data["dataset"]["output_dir"])

    # ---- stats ----
    @property
    def window_minutes(self) -> int:
        return int(self.data["stats"]["window_minutes"])

    @property
    def z_threshold(self) -> float:
        return float(self.data["stats"]["z_threshold"])

    @property
    def robust_stats(self) -> bool:
        return bool(self.data["stats"]["robust"])

    @property
    def min_baseline_samples(self) -> int:
        return int(self.data["stats"]["min_baseline_samples"])

    # ---- rules ----
    @property
    def rule_thresholds(self) -> Dict[str, float]:
        return {k: float(v) for k, v in self.data["rules"].items()}

    # ---- llm ----
    @property
    def llm_provider(self) -> str:
        return str(self.data["llm"]["provider"]).lower()

    @property
    def llm_model(self) -> str:
        return str(self.data["llm"]["model"])

    @property
    def llm_temperature(self) -> float:
        return float(self.data["llm"]["temperature"])

    @property
    def llm_max_tokens(self) -> int:
        return int(self.data["llm"]["max_tokens"])

    @property
    def llm_base_url(self) -> Optional[str]:
        url = self.data["llm"].get("base_url")
        return str(url) if url else None

    @property
    def llm_prices(self) -> tuple:
        return (
            float(self.data["llm"]["input_price_per_mtok"]),
            float(self.data["llm"]["output_price_per_mtok"]),
        )

    @property
    def llm_json_retries(self) -> int:
        return int(self.data["llm"]["json_retries"])

    @property
    def confidence_review_threshold(self) -> float:
        return float(self.data["llm"]["confidence_review_threshold"])

    # ---- pipeline ----
    @property
    def include_rule_hits(self) -> bool:
        return bool(self.data["pipeline"]["include_rule_hits_in_agent"])

    @property
    def max_agent_ips(self) -> int:
        return int(self.data["pipeline"]["max_agent_ips"])

    @property
    def enrich_max_evidence_rows(self) -> int:
        return int(self.data["pipeline"]["enrich_max_evidence_rows"])

    @property
    def output_dir(self) -> str:
        return str(self.data["pipeline"]["output_dir"])

    def to_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self.data)


def _deep_merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_settings(config_path: Optional[str] = None) -> Settings:
    """Load settings, overlaying ``config.yaml`` on top of defaults."""
    merged = copy.deepcopy(DEFAULTS)
    if config_path and os.path.exists(config_path):
        try:
            import yaml  # type: ignore

            with open(config_path, "r", encoding="utf-8") as fh:
                overlay = yaml.safe_load(fh) or {}
            merged = _deep_merge(merged, overlay)
        except ImportError:
            print(f"[config] PyYAML not installed — using built-in defaults for {config_path}")
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[config] Could not parse {config_path}: {exc} — using defaults")
    return Settings(data=merged, raw=merged)
