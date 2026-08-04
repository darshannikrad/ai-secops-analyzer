"""Shared utilities: timing, logging, IO helpers."""
from __future__ import annotations

import functools
import json
import logging
import os
import time
from typing import Any, Callable, Dict

LOG = logging.getLogger("secops")


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )
    LOG.setLevel(level)


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def save_json(obj: Any, path: str) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=str)


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def timed(fn: Callable) -> Callable:
    """Decorator: run a pipeline stage and return (result, elapsed_seconds)."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        return result, time.perf_counter() - start

    return wrapper


def record_stage(times: Dict[str, float], name: str, elapsed: float) -> None:
    times[name] = round(elapsed, 4)
