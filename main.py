#!/usr/bin/env python3
"""Autonomous AI SecOps Log Analyzer — command-line entrypoint.

Examples
--------
    python main.py demo                     # one-shot offline demo (zero cost)
    python main.py generate --minutes 120   # (re)generate the labelled dataset
    python main.py evaluate --llm openai    # full pipeline + evaluation
    python main.py analyze --logs my.log    # triage an arbitrary access log
"""
from __future__ import annotations

import argparse
import json
import sys

from secops.config import load_settings
from secops.data_generator import generate_logs, summarize
from secops.pipeline import analyze_logs, run_pipeline
from secops.utils import LOG, setup_logging


def cmd_generate(args) -> int:
    settings = load_settings(args.config)
    if args.seed is not None:
        settings.data["dataset"]["seed"] = args.seed
    if args.minutes:
        settings.data["dataset"]["minutes"] = args.minutes
    df, gt = generate_logs(
        seed=settings.seed, minutes=settings.minutes,
        base_rate_per_min=settings.base_rate_per_min,
        background_ips=settings.background_ips,
        out_dir=settings.dataset_output_dir,
    )
    print(json.dumps(summarize(df, gt), indent=2))
    LOG.info("Dataset written to %s/", settings.dataset_output_dir)
    return 0


def cmd_evaluate(args) -> int:
    settings = load_settings(args.config)
    if args.seed is not None:
        settings.data["dataset"]["seed"] = args.seed
    if args.minutes:
        settings.data["dataset"]["minutes"] = args.minutes
    if args.llm:
        settings.data["llm"]["provider"] = args.llm
    results = run_pipeline(settings)
    agent = results["agent"]
    print("\nAgent ledger:",
          json.dumps({
              "provider": agent["provider"],
              "cost_usd": agent["llm_cost_usd"],
              "llm_calls": agent["llm_calls"],
              "offline_fallbacks": agent["offline_fallbacks"],
          }, indent=2))
    LOG.info("Full metrics written to outputs/metrics.json")
    return 0


def cmd_analyze(args) -> int:
    settings = load_settings(args.config)
    if args.llm:
        settings.data["llm"]["provider"] = args.llm
    result = analyze_logs(settings, args.logs)
    print(json.dumps({
        "n_events": result["n_events"], "n_anomalies": result["n_anomalies"],
        "n_rule_hits": result["n_rule_hits"], "n_reports": result["n_reports"],
        "provider": result["agent"]["provider"],
    }, indent=2))
    LOG.info("Incident reports written to %s/reports/", settings.output_dir)
    return 0


def cmd_demo(args) -> int:
    settings = load_settings(args.config)
    settings.data["dataset"]["minutes"] = args.minutes or 60
    settings.data["dataset"]["seed"] = args.seed or 7
    settings.data["llm"]["provider"] = "offline"
    LOG.info("Running demo (offline agent — no API key required)...")
    run_pipeline(settings)
    print("\nDemo complete. Inspect outputs/ for incident reports & metrics.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secops-analyzer",
        description="Autonomous AI SecOps Log Analyzer — agentic threat profiling.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--config", default="config.yaml", help="YAML config path")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("demo", help="quick offline demo (no API key)")
    d.add_argument("--seed", type=int, default=7, help="reproducibility seed")
    d.add_argument("--minutes", type=int, default=60, help="observation window")
    d.set_defaults(fn=cmd_demo)

    g = sub.add_parser("generate", help="generate labelled synthetic dataset")
    g.add_argument("--seed", type=int, help="reproducibility seed")
    g.add_argument("--minutes", type=int, help="observation window (minutes)")
    g.set_defaults(fn=cmd_generate)

    e = sub.add_parser("evaluate", help="full pipeline + evaluation vs rule baseline")
    e.add_argument("--seed", type=int, help="reproducibility seed")
    e.add_argument("--minutes", type=int, help="observation window (minutes)")
    e.add_argument("--llm", choices=["auto", "openai", "ollama", "offline"],
                   help="force analyst provider")
    e.set_defaults(fn=cmd_evaluate)

    a = sub.add_parser("analyze", help="triage an arbitrary access log")
    a.add_argument("--logs", required=True, help="path to CSV access log")
    a.add_argument("--llm", choices=["auto", "openai", "ollama", "offline"],
                   help="force analyst provider")
    a.set_defaults(fn=cmd_analyze)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        LOG.error("interrupted")
        return 130
    except Exception as exc:  # noqa: BLE001
        LOG.error("fatal: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
