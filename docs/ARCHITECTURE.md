# System Architecture

## Data flow

```
┌─────────────────────────────── synthetic ground truth ──────────────────────────────┐
│  data_generator.py  ──►  data/logs.csv (events) + data/ground_truth.json (windows)   │
└───────────────────────────────────────────────────────────────────────────────────────┘
                                          │ raw events
                                          ▼
        ┌────────────────────────────────────────────────────────────────┐
        │ STAGE 1 — stats_engine.py                                     │
        │ window = 5 min  │  per (IP, window) behavioural features       │
        │ Z = (X − μ)/σ   │  15 features incl. failed_logins, entropy,   │
        │ flag max(Z) > 3 │  burst_max, scan_ratio                       │
        └──────────────┬─────────────────────────────────────────────────┘
                       │ flagged IP-windows
        ┌──────────────▼─────────────────────────────────────────────────┐
        │ STAGE 2 — rule_engine.py (baseline)                           │
        │ R001…R008 threshold signatures → RuleHit list                  │
        └──────────────┬─────────────────────────────────────────────────┘
                       │ rule hits
        ┌──────────────▼─────────────────────────────────────────────────┐
        │ STAGE 3 — orchestrator (agents.py)                            │
        │ candidates = stats outliers ∪ rule hits                       │
        │   └─ EnrichmentAgent ─► per-IP dossier (evidence timeline)     │
        │   └─ AnalystAgent ──► LLM OR deterministic fallback            │
        │        │            ──► ThreatVerdict (MITRE-mapped)           │
        │   └─ ReportAgent ──► IncidentReport (markdown + JSON)          │
        │ low-confidence ──► human review queue                          │
        └──────────────┬─────────────────────────────────────────────────┘
                       ▼
        ┌────────────────────────────────────────────────────────────────┐
        │ STAGE 4 — evaluation.py  (ground truth available)             │
        │ precision / recall / F1 / FPR / latency / cost / throughput    │
        │ outputs/metrics.json + comparison.csv                          │
        └────────────────────────────────────────────────────────────────┘
```

## Key design decisions

1. **One feature frame, three detectors.** Stage 1 and Stage 2 consume the same
   windowed feature frame; Stage 3 reasons over the same frame plus raw
   evidence. The only difference between the rule baseline and the agent is the
   *reasoning layer* — a controlled comparison.

2. **Fusion of statistical and signature signals.** Without fusion, the agent
   would never see attacks with weak statistical footprints. With it, the
   analyst can (a) confirm rule hits and (b) rescue moderate attacks that fall
   below a single threshold.

3. **Deterministic fallback = zero-cost ablation.** `offline_classifier.py`
   emits the exact same `ThreatVerdict` schema as the LLM. Downstream
   artefacts (reports, metrics) are identical in shape, so the paper can report
   "LLM vs deterministic expert" accuracy/cost deltas cleanly.

4. **Strict-JSON guardrails.** The analyst prompts for JSON, validates against a
   fixed key set, retries on parse failure, and falls back on any exception.
   Confidence below `confidence_review_threshold` (0.6) routes the case to a
   human queue — the anti-hallucination safety valve.

5. **Cost is a first-class metric.** `LLMClient` tracks prompt/completion tokens
   and converts to USD from `config.yaml` prices; `outputs/cost_ledger.json`
   records every run's spend.

## Module dependency graph

```
config.py ─────┐
threat_models ─┼─► data_generator ─► stats_engine ─► rule_engine
mitre.py ──────┘                          │              │
                                 agents.py ◄────────────┘
                                      │
              llm_client.py / offline_classifier.py
                                      │
                              pipeline.py ─► evaluation.py
                                      │
                                   main.py (CLI)
```
