# Autonomous AI SecOps Log Analyzer

**An Agentic Framework for Threat Profiling**

> **Group 84** — Yash Nimbalkar, Darshan Nikrad
>
> Domain: Generative AI · Agentic AI · Cybersecurity
> Conferences targeted: IEEE CSR · ACM SACMAT

---

## 1. What this project does

Security Operations Centers (SOCs) drown in alerts. Traditional rule-based IDS
fire on hand-tuned thresholds (high **false positives** → alert fatigue), while
pure statistical monitors catch everything but explain nothing (high **recall**,
low **precision**). LLM agents are smart but expensive — you cannot send every
request to a model.

This project implements a **three-stage hybrid pipeline** that gets the best of
all worlds:

```
raw access logs
      │
      ▼
┌──────────────────┐   ┌──────────────────┐   ┌───────────────────────────┐
│   STAGE 1        │   │   STAGE 2        │   │   STAGE 3                 │
│  Statistical     │──►│  Signature rules │──►│  Agentic AI analyst       │
│  triage (Pandas) │   │  (baseline)      │   │  (LLM or deterministic)   │
│  Z-scores        │   │  Snort-style     │   │  MITRE mapping + report   │
└──────────────────┘   └──────────────────┘   └───────────────────────────┘
   high recall           catches known          high precision,
   cheap (0.4 s)         signatures             zero false positives,
                                                 human-readable incidents
```

- **Stage 1 — Statistical baseline:** Pandas computes 15 behavioural features
  per (source-IP × 5-min window): request rate, error rate, failed logins,
  distinct usernames, egress bytes, latency, path entropy, port-scan ratio,
  minute-level burstiness, etc. Each is Z-scored `Z = (X − μ)/σ` and any window
  with `max(Z) > 3.0` is flagged.
- **Stage 2 — Signature rules:** classic threshold rules (brute force, credential
  stuffing, port scan, DDoS, exfiltration, SQLi, XSS) fire on the same feature
  frame — the controlled baseline for Phase 5.
- **Stage 3 — Agentic AI:** an orchestrator fuses the statistical outliers and
  rule hits, an *enrichment agent* builds a per-IP evidence dossier, an
  *analyst agent* (LLM or deterministic fallback) reasons about it and returns a
  structured **MITRE ATT&CK verdict**, and a *report agent* writes paper-quality
  incident reports. Low-confidence verdicts are routed to a human review queue
  (human-in-the-loop, mitigating LLM hallucination).

**Why unique (research contributions):**
1. **Fusion triage** — statistical outliers *and* signature hits are both sent
   to the agent, so the LLM recovers attacks single-threshold rules miss and
   dismisses statistical false positives (crawlers, CDNs, scanners).
2. **Cost-aware design** — a deterministic fallback analyst mirrors the LLM's
   output schema, giving a zero-cost ablation baseline and guaranteeing offline
   demos.
3. **Labelled, reproducible data** — a seeded generator emits access logs with
   ground-truth attack windows, so precision/recall/latency/cost are all
   measured, not estimated.

## 2. Quick start

Requires Python ≥ 3.10 (tested on 3.13) with `pandas`, `numpy`, `pyyaml`.

```bash
pip install -r requirements.txt

# One-shot offline demo (no API key) — generates data, runs everything
python main.py demo

# Full pipeline + evaluation vs the rule baseline
python main.py evaluate

# Use the real LLM analyst (set OPENAI_API_KEY first, or run Ollama locally)
python main.py evaluate --llm openai

# Triage an arbitrary access log (no ground truth)
python main.py analyze --logs my_access_log.csv

# Regenerate the synthetic dataset with custom size
python main.py generate --minutes 120 --seed 42
```

### Sample results (offline run, seed 7, 90 min, 2,825 events, 9 attacks)

| Detector | Precision | Recall | F1 | False-positive rate | Alerts | Latency |
|---|---|---|---|---|---|---|
| Statistical only (Z>3) | 0.53 | 1.00 | 0.69 | 0.32 | 17 | 2.47 min |
| Rule-based (baseline) | 1.00 | 0.89 | 0.94 | 0.00 | 8 | 3.20 min |
| **Agentic hybrid** | **1.00** | **1.00** | **1.00** | **0.00** | **9** | **2.47 min** |

> Statistical triage alone floods the analyst with **8 false positives**
> (alert fatigue). The agentic layer eliminates them **and** catches the
> moderate DDoS flood that threshold rules miss. Full pipeline: **0.46 s**
> (≈6,100 events/s), cost **$0.00** in offline mode.

## 3. Project structure

```
AI-SecOps-Analyzer/
├── main.py                  # CLI: demo | generate | evaluate | analyze
├── config.yaml              # all experiment knobs (seed, thresholds, LLM)
├── requirements.txt
├── .env.example             # OPENAI_API_KEY / OPENAI_BASE_URL
├── secops/                  # the package
│   ├── data_generator.py    # Phase 1: labelled synthetic logs + ground truth
│   ├── stats_engine.py      # Phase 2: behavioural features + Z-scores
│   ├── rule_engine.py       # Phase 5 baseline: signature rules
│   ├── llm_client.py        # Phase 3: LLM client (auto provider + cost)
│   ├── offline_classifier.py# Phase 3: deterministic fallback analyst
│   ├── agents.py            # Phase 4: enrichment / analyst / report / orchestrator
│   ├── pipeline.py          # Phase 4: end-to-end assembly + outputs
│   ├── evaluation.py        # Phase 5: metrics vs ground truth
│   ├── mitre.py             # MITRE ATT&CK taxonomy
│   └── threat_models.py     # AnomalyRecord / ThreatVerdict / IncidentReport
├── notebooks/
│   ├── research_evaluation.ipynb   # reproducible paper notebook
│   └── make_figures.py             # 5 publication figures
├── tests/                   # 21 unit + end-to-end tests (pytest)
├── docs/                    # IEEE paper outline, project report, architecture
├── data/                    # generated logs + ground_truth.json
└── outputs/                 # metrics, verdicts, reports/*.md, figures/
```

## 4. Using the LLM analyst (optional)

The pipeline auto-detects the provider (`provider: auto` in `config.yaml`):

| Provider | Setup |
|---|---|
| **OpenAI / Groq / Together…** | `export OPENAI_API_KEY=sk-...` — any OpenAI-compatible API |
| **Ollama (local, free)** | `ollama serve` + `ollama pull llama3.1`; set `base_url: http://localhost:11434/v1` in `config.yaml` |
| **LM Studio / any local server** | point `OPENAI_BASE_URL` at it |

The agent enforces strict-JSON output, retries malformed replies, validates the
schema, and falls back to the deterministic classifier if the LLM fails — so the
pipeline never breaks and costs stay bounded (`max_agent_ips` cap, token-cost
ledger in `outputs/cost_ledger.json`).

## 5. Outputs

Every run writes to `outputs/`:

- `metrics.json` / `comparison.csv` — the results table above, with stage timings
- `incident_reports.json` + `reports/INC-XXXX.md` — human-readable incident reports
  (executive summary, MITRE mapping, evidence timeline, IoCs, recommended actions)
- `verdicts.json`, `dossiers.json`, `rule_hits.json`, `feature_frame.csv` — full audit trail
- `cost_ledger.json` — LLM tokens & spend per run
- `figures/` — 5 publication-quality figures (via `notebooks/make_figures.py`)

## 6. Tests & reproducibility

```bash
python -m pytest tests/ -q          # 21 tests
python notebooks/make_figures.py    # regenerate paper figures
```

The generator is seeded, so every number in this README reproduces exactly with
`python main.py demo --seed 7 --minutes 90`.

## 6b. Web dashboard & hosting

The project ships a full web application: a FastAPI backend wrapping the
pipeline + a dark SOC-style dashboard (KPIs, Chart.js graphs, detector
comparison, expandable incident reports, publication figures, and drag-and-drop
log upload).

```bash
pip install -r requirements.txt fastapi uvicorn python-multipart openai
uvicorn web.main:app --host 0.0.0.0 --port 8000
# open http://localhost:8000  →  click “Launch Pipeline”
```

**Deploy online** (no build step): push the repo to GitHub and create a free
web service on [Render.com](https://render.com) (auto-detects `render.yaml`), or
use the `Dockerfile` on Railway / Hugging Face Spaces / Fly.io. Full guide:
`README-DEPLOY.md`. The app runs fully offline by default; set `OPENAI_API_KEY`
env var to enable the GPT analyst.

## 7. Roadmap / future work (paper section VI)

- Real datasets (CIC-IDS2017, UNSW-NB15) + live SIEM ingestion (Kafka/Splunk)
- Prompt-injection & hallucination hardening for the LLM analyst
- Feedback loop: analyst actions updating rule weights (active learning)
- Multi-window temporal reasoning and cross-IP campaign detection
- Human-in-the-loop label ingestion to recalibrate confidence

See `docs/PAPER_OUTLINE.md` for the full IEEE-paper skeleton and `docs/PROJECT_REPORT.md`
for the detailed viva report.
