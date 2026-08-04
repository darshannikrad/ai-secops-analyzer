# Project Report — Autonomous AI SecOps Log Analyzer

**Group 84**
| Sr. No. | Name |
|---|---|
| 1 | Yash Nimbalkar |
| 2 | Darshan Nikrad |

**Domain:** Generative AI, Agentic AI, Cybersecurity
**Keywords (ACM):** Security and Privacy → Intrusion/anomaly detection →
Intrusion detection systems · Computing Methodologies → Artificial intelligence
→ Natural language processing · Applied Computing → IT architectures

---

## 1. Problem Statement

SOCs receive thousands of alerts per day. Two failure modes dominate:

1. **Statistical monitors** flag anything unusual — they catch every attack
   (high recall) but drown analysts in false positives (low precision), the
   root cause of **alert fatigue**.
2. **Rule-based IDS** fire only on hand-tuned thresholds — precise on known
   signatures (high precision) but blind to moderate or novel attacks (low
   recall) and brittle to re-tune.

LLMs can reason about context, map findings to MITRE ATT&CK and write reports
humans actually read — but their latency and cost forbid applying them to raw
traffic. **This project's research question:** can an agentic LLM layer, applied
*only* to statistically- and signature-flagged candidates, simultaneously
achieve the recall of statistics, the precision of rules, and the readability of
a senior SOC analyst?

## 2. Solution Overview

A three-stage pipeline (see `docs/ARCHITECTURE.md`):

- **Stage 1 — Statistical baseline (Pandas).** Per (IP, 5-min window) we compute
  15 behavioural features, standardise each with Z-scores, and flag windows
  where `max(Z) > 3.0`.
- **Stage 2 — Signature baseline.** 8 Snort-style rules fire on the same feature
  frame (controlled comparison).
- **Stage 3 — Agentic AI.** Candidates = outliers ∪ rule hits. Four agents
  cooperate: **Enrichment** (evidence dossier), **Analyst** (LLM or
  deterministic fallback → MITRE-mapped verdict), **Report** (incident
  report), **Orchestrator** (candidate selection, agent loop, cost ledger).
- **Stage 4 — Evaluation.** Precision, recall, F1, false-positive rate, alert
  multiplicity, detection latency, throughput, USD cost — all vs ground truth.

## 3. Mathematics

**Z-score (classic):** Z = (X − μ)/σ — deviation from the traffic baseline in
standard units.

**Robust Z-score (median/MAD):** Z = 0.6745·(X − med)/MAD — resilient to the
very outliers we hunt.

**Shannon path entropy:** H = −Σᵢ pᵢ log₂ pᵢ — repetitive probing (low H) is
suspicious, so H is negatively standardised.

**F1:** F1 = 2·P·R/(P+R); **Alert multiplicity** = alerts issued / true
incidents (the alert-fatigue proxy; ideal = 1.0).

## 4. Implementation (Phase-wise, as per synopsis)

| Phase | Deliverable | Module | Status |
|---|---|---|---|
| 1 | Setup & data generation | `secops/data_generator.py` | ✅ |
| 2 | Statistical baseline | `secops/stats_engine.py` | ✅ |
| 3 | AI analyst integration | `secops/agents.py`, `llm_client.py`, `offline_classifier.py` | ✅ |
| 4 | Pipeline assembly | `secops/pipeline.py`, `main.py` | ✅ |
| 5 | Evaluation & paper drafting | `secops/evaluation.py`, `docs/PAPER_OUTLINE.md` | ✅ |

**Agents (the "agentic framework"):**
- `EnrichmentAgent.build_dossier(ip)` — features, rule hits, up to 25 evidence
  rows, indicators.
- `AnalystAgent.analyze(dossier)` — LLM with strict-JSON guardrails, schema
  validation, retry → fallback chain; confidence threshold → human review queue.
- `ReportAgent.build_report(verdict, dossier)` — markdown + JSON incidents.
- `Orchestrator.run(...)` — fusion selection, agent loop, `max_agent_ips` cap.

**Offline fallback (unique feature):** `classify_ip()` mirrors the LLM's output
schema with transparent domain rules (SQLi/XSS signatures first, then
credential stuffing > brute force > scan > exfiltration > flood, else benign).
The pipeline therefore runs with **zero API cost** and the same artefacts —
ideal for demo/exam and for the LLM-vs-deterministic ablation in the paper.

## 5. Experimental Results

Dataset: 2,825 events (1,506 benign / 1,319 attack), 53 source IPs, 9 labelled
attack campaigns, 90-minute window, seed 7.

| Detector | Prec | Recall | F1 | FPR | Alerts | Latency |
|---|---|---|---|---|---|---|
| Statistical only | 0.53 | 1.00 | 0.69 | 0.32 | 17 | 2.47 min |
| Rule-based baseline | 1.00 | 0.89 | 0.94 | 0.00 | 8 | 3.20 min |
| **Agentic hybrid** | **1.00** | **1.00** | **1.00** | **0.00** | **9** | **2.47 min** |

Performance: total pipeline 0.46 s ≈ 6,100 events/s; agent stage 0.02 s;
LLM cost $0.00 (offline) / ≈$0.01–0.02 (gpt-4o-mini).

**Discussion:**
- The 8 statistical false positives are crawlers/CDNs/monitoring agents the
  analyst correctly dismisses — a **47% alert-volume reduction at perfect
  recall**.
- The rule baseline misses the moderate DDoS flood (window volume ≈130 < 150
  threshold); the agent catches it by reasoning over the 40+ req/min burst.
- Latency is window-quantised (5 min resolution); the agent adds no latency
  beyond triage.

## 6. How to Run

```bash
pip install -r requirements.txt
python main.py demo                 # offline, ~1 s, reproduces results above
python main.py evaluate --llm openai  # with LLM analyst (set OPENAI_API_KEY)
python main.py analyze --logs logs.csv
python -m pytest tests/ -q          # 21 tests pass
```

## 7. Answers to likely viva questions

**Q: Why synthetic data?** A: Real labelled logs are scarce, stale, or
proprietary. A seeded generator gives exact ground truth (attack windows,
attacker IPs) so every metric is measurable and every run reproducible —
essential for a fair system comparison. The same schema is used by our public
`analyze` command on real logs (unlabelled mode).

**Q: Why Z-scores and not ML?** A: Z-scores are explainable, parameter-light,
and O(n) — a SOC can state *why* an IP was flagged. DeepLog/Loglizer learn
structure but can't say *what* the threat is; that semantic layer is exactly
what the LLM adds.

**Q: What if the LLM hallucinates?** A: Strict-JSON schema + validation + retry;
a confidence gate (<0.6 → human review) and a deterministic fallback guarantee
the pipeline never silently mislabels; the report always cites evidence rows.

**Q: Is it cost-feasible?** A: Yes. Stage 1+2 cost ~nothing; only flagged IPs
reach the LLM (17/53 here); token ledger records spend per run; `max_agent_ips`
caps worst case.

**Q: How is this different from a SIEM with rules?** A: SIEM rules are the
*baseline* here (Stage 2). The novelty is the agentic arbiter over fused
evidence — it recovers threshold-miss attacks and explains decisions in natural
language with MITRE mapping, which rules cannot do.

## 8. Individual Contributions

- **Yash Nimbalkar:** statistical feature engineering, Z-score engine, rule
  baseline, evaluation metrics.
- **Darshan Nikrad:** agentic layer (enrichment/analyst/report), LLM client &
  guardrails, pipeline assembly, CLI, documentation.

*(Adjust to match actual split.)*
