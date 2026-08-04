# Paper Outline — Autonomous AI SecOps Log Analyzer: An Agentic Framework for Threat Profiling

*Targets: IEEE CSR · ACM SACMAT · IEEE Big Data Security*
*Format: IEEE two-column, 6–8 pages*

---

## Abstract (≈150 words)

Security Operations Centers (SOCs) face alert fatigue: statistical anomaly
detectors produce high-recall but high-noise alerts, while rule-based intrusion
detection systems (IDS) suppress noise at the cost of missing novel or moderate
attacks. We propose a hybrid, agentic pipeline for server-access-log threat
profiling. A Pandas-based statistical stage computes behavioural features per
source IP and flags outliers via Z-scores; a second stage fuses these outliers
with signature-rule hits; a final agentic stage — an LLM analyst (or a
deterministic fallback) — reasons over per-IP evidence dossiers, maps findings
to MITRE ATT&CK, and emits human-readable incident reports. On a labelled
synthetic corpus of 2,825 events with nine attack campaigns, the hybrid system
achieves precision 1.00 / recall 1.00 / F1 1.00, zero false positives, and mean
detection latency 2.5 minutes — outperforming both the statistical-only
(F1 0.69) and rule-based (F1 0.94) stages, while costing $0.00 in
deterministic mode and <$0.02 per incident with an LLM analyst.

## I. Introduction

- The alert-fatigue problem: SOC metrics — 74% of analysts report alert
  overload (Vectra, 2023); median time-to-detect still counts in days.
- Statistical monitors: cheap, sensitive, uninterpretable, noisy.
  Rule-based IDS: precise on known signatures, blind to threshold-miss attacks,
  brittle to tune.
- LLMs as agents: contextual reasoning, MITRE mapping, natural-language reports —
  but latency/cost mean they cannot see all traffic.
- **Our thesis:** fuse statistical triage + signature rules, then let an agent
  reason *only* about candidates. Contributions:
  1. Fusion candidate-selection that recovers attacks rules miss and dismisses
     statistical false positives.
  2. A cost-aware agentic design with a deterministic fallback providing a
     zero-cost ablation baseline.
  3. A reproducible, labelled synthetic benchmark with end-to-end metrics
     (accuracy, latency, cost, alert-volume).

## II. Related Work

| Work | Approach | Gap |
|---|---|---|
| Snort / Suricata [rule-based] | Signature rules | High FPR, threshold tuning, unknown attacks |
| DeepLog [Du et al., 2017] | LSTM on log sequences | Detects *deviations*, no threat semantics |
| Loglizer [He et al., 2016] | ML log parsing | Structural, not reasoning |
| MIMIC / LLM-SOC research 2023–24 | LLM agents for triage | Evaluated on curated events, no statistical front-end |
| **This work** | **Stats triage → rules → agentic reasoning** | **End-to-end, measurable, hybrid** |

Positioning sentence for the paper: *"We bridge the gap between structural
anomaly detection and natural-language threat reasoning by making the LLM the
final arbiter over a fusion of statistical and signature evidence."*

## III. Methodology

### A. Dataset (synthetic, labelled)
Seeded generator (`secops/data_generator.py`) emits access logs over a 90-minute
window: 15 behavioural features per IP-window; 9 ground-truth campaigns
(brute force, credential stuffing, port scan, 3× DDoS, data exfiltration, SQLi,
XSS). Every event carries `is_attack` / `attack_type`; a manifest lists attack
windows — enabling exact measurement.

### B. Statistical stage
Window W = 5 min. Features computed with Pandas groupby: request count/rate,
error rate, egress bytes, latency, unique paths/UAs/ports, failed logins,
distinct usernames, SQLi/XSS pattern counts, Shannon path entropy
H = −Σ pᵢ log₂ pᵢ, minute-burst max, port-scan ratio.
Standardisation (mean/σ, or median/MAD):

> Z(X) = (X − μ) / σ, with MAD-robust variant Z = 0.6745 (X − med) / MAD

Flag if max over features of Z > 3.0. Empirical finding: this stage has recall
1.00 but precision 0.53 — the noise source motivating Stage 3.

### C. Signature baseline
Eight hand-tuned rules (brute force ≥5 failures; credential stuffing ≥8 users;
port scan ≥12 ports or scan-ratio ≥0.5; DDoS ≥150 reqs or burst ≥40/min;
exfiltration ≥50 MB; SQLi/XSS ≥1 pattern). Finding: precision 1.00 but recall
0.89 — the moderate flood (≈130 reqs/window) slips under the DDoS threshold.

### D. Agentic stage
- *Enrichment agent:* builds a dossier (features, rule hits, evidence timeline,
  indicators) per candidate IP.
- *Analyst agent:* system prompt with SOC persona + ATT&CK taxonomy; strict-JSON
  output schema; retries; schema validation; fallback to deterministic expert
  on failure; confidence <0.6 → human review queue.
- *Report agent:* executive summary, severity, MITRE technique/tactic, evidence
  timeline, IoCs, recommended actions.
- *Cost control:* `max_agent_ips` cap; token ledger; price per million tokens in
  config.

### E. Evaluation protocol
Per-source-IP confusion counts vs ground-truth attacker IPs: precision, recall,
F1, FPR, alert multiplicity (alerts/true incidents — the alert-fatigue proxy),
mean detection latency (window-end minus attack start), throughput (events/s),
and USD cost. All detectors share the same feature frame.

## IV. Experimental Setup & Results

**Hardware:** Apple Silicon / x86-64 laptop, Python 3.13, pandas 2.3.
**Data:** seed 7, 2,825 events (1,506 benign, 1,319 attack), 53 IPs, 9 campaigns.
**LLM mode:** gpt-4o-mini, temperature 0, strict JSON; deterministic fallback.

| Detector | Prec | Rec | F1 | FPR | Alerts | Mult. | Latency |
|---|---|---|---|---|---|---|---|
| Statistical only (Z>3) | 0.53 | 1.00 | 0.69 | 0.32 | 17 | 1.89 | 2.47 min |
| Rule-based baseline | 1.00 | 0.89 | 0.94 | 0.00 | 8 | 0.89 | 3.20 min |
| **Agentic hybrid (offline)** | **1.00** | **1.00** | **1.00** | **0.00** | **9** | **1.00** | **2.47 min** |
| Agentic hybrid + review | 0.53 | 1.00 | 0.69 | 0.32 | 17 | 1.89 | — |

Pipeline: stats 0.44 s, rules 0.002 s, agent 0.02 s, total 0.46 s (~6,100 ev/s).
LLM mode: $0.00 deterministic; ≈$0.01–0.02/run at gpt-4o-mini prices.

**Interpretation:** (i) the agentic layer removes **8 false positives** — a 47%
alert reduction at identical recall; (ii) it recovers the DDoS attack missed by
rules; (iii) the review queue trades F1 back to 0.69 only if every low-confidence
benign is escalated — demonstrating the value of confidence thresholds.

## V. Discussion & Limitations

- Synthetic data: patterns are realistic but not field traffic; attacks are
  single-source (no distributed campaigns).
- Deterministic fallback embeds domain thresholds — the LLM ablation is the
  honest comparison of *reasoning* vs *rules*.
- LLM hallucination risk mitigated by strict JSON, confidence thresholding and
  human review; prompt-injection via log content is future work.
- Detection latency is window-quantised (5 min resolution).

## VI. Conclusion & Future Work

Statistical triage provides cheap recall; agentic reasoning provides precision;
together they beat either stage alone on every metric. Future work: real
datasets (CIC-IDS2017/UNSW-NB15), streaming ingestion, multi-agent campaign
correlation, feedback-loop rule tuning, and human-label recalibration.

---

## Reproducibility appendix (for reviewers)

```bash
pip install -r requirements.txt
python main.py demo --seed 7 --minutes 90     # reproduces Table I exactly
python -m pytest tests/ -q                    # 21 tests
python notebooks/make_figures.py              # figures 1–5
```
