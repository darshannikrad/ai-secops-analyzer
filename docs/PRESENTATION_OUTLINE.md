# AI SecOps Log Analyzer: Project Review Presentation Outline

**Presentation Format:** 18-Slide Technical & Academic Defense Deck  
**Target Duration:** 20–25 Minutes + Q&A  
**Audience:** Technical Advisory Committee, Academic Review Board, Security Leaders  

---

## Slide 1: Title & Executive Overview
- **Header:** Autonomous AI SecOps Log Analyzer
- **Subtitle:** Evidence-Grounded Agentic Investigation for Cyber-Threat Triage
- **Presenter Information:** AI SecOps Research Group / Engineering Team
- **Key Talking Points:**
  - Introduce the core mission: solving the tier-1 SOC triaging bottleneck using evidence-grounded autonomous AI.
  - Highlight the key paradigm shift: moving away from ungrounded, hallucination-prone LLM chatbots toward a tool-sandboxed, hypothesis-driven forensic reasoning system.
  - State the primary contribution: verifiable evidentiary provenance, multi-pass incident correlation, and a formal 5-condition empirical evaluation.

---

## Slide 2: The Modern SOC Crisis (Problem Statement)
- **Header:** The Alert Fatigue & Triaging Bottleneck
- **Visuals / Metrics:**
  - Infographic showing 10,000+ raw daily alerts $\to$ 80% false-positive rate.
  - Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) measured in days/weeks.
  - Analyst burnout and cognitive overload leading to missed high-severity intrusions.
- **Key Talking Points:**
  - Enterprise SOCs are inundated with low-level telemetry across firewalls, proxies, and cloud runtimes.
  - Most alerts are evaluated in isolation, obscuring coordinated multi-stage attack campaigns.
  - Existing automation (SOAR) is brittle and limited to rigid static scripts that cannot reason about novel, multi-faceted threats.

---

## Slide 3: The Perils of Naive LLM Deployment in SecOps
- **Header:** Why Direct LLM Integration Fails in High-Stakes Security
- **Bullet Points:**
  - **Hallucination of Threat Artifacts:** Fabrication of non-existent IP addresses, timestamps, and CVE identifiers.
  - **Context Window Saturation:** Inability to ingest multi-gigabyte log streams without extreme latency and cost.
  - **Indirect Prompt Injection:** Adversaries embedding prompt overrides inside HTTP headers or usernames.
- **Key Talking Points:**
  - Demonstrating that while LLMs possess strong contextual reasoning, deploying them as conversational black-boxes creates critical vulnerabilities in security infrastructure.
  - Emphasize the necessity of architectural scaffolding: models must be constrained by external tools and verified evidence checks.

---

## Slide 4: Proposed Solution & Research Objectives
- **Header:** Evidence-Grounded Agentic Investigation Framework
- **Key Tenets:**
  - **1. Hybrid Detection:** Deterministic rules + statistical baseline anomaly estimation.
  - **2. Multi-Pass Correlation:** Entity, temporal ($\Delta t \le 300\text{s}$), and MITRE ATT&CK attack chain clustering.
  - **3. Dynamic Risk Prioritization:** Multi-factor weighted scoring ($P_1$–$P_4$).
  - **4. Dual-Hypothesis Agentic Triage:** Systematic evaluation of Malicious ($H_1$) vs. Benign ($H_0$).
  - **5. Strict Evidentiary Provenance:** Automated rejection of claims lacking immutable event ID anchors.
- **Key Talking Points:**
  - Outline how the system balances speed, explainability, and forensic rigor.
  - Introduce our research goal: bridging the reliability gap of foundation models in security operations.

---

## Slide 5: System Architecture & Layered Design
- **Header:** Decoupled Five-Tier Architecture
- **Visual:** Architectural block diagram showing:
  - Presentation Layer (Streamlit Dashboard)
  - Interface Layer (FastAPI REST Gateway `/api/v1`)
  - Analytics Layer (Ingestion, Detection, Correlation, Prioritization)
  - Agent Tooling Subsystem (Sandboxed Read-Only APIs)
  - Persistence Layer (SQLAlchemy 2.0 ORM + SQLite/PostgreSQL)
- **Key Talking Points:**
  - Walk through the strict separation of concerns.
  - Explain how the REST API acts as a secure boundary, keeping frontend views completely stateless and decoupled from analytical logic.

---

## Slide 6: Telemetry Ingestion & Normalization
- **Header:** Normalization to Open Cybersecurity Schema (OCSF)
- **Key Features:**
  - Multi-format ingestion support: CSV, JSON arrays, JSONL streams.
  - Automatic schema sniffing and field normalization (`client_ip`, `c-ip` $\to$ `source_ip`).
  - Strict UTC timestamp conversion and malformed record segregation.
- **Key Talking Points:**
  - Normalization prevents a combinatorial explosion of detection rules across vendor syntaxes.
  - Segregating malformed records into audit logs guarantees pipeline resilience without discarding forensic evidence.

---

## Slide 7: Hybrid Detection Engine
- **Header:** Combining Deterministic Signatures with Statistical Baselines
- **Two Columns:**
  - **Deterministic Rule Detectors:**
    - Brute-force authentication bursts.
    - SQL injection (SQLi) & command injection regex matching.
    - Directory and path traversal (`../`, `%2e%2e/`).
    - Volumetric Denial of Service (DoS) floods.
  - **Statistical Baseline Detector:**
    - Parametric Z-score outlier detection ($\mu \pm 3\sigma$).
    - Non-parametric Interquartile Range (IQR) fencing ($Q_3 + 1.5 \times \text{IQR}$).
- **Key Talking Points:**
  - Why neither approach suffices alone: rules miss zero-days; pure statistics suffer high false-positive rates on normal business spikes.
  - The hybrid engine catches both signature-known exploits and anomalous volumetric exfiltration.

---

## Slide 8: Multi-Stage Incident Correlation Engine
- **Header:** Transforming Isolated Alerts into Unified Attack Chains
- **Algorithm Flow:**
  - *Pass 1: Entity Pivot Clustering* $\to$ Groups alerts by shared source IP, target host, or user.
  - *Pass 2: Temporal Proximity Fencing* $\to$ Clusters alerts occurring within $\Delta t \le 300\text{s}$ windows.
  - *Pass 3: Attack Chain Sequencing* $\to$ Maps progressions across the MITRE ATT&CK matrix (Recon $\to$ Credential Access $\to$ Execution $\to$ Exfiltration).
- **Key Talking Points:**
  - Demonstrate how 15 isolated alerts generated during a penetration test collapse into a single coherent incident.
  - Emphasize that correlation directly solves alert fatigue for the human operator.

---

## Slide 9: Risk Prioritization & Triage Scoring
- **Header:** Multi-Factor Incident Risk Quantification
- **Equation & Weights:**
  $$\text{Priority Score} = w_s S_{\text{base}} + w_c C_{\text{conf}} + w_a A_{\text{asset}} + w_v V_{\text{vol}}$$
- **Triage Matrix:**
  - $S \ge 80 \implies \text{P1\_CRITICAL}$ (Immediate Escalation)
  - $60 \le S < 80 \implies \text{P2\_HIGH}$ (Urgent Triage)
  - $40 \le S < 60 \implies \text{P3\_MEDIUM}$ (Standard Queue)
  - $S < 40 \implies \text{P4\_LOW}$ (Informational / Background)
- **Key Talking Points:**
  - Explain how asset criticality multipliers prevent junior analysts from ignoring high-value database servers.
  - Dynamic score boosts occur if full MITRE ATT&CK kill-chain progression is confirmed.

---

## Slide 10: Investigation Agent Architecture
- **Header:** The Autonomous Evidence-Grounded Investigator
- **Key Subsystems:**
  - Orchestration engine supporting Offline Heuristic, Ollama, OpenAI, Anthropic, and Google Gemini.
  - Sandboxed tool dispatcher.
  - Provenance validation post-processor.
- **Key Talking Points:**
  - The model does not speak to the world directly; it operates inside an analytical runtime loop.
  - The offline mode guarantees that the entire research framework runs deterministically in air-gapped environments without API costs.

---

## Slide 11: Dual-Hypothesis Reasoning & Sandboxed Tooling
- **Header:** Formulating $H_1$ vs. $H_0$ & Tool Sandboxing
- **Diagram:**
  - Initial Incident $\to$ Formulate $H_1$ (Malicious) & $H_0$ (Benign).
  - Tool Invocation: `get_incident_details` $\to$ `get_related_events` $\to$ `get_baseline_comparison`.
  - Evidence Weighing: Supporting vs. Contradictory Telemetry.
  - Synthesized Finding: Verified Threat Assessment + Containment Runbook.
- **Key Talking Points:**
  - Dual-hypothesis testing eliminates confirmation bias by actively searching for benign explanations (e.g. scheduled backups, authorized scanner activity).
  - Seven read-only tools ensure the agent cannot cause operational damage to systems.

---

## Slide 12: Evidentiary Provenance & Prompt Injection Defense
- **Header:** Defensive Engineering in Agentic Systems
- **Defensive Measures:**
  - **Provenance Guarantee:** Every assertion in the report must explicitly cite verified `source_event_ids`. Fabricated IDs trigger automated rejection.
  - **Indirect Injection Filter:** Telemetry is pre-sanitized; prompt injection attempts in log headers are neutralized and escalated as independent alerts.
  - **Tag Quarantining:** All untrusted log payload data is quarantined within `<untrusted_telemetry>` blocks.
- **Key Talking Points:**
  - Detail how our architecture solves the two biggest security risks of LLMs: hallucinations and prompt hijacking.

---

## Slide 13: Database Schema & Entity Relationships
- **Header:** Relational Persistence via SQLAlchemy 2.0
- **Data Model:**
  - `AnalysisJobDB` (1) $\to$ (N) `DetectionDB`
  - `AnalysisJobDB` (1) $\to$ (N) `IncidentDB`
  - `IncidentDB` (1) $\to$ (N) `InvestigationDB`
  - `AnalysisJobDB` (1) $\to$ (N) `ReportDB`
- **Key Talking Points:**
  - Explain how cascade deletions maintain data integrity.
  - Highlight the balance between indexed scalar relational columns and flexible JSON fields for nested telemetry.

---

## Slide 14: REST API Gateway & System Integration
- **Header:** Programmatic Access via FastAPI (`/api/v1`)
- **Key Route Families:**
  - Ingestion: `POST /upload`
  - Analytics: `POST /analyze/{job_id}`
  - Operations: `GET /incidents/{job_id}`, `PATCH /incidents/{id}/status`
  - Investigation: `POST /investigate/{incident_id}`
  - Reporting: `GET /reports/{job_id}` (JSON / CSV)
- **Key Talking Points:**
  - High-throughput asynchronous endpoints with interactive OpenAPI / Swagger specifications.
  - Complete parity between UI actions and headless API operations.

---

## Slide 15: Experimental Evaluation Setup
- **Header:** Methodology: 5 Experimental Conditions (A–E)
- **Conditions Table:**
  - **Condition A:** Rule-based detection only.
  - **Condition B:** Rules + statistical anomaly baselines.
  - **Condition C:** Detection + correlation + deterministic triage.
  - **Condition D:** Detection + correlation + ungrounded LLM.
  - **Condition E:** Full platform with tool-augmented agentic investigation.
- **Key Talking Points:**
  - Explain how this ablation study isolates the exact performance benefit of each architectural stage.
  - Dataset: 500 benign records + multi-stage attack scenarios pinned to seed 42 for 100% reproducibility.

---

## Slide 16: Research Results & Benchmark Insights
- **Header:** Empirical Comparison Across Conditions
- **Key Takeaways & Metric Trends:**
  - Condition A achieves high precision on signatures but poor recall on volumetric exfiltration.
  - Condition B increases recall but produces higher raw false positives prior to correlation.
  - Condition C & E demonstrate that correlation reduces alert ticket volume by up to 80%.
  - Condition D (ungrounded LLM) exhibits high unsupported claim rates (~25–30%), whereas Condition E reduces unsupported claims to ~0%.
- **Key Talking Points:**
  - Walk through the metrics table.
  - Highlight how Condition E successfully merges high detection accuracy with zero-hallucination provenance.

---

## Slide 17: Interactive SOC Dashboard Demonstration
- **Header:** Operational Walkthrough in Streamlit
- **Demonstration Steps:**
  1. **Upload & Validate:** Drag-and-drop log file with real-time schema validation.
  2. **Security Overview:** Review global threat KPIs and severity distributions.
  3. **Incident Management:** Inspect correlated attack chain cards and update status.
  4. **AI Investigation:** Trigger real-time agent triage, view tool call execution traces, and inspect the dual-hypothesis breakdown.
  5. **Reports & Export:** Download compliance-ready JSON and CSV reports.
- **Key Talking Points:**
  - Showcase the intuitive UI designed specifically for SOC tier-1 and tier-2 analysts.
  - Emphasize that all UI cards reflect live backend API data.

---

## Slide 18: Limitations, Future Work & Conclusion
- **Header:** Conclusions & Next Horizons
- **Summary of Contributions:**
  - Evidence-grounded autonomous triage with verifiable provenance.
  - Multi-stage correlation reducing alert fatigue.
  - Open-source, reproducible benchmarking framework.
- **Future Horizons:**
  - Multi-agent adversarial debate (Forensic Examiner vs. Red-Team Challenger).
  - Distributed stream ingestion with Apache Kafka and Apache Flink.
  - Enterprise vector database integration for multi-million incident repositories.
- **Closing Statement:**
  - "By anchoring artificial intelligence to verified evidentiary tools and rigorous hypothesis testing, we make autonomous Security Operations both reliable and enterprise-ready."
- **Q&A Invitation:** Thank you — open for committee questions.
