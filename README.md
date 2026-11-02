# 🛡️ Autonomous AI SecOps Log Analyzer

> An Evidence-Grounded Agentic Framework for Security Incident Detection, Correlation, and Threat Prioritization

[![Tests](https://img.shields.io/badge/tests-95%2F95%20passing-brightgreen)](#test-results)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)

---

## 📖 Overview

A complete security analytics platform that:

- **Ingests** network/application logs (CSV, JSON, JSONL)
- **Detects** suspicious activity using 9 explainable detectors + ML anomaly detection
- **Correlates** events into incidents using graph-based clustering
- **Investigates** incidents using a controlled AI agent with 7 purpose-built tools
- **Prioritizes** threats with transparent, multi-factor scoring
- **Reports** findings with evidence-backed JSON, CSV, and PDF reports
- **Visualizes** everything through an interactive SOC dashboard

### Key Features

| Feature | Details |
|---------|---------|
| 🔍 **9 Detection Strategies** | DoS, brute force, port scan, HTTP anomalies, path traversal, SQL injection, data exfiltration, auth anomalies, Isolation Forest |
| 🔗 **Graph-Based Correlation** | Groups 28 detections → 15 incidents (46% workload reduction) |
| 🤖 **Agentic Investigation** | 7 tools with safety guardrails, prompt injection defense |
| 📊 **100% Evidence Attribution** | Zero fabricated evidence, zero unsupported claims |
| 🔒 **Works Fully Offline** | No API keys required — optional LLM enhancement |
| 🧪 **95 Tests Passing** | Unit, integration, and security test suites |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11 or higher
- pip package manager
- ~500MB disk space (including dependencies)

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ai-secops-analyzer.git
cd ai-secops-analyzer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Run Everything (One Command)

```bash
chmod +x examples/run_test.sh
./examples/run_test.sh
```

This runs all tests, generates data, executes experiments, and tests the API.

### Step-by-Step Usage

#### 1. Generate Sample Data
```bash
python -m src.evaluation.synthetic_data data/sample
# Output: 910 records (CSV, JSON, JSONL) + ground truth labels
```

#### 2. Run Tests
```bash
python -m pytest tests/ -v
# Expected: 95 passed
```

#### 3. Run Evaluation Experiments
```bash
python -m src.evaluation.run_experiments
# Results saved to data/results/experiment_results.json
```

#### 4. Start the Backend API
```bash
python -m uvicorn src.api.main:app --port 8000
# API docs at http://localhost:8000/docs
```

#### 5. Start the Dashboard
```bash
# In a new terminal (with venv activated)
streamlit run src/dashboard/app.py
# Dashboard at http://localhost:8501
```

---

## 📡 API Usage

### Upload a Log File
```bash
curl -X POST http://localhost:8000/api/v1/upload \
  -F "file=@examples/attack_scenario.csv"
```

### Run Analysis
```bash
curl -X POST http://localhost:8000/api/v1/analyze/{job_id}
```

### Get Detections
```bash
curl http://localhost:8000/api/v1/detections/{job_id}
```

### Get Incidents
```bash
curl http://localhost:8000/api/v1/incidents/{job_id}
```

### Investigate an Incident (Offline AI)
```bash
curl -X POST http://localhost:8000/api/v1/investigate/{incident_id} \
  -H "Content-Type: application/json" \
  -d '{"provider": "offline"}'
```

### Generate Report
```bash
# JSON report
curl http://localhost:8000/api/v1/reports/{job_id}?format=json

# CSV report
curl http://localhost:8000/api/v1/reports/{job_id}?format=csv
```

### Full API Documentation
Start the server and visit: **http://localhost:8000/docs**

---

## 📁 Testing Examples

The `examples/` directory contains ready-to-use test files:

| File | Description | Expected Detections |
|------|-------------|-------------------|
| `normal_traffic.csv` | Clean traffic — should produce zero or minimal detections | None |
| `attack_scenario.csv` | Multi-stage attack: brute force → SQLi → path traversal → data exfil | Brute force, injection, path traversal, data exfiltration |
| `dos_attack.jsonl` | High-frequency requests (DoS simulation) in JSONL format | DoS / request flooding |
| `mixed_traffic.json` | JSON format with normal + attack traffic mixed | Injection, path traversal |

### Testing with Example Files

```bash
# Start the backend
python -m uvicorn src.api.main:app --port 8000

# Upload and analyze the attack scenario
JOB_ID=$(curl -s -X POST http://localhost:8000/api/v1/upload \
  -F "file=@examples/attack_scenario.csv" | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])")

curl -s -X POST http://localhost:8000/api/v1/analyze/$JOB_ID | python3 -m json.tool

# View detections
curl -s http://localhost:8000/api/v1/detections/$JOB_ID | python3 -m json.tool
```

---

## 🏗️ Architecture

```
┌──────────────┐    ┌────────────────┐    ┌──────────────────┐
│  Ingestion   │───▶│   Detection    │───▶│   Correlation    │
│ CSV/JSON/JSONL│   │ 9 Rules + ML   │    │  Graph-Based     │
└──────────────┘    └────────────────┘    └────────┬─────────┘
                                                   │
┌──────────────┐    ┌────────────────┐    ┌────────▼─────────┐
│  Reporting   │◀───│ Prioritization │◀───│  Investigation   │
│ JSON/CSV/PDF │    │  Multi-factor  │    │  7 Tools + Agent │
└──────────────┘    └────────────────┘    └──────────────────┘
       │
┌──────▼───────┐    ┌────────────────┐
│  Dashboard   │    │  FastAPI +     │
│  (Streamlit) │◀──▶│  SQLite DB     │
└──────────────┘    └────────────────┘
```

### Module Structure

```
src/
├── api/            # FastAPI backend (routes, schemas)
├── ingestion/      # Log parsing, validation, normalization
├── detection/      # 9 detectors + baselines + engine
├── correlation/    # Graph-based event correlation
├── investigation/  # AI agent + 7 tools + LLM providers
├── prioritization/ # Multi-dimensional threat scoring
├── reporting/      # JSON, CSV, PDF report generation
├── dashboard/      # Streamlit SOC dashboard
├── evaluation/     # Experiment framework + synthetic data
├── database/       # SQLAlchemy ORM + repository
└── utils/          # Config, models, security, helpers
```

---

## 🧪 Test Results

```
======================== 95 passed, 0 failed ========================
```

| Test Category | Count | Coverage |
|---------------|-------|----------|
| Unit Tests | 52 | All modules |
| Integration Tests | 10 | Full pipeline E2E |
| Security Tests | 33 | Injection, sanitization, access control |

---

## 📊 Experiment Results

Five-condition ablation study on 910 synthetic security events:

| Condition | Description | Precision | Recall | F1 | Evidence Acc. |
|-----------|-------------|-----------|--------|-----|--------------|
| A | Rule-based only | 0.419 | 0.295 | 0.346 | 100% |
| B | + Statistical anomaly | 0.424 | 0.307 | 0.356 | 100% |
| C | + Correlation + investigation | 0.424 | 0.307 | 0.356 | 100% |
| D | + LLM investigation | 0.424 | 0.307 | 0.356 | 100% |
| E | Complete agentic framework | 0.424 | 0.307 | 0.356 | 100% |

**Key findings:**
- Statistical detection: +1.2pp recall improvement
- Correlation: 46% workload reduction (28 → 15 incidents)
- Evidence accuracy: 100% across all conditions, 0% unsupported claims

---

## ⚙️ Configuration

### Environment Variables (`.env`)

```bash
# LLM Providers (all optional - works without any API key)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_API_KEY=AIza...
LLM_PROVIDER=offline  # offline | openai | anthropic | google | local

# Database
DATABASE_URL=sqlite:///./secops_analyzer.db

# Server
API_HOST=0.0.0.0
API_PORT=8000

# Security
SECRET_KEY=change-this-in-production
MAX_UPLOAD_SIZE_MB=100
MAX_TOOL_CALLS_PER_INVESTIGATION=20
```

Copy `.env.example` to `.env` and configure as needed.

---

## 📄 Documentation

| Document | Description |
|----------|-------------|
| [Research Paper](docs/RESEARCH_PAPER.md) | Full IEEE-format research paper with results |
| [Technical Report](docs/TECHNICAL_REPORT.md) | Comprehensive technical documentation |
| [Research Manuscript](docs/RESEARCH_MANUSCRIPT.md) | Academic manuscript with methodology |
| [API Documentation](docs/api/API_DOCUMENTATION.md) | Complete API reference |
| [Reproducibility Guide](docs/REPRODUCIBILITY_GUIDE.md) | Step-by-step reproduction instructions |
| [Feature Verification](docs/FEATURE_VERIFICATION.md) | Test matrix with 95/95 results |
| [Viva Questions](docs/VIVA_QUESTIONS.md) | 32 Q&A for project defense |
| [Presentation Outline](docs/PRESENTATION_OUTLINE.md) | 18-slide presentation guide |

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python, FastAPI, Uvicorn |
| Data Processing | Pandas, NumPy |
| Machine Learning | scikit-learn (Isolation Forest) |
| Database | SQLAlchemy, SQLite |
| Dashboard | Streamlit, Plotly |
| Validation | Pydantic |
| Testing | pytest (95 tests) |
| AI Investigation | Configurable LLM (offline/cloud/local) |

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- MITRE ATT&CK Framework for threat taxonomy
- NIST SP 800-61r2 for incident handling guidelines
- scikit-learn for Isolation Forest implementation
- FastAPI and Streamlit communities
