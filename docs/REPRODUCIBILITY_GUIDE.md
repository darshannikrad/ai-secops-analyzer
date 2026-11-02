# AI SecOps Log Analyzer: Research Reproducibility Guide

This guide provides step-by-step instructions for reproducing all experiments, datasets, benchmarks, and results described in the research manuscript.

---

## 1. Environment Setup

### 1.1 Hardware and OS Requirements
- **Operating System:** macOS (macOS 12+), Ubuntu Linux 22.04 LTS, or Windows 11 with WSL2.
- **Python Version:** Python 3.10, 3.11, 3.12, 3.13, or 3.14.
- **Memory:** Minimum 4 GB RAM (8 GB recommended).
- **Disk Space:** 500 MB free space for code, dependencies, and cached results.

### 1.2 Virtual Environment Initialization
Clone the repository and initialize an isolated Python environment:

```bash
# Navigate to project root
cd /Users/darshannikrad/.gemini/antigravity/scratch/ai-secops-analyzer

# Create virtual environment (if not already present)
python3 -m venv venv

# Activate virtual environment
# On macOS / Linux:
source venv/bin/activate
# On Windows (cmd/PowerShell):
# .\venv\Scripts\Activate.ps1

# Upgrade package installers
pip install --upgrade pip setuptools wheel

# Install required dependencies
pip install -r requirements.txt
```

### 1.3 LLM Provider Configuration (Optional)
The evaluation framework includes a fully deterministic offline mode (`provider="offline"`) that executes without external API keys or network calls.

If evaluating online LLM providers, set the appropriate environment variables in `.env` or in your active terminal:

```bash
# OpenAI Models (e.g. gpt-4o, gpt-4o-mini)
export OPENAI_API_KEY="sk-..."

# Anthropic Models (e.g. claude-3-5-sonnet)
export ANTHROPIC_API_KEY="sk-ant-..."

# Google Gemini Models (e.g. gemini-1.5-pro)
export GOOGLE_API_KEY="AIza..."

# Local Ollama Engine (Default: http://localhost:11434)
export OLLAMA_HOST="http://localhost:11434"
```

---

## 2. Dataset Generation

The evaluation framework uses a fully deterministic synthetic security dataset generator located at `src/evaluation/synthetic_data.py`. Random generation is pinned to seed `42` to guarantee identical byte-level output across platforms.

### Generating the Standard Benchmark Dataset
Run the data generator standalone via Python:

```bash
python -c "
from src.evaluation.synthetic_data import generate_full_dataset
records, ground_truth = generate_full_dataset(normal_count=500, seed=42, output_dir='data/sample')
print(f'Generated {len(records)} records ({sum(1 for g in ground_truth if g.get(\"is_malicious\"))} malicious).')
"
```

Output files created:
- `data/sample/synthetic_dataset.csv`: 500 benign records combined with attack scenario events.
- `data/sample/ground_truth.json`: Event-by-event classification annotations (`is_malicious`, `attack_type`, `expected_detection`).

### Attack Scenarios Embedded in Dataset
1. **Brute Force & Credential Stuffing:** 20 rapid authentication failures on target account `admin` from IP `198.51.100.25`, followed by privilege escalation.
2. **SQL Injection (SQLi) & Data Exfiltration:** Union-based payload injections against `/api/users?id=1%20UNION%20SELECT...` followed by massive outbound egress responses (>50,000 bytes).
3. **Path Traversal & Command Injection:** File evasion queries (`/static/../../etc/passwd`) and operating system command separators (`; id; cat /etc/shadow`).
4. **Denial of Service (DoS):** Volumetric request bursts targeting `/search` within a narrow temporal window.

---

## 3. Running Experiments

### 3.1 Executing the Standard Evaluation Benchmark
To run all five experimental conditions (A through E) and generate comparative metrics, execute:

```bash
python -m src.evaluation.run_experiments
```

### 3.2 What the Script Executes
The runner executes sequentially:
1. **Condition A:** Rule-based detection only (no statistical baselines, no correlation).
2. **Condition B:** Rules + statistical anomaly detection (Z-score + IQR).
3. **Condition C:** Detection + correlation + deterministic rule-based investigation.
4. **Condition D:** Detection + correlation + LLM-only ungrounded investigation.
5. **Condition E:** Full platform with tool-using agentic investigation and evidence provenance checking.

All results are written to `data/results/`:
- `data/results/evaluation_summary.csv`: Machine-readable CSV comparing precision, recall, F1, FPR, latency, and attribution accuracy.
- `data/results/evaluation_summary.json`: Detailed JSON containing full experiment metadata, configuration snapshots, and tool call traces.

---

## 4. Interpreting Results

When `run_experiments.py` finishes, it outputs a Markdown table summarizing the metrics:

```text
============================================================
AI SecOps Log Analyzer - Evaluation Experiments
============================================================
...
+-----------+-----------------------------------+-----------+--------+----------+-------+
| Condition | Description                       | Precision | Recall | F1-Score | FPR   |
+-----------+-----------------------------------+-----------+--------+----------+-------+
| A         | Rule-based detection only         | ...       | ...    | ...      | ...   |
| B         | Rules + statistical anomaly       | ...       | ...    | ...      | ...   |
| C         | Detection + corr + deterministic  | ...       | ...    | ...      | ...   |
| D         | Detection + corr + LLM-only       | ...       | ...    | ...      | ...   |
| E         | Complete agentic framework        | ...       | ...    | ...      | ...   |
+-----------+-----------------------------------+-----------+--------+----------+-------+
```

### Key Metrics Defined:
- **Precision ($P$):** Proportion of flagged log records that were genuinely malicious.
- **Recall ($R$):** Proportion of actual attack records correctly flagged.
- **F1-Score ($F_1$):** Harmonic mean of Precision and Recall.
- **False Positive Rate (FPR):** Benign events erroneously labeled as malicious ($FP / (FP + TN)$).
- **Evidence Attribution Accuracy (%):** Percentage of cited log event IDs and IP addresses that actually exist in the ingested telemetry.
- **Unsupported Claim Rate (%):** Frequency of analytical assertions that lack valid event pointer links.

---

## 5. Configuration Parameters

System behavior is configured through `src/utils/config.py` and environment overrides:

| Parameter | Default Value | Description |
|:---|:---|:---|
| `APP_ENV` | `development` | Runtime environment (`development`, `testing`, `production`) |
| `DATABASE_URL` | `sqlite:///./secops.db` | SQLAlchemy connection string |
| `LLM_PROVIDER` | `offline` | Default investigation provider (`offline`, `openai`, `anthropic`, `google`, `ollama`) |
| `LLM_MODEL` | `offline-heuristic-v1` | Model name when provider is online |
| `MAX_UPLOAD_SIZE_MB` | `100` | Maximum allowable upload file size |
| `CORRELATION_TIME_WINDOW_SECONDS` | `300` | Sliding window delta for temporal alert grouping |
| `STATISTICAL_ZSCORE_THRESHOLD` | `3.0` | Number of standard deviations for Z-score anomaly detector |
| `STATISTICAL_IQR_MULTIPLIER` | `1.5` | Multiplier for Interquartile Range anomaly fence |

---

## 6. Running Interactive Services

### 6.1 Launching the FastAPI Backend Gateway
```bash
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive OpenAPI documentation will be accessible at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### 6.2 Launching the Streamlit SOC Dashboard
In a secondary terminal window:
```bash
source venv/bin/activate
streamlit run src/dashboard/app.py --server.port 8501
```
Open `http://localhost:8501` in your browser. Navigate to the **🧪 Research Evaluation** page to trigger and visualize benchmarks directly from the GUI.

---

## 7. Troubleshooting & Common Issues

### Issue 1: `ModuleNotFoundError: No module named 'src'`
**Cause:** Python path does not include the project root.  
**Resolution:** Run scripts using module notation (`python -m src.evaluation.run_experiments`) or export `PYTHONPATH`:
```bash
export PYTHONPATH="/Users/darshannikrad/.gemini/antigravity/scratch/ai-secops-analyzer:$PYTHONPATH"
```

### Issue 2: Streamlit Dashboard displays `⚠️ Backend API not reachable`
**Cause:** The FastAPI gateway process is not running on port 8000.  
**Resolution:** Verify that `uvicorn` is active:
```bash
curl -s http://localhost:8000/api/v1/health
# Expected response: {"status":"ok","version":"1.0.0","database_ok":true,...}
```

### Issue 3: Ingestion fails with `422 Unprocessable Entity`
**Cause:** The uploaded CSV or JSON file lacks required timestamps or source IP fields.  
**Resolution:** Verify that log files contain standard field headers: `timestamp`, `source_ip` (or `client_ip`), and `message` (or `request_path`). Refer to `data/sample/synthetic_dataset.csv` as a baseline reference.
