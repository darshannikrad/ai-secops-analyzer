#!/usr/bin/env bash
# ============================================================================
# AI SecOps Log Analyzer - Quick Test Script
# Run this to verify the entire system works end-to-end
# ============================================================================

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"
PYTHON="$PROJECT_DIR/venv/bin/python"

echo "=============================================="
echo "  AI SecOps Log Analyzer - System Test"
echo "=============================================="

# Check venv exists
if [ ! -f "$PYTHON" ]; then
    echo "❌ Virtual environment not found. Run setup first:"
    echo "   python3 -m venv venv && venv/bin/pip install -r requirements.txt"
    exit 1
fi

echo ""
echo "📋 Step 1: Running test suite..."
echo "----------------------------------------------"
$PYTHON -m pytest tests/ -v --tb=short
echo "✅ All tests passed!"

echo ""
echo "📋 Step 2: Generating synthetic dataset..."
echo "----------------------------------------------"
$PYTHON -m src.evaluation.synthetic_data data/sample
echo "✅ Dataset generated!"

echo ""
echo "📋 Step 3: Running evaluation experiments..."
echo "----------------------------------------------"
$PYTHON -m src.evaluation.run_experiments
echo "✅ Experiments completed! Results in data/results/"

echo ""
echo "📋 Step 4: Testing API endpoints..."
echo "----------------------------------------------"
# Start server in background
$PYTHON -m uvicorn src.api.main:app --port 8000 &
SERVER_PID=$!
sleep 3

# Health check
echo "  → Health endpoint:"
curl -s http://127.0.0.1:8000/api/v1/health | python3 -m json.tool

# Upload example file
echo ""
echo "  → Uploading attack_scenario.csv..."
UPLOAD_RESPONSE=$(curl -s -X POST http://127.0.0.1:8000/api/v1/upload \
    -F "file=@examples/attack_scenario.csv")
echo "$UPLOAD_RESPONSE" | python3 -m json.tool

# Extract job ID and run analysis
JOB_ID=$(echo "$UPLOAD_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])")
echo ""
echo "  → Running analysis on job $JOB_ID..."
curl -s -X POST "http://127.0.0.1:8000/api/v1/analyze/$JOB_ID" | python3 -m json.tool

# Get detections
echo ""
echo "  → Detection results:"
curl -s "http://127.0.0.1:8000/api/v1/detections/$JOB_ID" | python3 -m json.tool | head -30

# Get report
echo ""
echo "  → Generating report..."
curl -s "http://127.0.0.1:8000/api/v1/reports/$JOB_ID?format=json" | python3 -m json.tool | head -20

# Clean up
kill $SERVER_PID 2>/dev/null || true
echo ""
echo "✅ API tests completed!"

echo ""
echo "=============================================="
echo "  ✅ ALL SYSTEM TESTS PASSED"
echo "=============================================="
echo ""
echo "To start the dashboard:"
echo "  venv/bin/python -m uvicorn src.api.main:app --port 8000 &"
echo "  venv/bin/streamlit run src/dashboard/app.py"
