"""
SOC-style Streamlit Dashboard for the AI SecOps Log Analyzer.

All metrics come from actual backend API responses. No hardcoded production results.
"""

import io
import json
import time
from datetime import datetime

import requests
import streamlit as st

# Page config
st.set_page_config(
    page_title="AI SecOps Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_BASE = "http://localhost:8000/api/v1"


def api_get(endpoint: str, params: dict | None = None) -> dict | None:
    """Make GET request to backend API."""
    try:
        resp = requests.get(f"{API_BASE}{endpoint}", params=params, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        else:
            st.error(f"API error {resp.status_code}: {resp.text[:200]}")
            return None
    except requests.ConnectionError:
        st.warning("⚠️ Backend API not reachable. Start it with: `python -m uvicorn src.api.main:app`")
        return None
    except Exception as e:
        st.error(f"API request failed: {e}")
        return None


def api_post(endpoint: str, data: dict | None = None, files: dict | None = None) -> dict | None:
    """Make POST request to backend API."""
    try:
        resp = requests.post(f"{API_BASE}{endpoint}", json=data, files=files, timeout=120)
        if resp.status_code in (200, 201):
            return resp.json()
        else:
            st.error(f"API error {resp.status_code}: {resp.text[:300]}")
            return None
    except requests.ConnectionError:
        st.warning("⚠️ Backend API not reachable.")
        return None
    except Exception as e:
        st.error(f"API request failed: {e}")
        return None


def api_patch(endpoint: str, data: dict) -> dict | None:
    """Make PATCH request to backend API."""
    try:
        resp = requests.patch(f"{API_BASE}{endpoint}", json=data, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        else:
            st.error(f"API error {resp.status_code}: {resp.text[:200]}")
            return None
    except Exception as e:
        st.error(f"API request failed: {e}")
        return None


# ============================================================
# Sidebar Navigation
# ============================================================
st.sidebar.title("🛡️ AI SecOps Analyzer")
st.sidebar.markdown("---")

pages = [
    "📊 Security Overview",
    "📤 Upload & Validate",
    "🔍 Detection Explorer",
    "🚨 Incident Management",
    "🤖 AI Investigation",
    "📋 Historical Analyses",
    "📄 Reports & Export",
    "🧪 Research Evaluation",
    "💚 System Health",
]
page = st.sidebar.radio("Navigation", pages, label_visibility="collapsed")


# ============================================================
# 1. Security Overview
# ============================================================
if page == "📊 Security Overview":
    st.title("📊 Security Overview Dashboard")

    # Fetch stats from API
    stats = api_get("/stats")

    if stats:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Analyses", stats.get("total_jobs", 0))
        col2.metric("Total Detections", stats.get("total_detections", 0))
        col3.metric("Active Incidents", stats.get("active_incidents", 0))
        col4.metric("Investigations", stats.get("total_investigations", 0))

        st.markdown("---")

        # Recent activity
        col_left, col_right = st.columns(2)

        with col_left:
            st.subheader("Detection Type Distribution")
            det_dist = stats.get("detection_type_distribution", {})
            if det_dist:
                try:
                    import plotly.express as px
                    fig = px.pie(
                        names=list(det_dist.keys()),
                        values=list(det_dist.values()),
                        title="Detections by Type",
                    )
                    st.plotly_chart(fig, use_container_width=True)
                except ImportError:
                    st.bar_chart(det_dist)
            else:
                st.info("No detection data yet. Upload and analyze a log file to begin.")

        with col_right:
            st.subheader("Severity Distribution")
            sev_dist = stats.get("severity_distribution", {})
            if sev_dist:
                try:
                    import plotly.express as px
                    colors = {"CRITICAL": "#ff0000", "HIGH": "#ff6600", "MEDIUM": "#ffcc00", "LOW": "#33cc33", "INFO": "#3399ff"}
                    fig = px.bar(
                        x=list(sev_dist.keys()),
                        y=list(sev_dist.values()),
                        color=list(sev_dist.keys()),
                        color_discrete_map=colors,
                        title="Detections by Severity",
                    )
                    st.plotly_chart(fig, use_container_width=True)
                except ImportError:
                    st.bar_chart(sev_dist)
            else:
                st.info("No severity data yet.")

        # Recent jobs
        st.subheader("Recent Analysis Jobs")
        jobs = api_get("/jobs", {"limit": 5})
        if jobs and jobs.get("jobs"):
            for job in jobs["jobs"]:
                status_icon = "✅" if job.get("status") == "completed" else "⏳" if job.get("status") == "running" else "❌"
                st.markdown(
                    f"{status_icon} **{job.get('filename', 'Unknown')}** - "
                    f"Status: {job.get('status', 'unknown')} | "
                    f"Detections: {job.get('detection_count', 0)} | "
                    f"Incidents: {job.get('incident_count', 0)} | "
                    f"Uploaded: {job.get('upload_time', 'N/A')}"
                )
        else:
            st.info("No analysis jobs yet. Go to Upload & Validate to start.")

    else:
        st.info("🔌 Connect to the backend API to view security metrics.")
        st.code("python -m uvicorn src.api.main:app --reload --port 8000", language="bash")


# ============================================================
# 2. Upload & Validate
# ============================================================
elif page == "📤 Upload & Validate":
    st.title("📤 Upload & Validate Log Files")

    st.markdown("""
    Upload network/application log files for security analysis. 
    Supported formats: **CSV**, **JSON**, **JSONL**.
    """)

    uploaded_file = st.file_uploader(
        "Choose a log file",
        type=["csv", "json", "jsonl"],
        help="Upload CSV, JSON, or JSONL formatted log files"
    )

    if uploaded_file:
        st.info(f"📁 File: {uploaded_file.name} ({uploaded_file.size:,} bytes)")

        if st.button("🔄 Upload & Validate", type="primary"):
            with st.spinner("Uploading and validating..."):
                files = {"file": (uploaded_file.name, uploaded_file.getvalue())}
                result = api_post("/upload", files=files)

            if result:
                st.success(f"✅ Upload successful! Job ID: {result.get('job_id', 'N/A')}")

                vr = result.get("validation_result", {})
                col1, col2, col3 = st.columns(3)
                col1.metric("Valid Records", vr.get("valid_count", 0))
                col2.metric("Invalid Records", vr.get("invalid_count", 0))
                col3.metric("Duplicates", vr.get("duplicate_count", 0))

                if vr.get("malformed_details"):
                    with st.expander("⚠️ Malformed Record Details"):
                        for detail in vr["malformed_details"][:20]:
                            st.text(detail)

                # Offer to run analysis
                st.markdown("---")
                job_id = result.get("job_id")
                if job_id and st.button("🚀 Run Full Analysis", type="primary"):
                    with st.spinner("Running detection, correlation, and investigation..."):
                        analysis = api_post(f"/analyze/{job_id}")
                    if analysis:
                        st.success(
                            f"✅ Analysis complete! "
                            f"Detections: {analysis.get('detection_count', 0)}, "
                            f"Incidents: {analysis.get('incident_count', 0)}"
                        )
                    else:
                        st.error("Analysis failed.")

    # Manual job ID analysis
    st.markdown("---")
    st.subheader("Analyze Existing Job")
    manual_job_id = st.text_input("Enter Job ID to analyze")
    if manual_job_id and st.button("▶️ Run Analysis"):
        with st.spinner("Analyzing..."):
            result = api_post(f"/analyze/{manual_job_id}")
        if result:
            st.success(f"Analysis complete: {json.dumps(result, indent=2)}")


# ============================================================
# 3. Detection Explorer
# ============================================================
elif page == "🔍 Detection Explorer":
    st.title("🔍 Detection Explorer")

    # Job selector
    jobs = api_get("/jobs", {"limit": 50})
    job_options = {}
    if jobs and jobs.get("jobs"):
        for j in jobs["jobs"]:
            label = f"{j['filename']} ({j.get('status', 'unknown')}) - {j.get('job_id', '')[:8]}"
            job_options[label] = j["job_id"]

    if not job_options:
        st.info("No analysis jobs available. Upload and analyze a log file first.")
    else:
        selected_job_label = st.selectbox("Select Analysis Job", list(job_options.keys()))
        job_id = job_options[selected_job_label]

        # Filters
        col1, col2 = st.columns(2)
        with col1:
            type_filter = st.multiselect(
                "Detection Type",
                ["DOS", "BRUTE_FORCE", "PORT_SCAN", "HTTP_ANOMALY",
                 "PATH_TRAVERSAL", "INJECTION", "DATA_EXFIL",
                 "AUTH_ANOMALY", "STATISTICAL_ANOMALY"]
            )
        with col2:
            severity_filter = st.multiselect(
                "Severity",
                ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            )

        # Fetch detections
        params = {}
        if type_filter:
            params["detection_type"] = ",".join(type_filter)
        if severity_filter:
            params["severity"] = ",".join(severity_filter)

        detections = api_get(f"/detections/{job_id}", params)

        if detections and detections.get("detections"):
            st.metric("Total Detections", detections.get("total", len(detections["detections"])))

            for det in detections["detections"]:
                severity = det.get("severity", "UNKNOWN")
                sev_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}
                icon = sev_colors.get(severity, "⚪")

                with st.expander(
                    f"{icon} [{severity}] {det.get('detection_type', 'Unknown')} - "
                    f"{det.get('description', 'No description')[:100]}"
                ):
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Confidence", f"{det.get('confidence', 0):.2%}")
                    col2.metric("Measured Value", det.get("measured_value", "N/A"))
                    col3.metric("Threshold", det.get("threshold_value", "N/A"))

                    st.markdown(f"**Explanation:** {det.get('explanation', 'N/A')}")
                    st.markdown(f"**Source IPs:** {', '.join(det.get('source_ips', []) or ['N/A'])}")
                    st.markdown(f"**Time Range:** {det.get('timestamp_start', 'N/A')} → {det.get('timestamp_end', 'N/A')}")
                    st.markdown(f"**Source Events:** {len(det.get('source_event_ids', []) or [])}")

                    if det.get("evidence"):
                        st.json(det["evidence"])
        else:
            st.info("No detections found for this job.")


# ============================================================
# 4. Incident Management
# ============================================================
elif page == "🚨 Incident Management":
    st.title("🚨 Incident Management")

    jobs = api_get("/jobs", {"limit": 50})
    job_options = {}
    if jobs and jobs.get("jobs"):
        for j in jobs["jobs"]:
            if j.get("status") == "completed":
                label = f"{j['filename']} - {j.get('job_id', '')[:8]}"
                job_options[label] = j["job_id"]

    if not job_options:
        st.info("No completed analyses. Upload and analyze a log file first.")
    else:
        selected_job_label = st.selectbox("Select Analysis Job", list(job_options.keys()))
        job_id = job_options[selected_job_label]

        incidents = api_get(f"/incidents/{job_id}")

        if incidents and incidents.get("incidents"):
            for inc in incidents["incidents"]:
                priority = inc.get("priority", "P4")
                priority_colors = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "🟢"}
                icon = priority_colors.get(priority, "⚪")

                with st.expander(
                    f"{icon} [{priority}] {inc.get('title', 'Untitled')} | "
                    f"Status: {inc.get('status', 'NEW')}"
                ):
                    col1, col2, col3, col4 = st.columns(4)
                    col1.metric("Severity", inc.get("severity", "N/A"))
                    col2.metric("Priority", priority)
                    col3.metric("Detections", len(inc.get("detections", []) or inc.get("detection_ids", [])))
                    col4.metric("Status", inc.get("status", "NEW"))

                    st.markdown(f"**Correlation:** {inc.get('correlation_explanation', 'N/A')}")

                    if inc.get("evidence_summary"):
                        st.subheader("Evidence Summary")
                        st.json(inc["evidence_summary"])

                    # Status update
                    inc_id = inc.get("incident_id", "")
                    new_status = st.selectbox(
                        "Update Status",
                        ["NEW", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"],
                        key=f"status_{inc_id}",
                    )
                    if st.button("Update", key=f"update_{inc_id}"):
                        result = api_patch(f"/incidents/{inc_id}/status", {"status": new_status})
                        if result:
                            st.success("Status updated!")
                            st.rerun()

                    # Investigation trigger
                    if st.button("🤖 Investigate", key=f"investigate_{inc_id}"):
                        with st.spinner("Running AI investigation..."):
                            result = api_post(f"/investigate/{inc_id}", {"provider": "offline"})
                        if result:
                            st.success("Investigation complete!")
                            st.rerun()
        else:
            st.info("No incidents found.")


# ============================================================
# 5. AI Investigation
# ============================================================
elif page == "🤖 AI Investigation":
    st.title("🤖 AI Investigation Timeline")

    st.markdown("""
    View investigation results including tool-call traces, hypotheses, 
    evidence evaluation, and AI-generated recommendations.
    """)

    incident_id = st.text_input("Enter Incident ID")

    if incident_id:
        investigation = api_get(f"/investigation/{incident_id}")

        if investigation:
            st.markdown(f"**Provider:** `{investigation.get('provider_used', 'unknown')}`")
            st.markdown(f"**Duration:** {investigation.get('duration_seconds', 0):.1f}s")
            st.markdown(f"**Tool Calls:** {investigation.get('tool_call_count', 0)}")
            st.markdown(f"**Confidence:** {investigation.get('confidence', 0):.2%}")

            st.markdown("---")

            # Hypotheses
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("🔴 Malicious Hypothesis")
                st.markdown(investigation.get("hypothesis_malicious", "Not generated"))
            with col2:
                st.subheader("🟢 Benign Hypothesis")
                st.markdown(investigation.get("hypothesis_benign", "Not generated"))

            # Evidence
            st.subheader("Supporting Evidence")
            for ev in investigation.get("supporting_evidence", []):
                st.markdown(f"- ✅ {ev}")

            st.subheader("Contradictory Evidence")
            for ev in investigation.get("contradictory_evidence", []):
                st.markdown(f"- ⚠️ {ev}")

            if investigation.get("missing_info"):
                st.subheader("Missing Information")
                for info in investigation["missing_info"]:
                    st.markdown(f"- ❓ {info}")

            # Threat Assessment
            st.markdown("---")
            st.subheader("Threat Assessment")
            st.markdown(investigation.get("threat_assessment", "Not available"))

            # Recommendations
            st.subheader("Recommendations")
            for rec in investigation.get("recommendations", []):
                st.markdown(f"- 💡 {rec}")

            # Tool Call Trace
            st.markdown("---")
            st.subheader("🔧 Tool Call Trace")
            steps = investigation.get("steps", [])
            if steps:
                for step in steps:
                    with st.expander(
                        f"Step {step.get('step_number', '?')}: {step.get('tool_name', 'unknown')}"
                    ):
                        st.markdown(f"**Reasoning:** {step.get('reasoning', 'N/A')}")
                        st.markdown(f"**Arguments:**")
                        st.json(step.get("tool_args", {}))
                        st.markdown(f"**Result:**")
                        st.json(step.get("tool_result", {}))
            else:
                st.info("No tool call trace available.")

            # Full Report
            st.markdown("---")
            st.subheader("📄 Full Report")
            report_text = investigation.get("report_text", "")
            if report_text:
                st.markdown(report_text)
        else:
            st.info("No investigation found for this incident.")


# ============================================================
# 6. Historical Analyses
# ============================================================
elif page == "📋 Historical Analyses":
    st.title("📋 Historical Analyses")

    jobs = api_get("/jobs", {"limit": 100})

    if jobs and jobs.get("jobs"):
        st.metric("Total Analyses", jobs.get("total", len(jobs["jobs"])))

        # Build table data
        table_data = []
        for j in jobs["jobs"]:
            table_data.append({
                "Job ID": j.get("job_id", "")[:12] + "...",
                "File": j.get("filename", "Unknown"),
                "Status": j.get("status", "unknown"),
                "Records": j.get("record_count", 0),
                "Detections": j.get("detection_count", 0),
                "Incidents": j.get("incident_count", 0),
                "Uploaded": j.get("upload_time", "N/A"),
            })

        st.dataframe(table_data, use_container_width=True)
    else:
        st.info("No historical analyses found.")


# ============================================================
# 7. Reports & Export
# ============================================================
elif page == "📄 Reports & Export":
    st.title("📄 Reports & Export")

    jobs = api_get("/jobs", {"limit": 50})
    job_options = {}
    if jobs and jobs.get("jobs"):
        for j in jobs["jobs"]:
            if j.get("status") == "completed":
                label = f"{j['filename']} - {j.get('job_id', '')[:8]}"
                job_options[label] = j["job_id"]

    if not job_options:
        st.info("No completed analyses to export.")
    else:
        selected = st.selectbox("Select Analysis Job", list(job_options.keys()))
        job_id = job_options[selected]

        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("📥 Download JSON Report"):
                report = api_get(f"/reports/{job_id}", {"format": "json"})
                if report:
                    st.download_button(
                        "💾 Save JSON",
                        data=json.dumps(report, indent=2),
                        file_name=f"report_{job_id[:8]}.json",
                        mime="application/json",
                    )

        with col2:
            if st.button("📥 Download CSV Report"):
                report = api_get(f"/reports/{job_id}", {"format": "csv"})
                if report and report.get("csv_content"):
                    st.download_button(
                        "💾 Save CSV",
                        data=report["csv_content"],
                        file_name=f"report_{job_id[:8]}.csv",
                        mime="text/csv",
                    )

        with col3:
            if st.button("📥 Download PDF Report"):
                st.info("PDF export requires fpdf2. Install with: pip install fpdf2")


# ============================================================
# 8. Research Evaluation
# ============================================================
elif page == "🧪 Research Evaluation":
    st.title("🧪 Research Evaluation Results")

    st.markdown("""
    Comparison of five experimental conditions evaluating the evidence-grounded 
    agentic investigation framework.
    """)

    # Try to load results from file
    import os
    results_path = os.path.join("data", "results", "experiment_results.json")
    if os.path.exists(results_path):
        with open(results_path) as f:
            results = json.load(f)

        if results:
            # Summary metrics
            st.subheader("Experiment Comparison")

            table_data = []
            for r in results:
                table_data.append({
                    "Condition": r.get("condition", "?"),
                    "Description": r.get("config", {}).get("description", ""),
                    "Precision": f"{r.get('precision', 0):.3f}",
                    "Recall": f"{r.get('recall', 0):.3f}",
                    "F1 Score": f"{r.get('f1_score', 0):.3f}",
                    "FPR": f"{r.get('false_positive_rate', 0):.3f}",
                    "Evidence Acc.": f"{r.get('evidence_attribution_accuracy', 0):.3f}",
                    "Latency (ms)": f"{r.get('latency_ms', 0):.0f}",
                    "Tool Calls": r.get("tool_call_count", 0),
                })
            st.dataframe(table_data, use_container_width=True)

            # Charts
            try:
                import plotly.express as px
                import plotly.graph_objects as go

                conditions = [r["condition"] for r in results]
                f1_scores = [r.get("f1_score", 0) for r in results]
                precisions = [r.get("precision", 0) for r in results]
                recalls = [r.get("recall", 0) for r in results]

                fig = go.Figure()
                fig.add_trace(go.Bar(name="Precision", x=conditions, y=precisions))
                fig.add_trace(go.Bar(name="Recall", x=conditions, y=recalls))
                fig.add_trace(go.Bar(name="F1 Score", x=conditions, y=f1_scores))
                fig.update_layout(
                    title="Detection Metrics by Condition",
                    barmode="group",
                    yaxis_title="Score",
                )
                st.plotly_chart(fig, use_container_width=True)

            except ImportError:
                st.warning("Install plotly for interactive charts: pip install plotly")
    else:
        st.info("No experiment results found. Run the evaluation framework first.")
        st.code(
            "python -m src.evaluation.run_experiments",
            language="bash"
        )


# ============================================================
# 9. System Health
# ============================================================
elif page == "💚 System Health":
    st.title("💚 System Health")

    health = api_get("/health")

    if health:
        col1, col2, col3 = st.columns(3)
        status = health.get("status", "unknown")
        col1.metric("Status", "🟢 Healthy" if status == "healthy" else "🔴 Unhealthy")
        col2.metric("Version", health.get("version", "unknown"))
        col3.metric("Database", "✅ OK" if health.get("database_ok") else "❌ Error")

        st.markdown("---")
        st.subheader("Configuration")
        config = api_get("/config")
        if config:
            st.json(config)
    else:
        st.error("Cannot reach backend API.")
        st.markdown("""
        ### Quick Start
        ```bash
        # Start the backend
        cd ai-secops-analyzer
        pip install -r requirements.txt
        python -m uvicorn src.api.main:app --reload --port 8000
        
        # In another terminal, start the dashboard
        streamlit run src/dashboard/app.py
        ```
        """)
