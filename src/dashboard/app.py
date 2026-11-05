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


def get_job_id(j: dict) -> str:
    """Extract job id safely from a job dict."""
    return str(j.get("id") or j.get("job_id") or "")


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

if "nav_page" not in st.session_state or st.session_state["nav_page"] not in pages:
    st.session_state["nav_page"] = pages[0]

page_index = pages.index(st.session_state["nav_page"])
page = st.sidebar.radio("Navigation", pages, index=page_index, label_visibility="collapsed")
st.session_state["nav_page"] = page


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
                st_val = str(job.get("status", "")).upper()
                status_icon = "✅" if st_val == "COMPLETED" else "⏳" if st_val in ("RUNNING", "PENDING", "INVESTIGATING") else "❌"
                st.markdown(
                    f"{status_icon} **{job.get('filename', 'Unknown')}** - "
                    f"Status: `{job.get('status', 'unknown')}` | "
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
                col1.metric("Valid Records", vr.get("valid_records", vr.get("valid_count", 0)))
                col2.metric("Invalid Records", vr.get("invalid_records", vr.get("invalid_count", 0)))
                col3.metric("Duplicates", vr.get("duplicate_count", 0))

                if vr.get("malformed_details"):
                    with st.expander("⚠️ Malformed Record Details"):
                        for detail in vr["malformed_details"][:20]:
                            st.text(detail)

                # Offer to run analysis
                st.markdown("---")
                job_id = result.get("job_id") or result.get("id")
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
            jid = get_job_id(j)
            if jid:
                label = f"{j.get('filename', 'Unknown')} ({j.get('status', 'unknown')}) - {jid[:8]}"
                job_options[label] = jid

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
            jid = get_job_id(j)
            if jid and str(j.get("status", "")).upper() == "COMPLETED":
                label = f"{j.get('filename', 'Unknown')} - {jid[:8]}"
                job_options[label] = jid

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

                    inc_id = inc.get("incident_id", "")
                    st.markdown("**Incident ID:**")
                    st.code(inc_id, language=None)

                    col_view, col_status = st.columns([1, 1])
                    with col_view:
                        if st.button("🔍 Open in AI Investigation", key=f"view_{inc_id}"):
                            st.session_state["nav_page"] = "🤖 AI Investigation"
                            st.session_state["selected_incident_id"] = inc_id
                            st.rerun()

                    st.markdown(f"**Correlation:** {inc.get('correlation_explanation', 'N/A')}")

                    if inc.get("evidence_summary"):
                        st.subheader("Evidence Summary")
                        st.json(inc["evidence_summary"])

                    # Status update
                    st.markdown("---")
                    st.markdown("##### 📌 Incident Triage Status")
                    new_status = st.selectbox(
                        "Update Status",
                        ["NEW", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"],
                        key=f"status_{inc_id}",
                    )
                    if st.button("Update Status", key=f"update_{inc_id}"):
                        result = api_patch(f"/incidents/{inc_id}/status", {"status": new_status})
                        if result:
                            st.success("Status updated!")
                            st.rerun()

                    # Investigation trigger with provider selector
                    st.markdown("---")
                    st.markdown("##### 🤖 Run Autonomous AI Investigation")
                    col_p, col_b = st.columns([2, 1])
                    with col_p:
                        selected_provider = st.selectbox(
                            "AI Investigation Provider",
                            ["google", "local", "offline", "openai", "anthropic"],
                            key=f"prov_{inc_id}",
                        )
                    with col_b:
                        st.markdown("<div style='height: 28px'></div>", unsafe_allow_html=True)
                        if st.button("🚀 Investigate Now", key=f"investigate_{inc_id}", type="primary"):
                            with st.spinner(f"Running autonomous AI investigation ({selected_provider})..."):
                                result = api_post(f"/investigate/{inc_id}", {"provider": selected_provider})
                            if result:
                                st.success("Investigation complete!")
                                st.session_state["nav_page"] = "🤖 AI Investigation"
                                st.session_state["selected_incident_id"] = inc_id
                                st.rerun()
        else:
            st.info("No incidents found.")


# ============================================================
# 5. AI Investigation
# ============================================================
elif page == "🤖 AI Investigation":
    st.title("🤖 Autonomous AI Investigation")

    st.markdown("""
    Explore autonomous AI investigations powered by **Google Gemini** or **Local Llama 3.2**. 
    The AI agent reasons across correlated telemetry, executes multi-step investigation tools, 
    evaluates dual hypotheses (*Malicious Attack Campaign* vs *Benign Operational Anomaly*), 
    and synthesizes actionable containment guidance.
    """)

    # Load all incidents across completed jobs
    jobs = api_get("/jobs", {"limit": 50})
    incident_options = {}
    incident_map = {}

    if jobs and jobs.get("jobs"):
        for j in jobs["jobs"]:
            jid = get_job_id(j)
            if jid and str(j.get("status", "")).upper() == "COMPLETED":
                fname = j.get("filename", "Unknown")
                incs = api_get(f"/incidents/{jid}")
                if incs and incs.get("incidents"):
                    for inc in incs["incidents"]:
                        iid = inc.get("incident_id")
                        if iid:
                            priority = inc.get("priority", "P4")
                            title = inc.get("title", "Untitled Incident")
                            short_title = title if len(title) <= 55 else title[:52] + "..."
                            label = f"[{priority}] {short_title} — {fname} ({iid[:8]})"
                            incident_options[label] = iid
                            incident_map[iid] = {
                                "incident": inc,
                                "filename": fname,
                                "job_id": jid
                            }

    if not incident_options:
        st.info("ℹ️ No incidents found yet. Upload and analyze a log file in **📤 Upload & Validate** first.")
        if st.button("📤 Go to Upload & Validate"):
            st.session_state["nav_page"] = "📤 Upload & Validate"
            st.rerun()
    else:
        # Incident Selector
        labels = list(incident_options.keys())
        default_idx = 0
        current_sel_id = st.session_state.get("selected_incident_id")
        if current_sel_id:
            for idx, lbl in enumerate(labels):
                if incident_options[lbl] == current_sel_id:
                    default_idx = idx
                    break

        selected_label = st.selectbox(
            "🎯 Select Incident to Investigate or Review",
            labels,
            index=default_idx,
            help="Select any security incident discovered by the correlation engine."
        )
        selected_incident_id = incident_options[selected_label]
        st.session_state["selected_incident_id"] = selected_incident_id

        # Manual entry expander for advanced direct lookups
        with st.expander("Or enter Incident ID manually"):
            manual_id = st.text_input("Manual Incident UUID", value="", placeholder="Paste UUID here...")
            if manual_id.strip():
                selected_incident_id = manual_id.strip()

        # Display Selected Incident Summary Card
        inc_info = incident_map.get(selected_incident_id, {})
        inc_obj = inc_info.get("incident", {})

        st.markdown("---")
        col_m1, col_m2, col_m3, col_m4 = st.columns(4)
        col_m1.metric("Priority", inc_obj.get("priority", "N/A"))
        col_m2.metric("Severity", inc_obj.get("severity", "N/A"))
        col_m3.metric("Status", inc_obj.get("status", "NEW"))
        col_m4.metric("Detections", len(inc_obj.get("detections", []) or inc_obj.get("detection_ids", [])))

        st.markdown(f"**Incident ID:** `{selected_incident_id}`")
        if inc_obj.get("title"):
            st.markdown(f"**Title:** {inc_obj['title']}")
        if inc_obj.get("correlation_explanation"):
            st.markdown(f"**Correlation Details:** {inc_obj['correlation_explanation']}")

        # Fetch investigation
        data = api_get(f"/investigation/{selected_incident_id}")
        investigation = data.get("investigation") if (data and isinstance(data, dict) and "investigation" in data) else data

        if not investigation:
            st.markdown("---")
            st.warning("⚡ **This incident has not been investigated by an AI agent yet.**")
            st.markdown("""
            The autonomous AI SecOps agent will:
            1. Query raw telemetry and baseline deviations using investigative tools.
            2. Evaluate dual hypotheses (**Malicious Attack Campaign** vs **Benign Operational Outlier**).
            3. Synthesize evidence-grounded threat assessment and containment recommendations.
            """)

            st.markdown("##### 🚀 Run Autonomous AI Investigation")
            col_prov, col_btn = st.columns([2, 1])
            with col_prov:
                run_provider = st.selectbox(
                    "Choose AI Provider",
                    ["google", "local", "offline", "openai", "anthropic"],
                    help="'google' uses Gemini Flash with your Google API Key. 'local' uses Llama 3.2 via Ollama.",
                    key=f"run_prov_{selected_incident_id}"
                )
            with col_btn:
                st.markdown("<div style='height: 28px'></div>", unsafe_allow_html=True)
                if st.button("🤖 Launch AI Investigation", type="primary", key=f"launch_btn_{selected_incident_id}"):
                    with st.spinner(f"Autonomous AI agent investigating with {run_provider}... Executing tool calls, analyzing attack vectors, and synthesizing threat assessment..."):
                        res = api_post(f"/investigate/{selected_incident_id}", {"provider": run_provider})
                    if res:
                        st.success("✅ Autonomous investigation completed successfully!")
                        st.rerun()
        else:
            st.markdown("---")
            st.success(f"✅ **AI Investigation Completed** (Provider: `{investigation.get('provider_used', 'unknown')}` | Confidence: {investigation.get('confidence', 0):.1%})")

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Provider", investigation.get('provider_used', 'unknown'))
            col2.metric("Duration", f"{investigation.get('duration_seconds', 0):.2f}s")
            col3.metric("Tool Calls", investigation.get('tool_call_count', 0))
            col4.metric("Confidence", f"{investigation.get('confidence', 0):.1%}")

            st.markdown("---")

            # Dual Hypotheses
            col_h1, col_h2 = st.columns(2)
            with col_h1:
                st.markdown("### 🔴 Malicious Campaign Hypothesis")
                st.info(investigation.get("hypothesis_malicious", "Not generated"))
            with col_h2:
                st.markdown("### 🟢 Benign Outlier Hypothesis")
                st.success(investigation.get("hypothesis_benign", "Not generated"))

            # Evidence Breakdown
            col_e1, col_e2 = st.columns(2)
            with col_e1:
                st.markdown("### 🛡️ Supporting Evidence (Malicious)")
                ev_list = investigation.get("supporting_evidence", [])
                if ev_list:
                    for ev in ev_list:
                        st.markdown(f"- ✅ {ev}")
                else:
                    st.caption("No specific supporting evidence recorded.")
            with col_e2:
                st.markdown("### ⚖️ Contradictory Evidence (Benign)")
                cev_list = investigation.get("contradictory_evidence", [])
                if cev_list:
                    for ev in cev_list:
                        st.markdown(f"- ⚠️ {ev}")
                else:
                    st.caption("No contradictory evidence recorded.")

            if investigation.get("missing_info"):
                st.markdown("### ❓ Missing Telemetry & Information Gaps")
                for info in investigation["missing_info"]:
                    st.markdown(f"- 🔍 {info}")

            # Threat Assessment
            st.markdown("---")
            st.markdown("### 🎯 Threat Assessment")
            st.markdown(investigation.get("threat_assessment", "Not available"))

            # Recommendations
            st.markdown("### 💡 Recommended Mitigation Actions")
            recs = investigation.get("recommendations", [])
            if recs:
                for idx, rec in enumerate(recs, 1):
                    st.markdown(f"{idx}. {rec}")
            else:
                st.caption("No recommendations generated.")

            # Investigative Tool Trail
            st.markdown("---")
            st.markdown("### 🔧 Agent Tool Execution Trail")
            steps = investigation.get("steps", [])
            if steps:
                st.caption(f"The autonomous agent executed {len(steps)} investigative tool calls to query baseline context, parse events, and evaluate evidence:")
                for step in steps:
                    s_num = step.get('step_number', '?')
                    t_name = step.get('tool_name', 'unknown')
                    with st.expander(f"Step {s_num}: `{t_name}` — {step.get('reasoning', 'N/A')[:90]}"):
                        st.markdown(f"**Reasoning:** {step.get('reasoning', 'N/A')}")
                        col_t1, col_t2 = st.columns(2)
                        with col_t1:
                            st.markdown("**Arguments:**")
                            st.json(step.get("tool_args", {}))
                        with col_t2:
                            st.markdown("**Tool Output / Evidence:**")
                            st.json(step.get("tool_result", {}))
            else:
                st.info("No tool call trace recorded for this investigation.")

            # Full Report
            report_text = investigation.get("report_text", "")
            if report_text:
                st.markdown("---")
                with st.expander("📄 View Full Markdown Investigation Report", expanded=False):
                    st.markdown(report_text)

            # Re-run option
            st.markdown("---")
            with st.expander("🔄 Re-run Investigation with Another AI Provider"):
                col_rp1, col_rp2 = st.columns([2, 1])
                with col_rp1:
                    re_provider = st.selectbox(
                        "Select AI Model Provider",
                        ["google", "local", "offline", "openai", "anthropic"],
                        key=f"re_prov_{selected_incident_id}"
                    )
                with col_rp2:
                    st.markdown("<div style='height: 28px'></div>", unsafe_allow_html=True)
                    if st.button("🚀 Re-run Investigation", key=f"rerun_{selected_incident_id}"):
                        with st.spinner(f"Re-investigating with {re_provider}..."):
                            res = api_post(f"/investigate/{selected_incident_id}", {"provider": re_provider})
                        if res:
                            st.success("Re-investigation complete!")
                            st.rerun()


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
            jid = get_job_id(j)
            table_data.append({
                "Job ID": jid[:12] + "..." if jid else "N/A",
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
            jid = get_job_id(j)
            if jid and str(j.get("status", "")).upper() == "COMPLETED":
                label = f"{j.get('filename', 'Unknown')} - {jid[:8]}"
                job_options[label] = jid

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
        status = str(health.get("status", "unknown")).lower()
        col1.metric("Status", "🟢 Healthy" if status in ("ok", "healthy") else "🔴 Unhealthy")
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
