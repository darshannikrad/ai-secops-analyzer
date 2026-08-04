/* AI SecOps Log Analyzer — dashboard controller */
"use strict";

const $ = (sel) => document.querySelector(sel);
const term = $("#terminal");
const charts = {};
const fileInput = $("#file-input");

/* Escape user-controlled strings before HTML injection (XSS defence). */
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

/* ────────────────────────── terminal feed ────────────────────────── */
function logTerm(line, cls = "t-dim") {
  const el = document.createElement("div");
  el.className = cls;
  el.textContent = line;
  term.appendChild(el);
  term.scrollTop = term.scrollHeight;
}
function bootTerminal() {
  term.innerHTML = "";
  const lines = [
    ["secops-analyzer v1.0.0 — agentic threat-profiling console", "t-info"],
    ["stage engine ....... online    (stats · rules · agents)", "t-ok"],
    ["llm gateway ........ auto      (openai / ollama / offline)", "t-ok"],
    ["mitre taxonomy ..... 7 techniques mapped", "t-ok"],
    ["awaiting pipeline launch — set parameters and hit RUN", "t-dim"],
  ];
  lines.forEach(([l, c], i) => setTimeout(() => logTerm(l, c), 120 * (i + 1)));
}

/* ────────────────────────── pipeline run ────────────────────────── */
async function runPipeline() {
  const seed = parseInt($("#in-seed").value || "7", 10);
  const minutes = parseInt($("#in-minutes").value || "90", 10);
  const provider = $("#in-provider").value;
  setBusy(true);
  term.innerHTML = "";
  const boot = [
    ["launching pipeline  seed=" + seed + " window=" + minutes + "min provider=" + provider, "t-info"],
    ["phase 1/4  generating labelled traffic corpus...", "t-dim"],
  ];
  boot.forEach(([l, c]) => logTerm(l, c));
  try {
    const data = await postJSON("/api/demo", { seed, minutes, provider });
    renderRun(data);
    toast("Pipeline complete — " + data.verdict_counts.threats + " threats surfaced");
  } catch (err) {
    logTerm("✗ fatal: " + err.message, "t-warn");
    toast("Run failed: " + err.message, true);
  } finally {
    setBusy(false);
  }
}

/* Robust fetch: never chokes on non-JSON (HTML) responses — surface a clear message. */
async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return parseResponse(res, url);
}

async function parseResponse(res, url) {
  const ct = (res.headers.get("content-type") || "").toLowerCase();
  if (!ct.includes("json")) {
    const snippet = (await res.text()).slice(0, 160).replace(/\s+/g, " ");
    throw new Error("server returned HTML instead of JSON (" + snippet + "…) — the site may still be starting up, try again in a minute");
  }
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || res.statusText);
  return data;
}

function renderRun(d) {
  // terminal narrative from real numbers (handles both demo & upload payloads)
  const cost = Number(d.llm_cost_usd ?? d.cost_usd ?? 0);
  logTerm("✓ dataset ready    " + d.dataset.total_events + " events"
    + (d.dataset.attack_events != null ? " (" + d.dataset.attack_events + " attack)" : ""), "t-ok");
  const st = d.stage_times || {};
  if (d.evaluation) logTerm("phase 2/4  stats engine  z>3 flagged", "t-dim");
  logTerm("  · stats  " + (st.stats_stage_s ?? "?") + "s   rules  " + (st.rules_stage_s ?? "?") + "s", "t-ok");
  logTerm("phase 3/4  agent triage  " + d.verdict_counts.candidates + " candidates → "
    + d.verdict_counts.threats + " threats / " + d.verdict_counts.benign + " benign"
    + (d.verdict_counts.review ? " / " + d.verdict_counts.review + " review" : ""), "t-info");
  logTerm("  · provider " + d.provider + "  cost $" + cost.toFixed(4)
    + (d.offline_fallbacks ? "  (" + d.offline_fallbacks + " fallbacks)" : ""), "t-ok");
  logTerm("phase 4/4  wrote " + d.incidents.length + " incident report"
    + (d.incidents.length === 1 ? "" : "s") + (d.figures && d.figures.length ? " + " + d.figures.length + " figures" : ""), "t-info");
  logTerm("● pipeline idle — total " + (d.total_wall_s ?? "?") + "s", "t-warn");

  $("#results").classList.remove("hidden");
  renderKPIs(d);

  const hasEval = !!(d.evaluation && d.evaluation.detectors && d.evaluation.detectors.length);
  document.querySelector(".charts").classList.toggle("hidden", !hasEval);
  const twoCol = document.querySelector(".two-col");
  twoCol.classList.remove("hidden");
  if (hasEval) {
    renderCharts(d);
    renderTables(d);
  } else {
    // detection mode (uploaded logs, no ground truth) — show a notice instead
    twoCol.innerHTML =
      `<div class="card"><h3 class="card-title">Detection mode <span class="tag">no ground truth</span></h3>
      <p style="color:var(--muted);font-size:13px;line-height:1.7">
      Uploaded logs are triaged like live traffic: the agent reviewed the flagged
      IPs and produced the incident reports below. There is no labelled ground truth
      for a file, so the precision/recall comparison table is skipped. Click
      <b>Launch Pipeline</b> to see the full statistical-vs-rules-vs-agent evaluation.
      </p></div>`;
  }
  renderIncidents(d);
  renderFigures(d);
  $("#results").scrollIntoView({ behavior: "smooth" });
}

/* ────────────────────────── KPIs ────────────────────────── */
function kpi(label, value, sub, cls = "") {
  return `<div class="kpi ${cls}">
    <div class="k-label">${label}</div>
    <div class="k-value">${value}</div>
    <div class="k-sub">${sub}</div></div>`;
}
function renderKPIs(d) {
  const dets = (d.evaluation && d.evaluation.detectors) || [];
  const agent = dets.find((x) => x.detector === "agentic_hybrid") || {};
  const stats = dets.find((x) => x.detector === "stats_only") || {};
  $("#kpis").innerHTML = [
    kpi("Events processed", d.dataset.total_events.toLocaleString(),
        d.dataset.distinct_src_ips + " source IPs · " + d.dataset.attacks_by_type
          ? Object.keys(d.dataset.attacks_by_type).length + " attack types" : "", "acc"),
    kpi("True incidents", d.dataset.ground_truth_incidents || "—",
        "labelled ground truth", "warn"),
    kpi("Agentic F1", agent.f1 != null ? agent.f1.toFixed(3) : "—",
        "precision " + (agent.precision ?? "—") + " · recall " + (agent.recall ?? "—"), "good"),
    kpi("False positives", agent.fp ?? "—",
        "stats-only: " + (stats.fp ?? "—") + " (alert fatigue)", agent.fp ? "bad" : "good"),
    kpi("Alerts issued", agent.alerts_issued ?? "—",
        "vs " + (agent.true_incidents ?? "—") + " true — multiplicity " + (agent.alert_multiplicity ?? "—"), "acc"),
    kpi("Detection latency", (agent.detection_latency_mean_min ?? 0) + " min",
        "rule baseline " + (dets.find(x => x.detector === "rule_based")?.detection_latency_mean_min ?? "—") + " min", "acc"),
    kpi("Pipeline cost", "$" + Number(d.llm_cost_usd ?? d.cost_usd ?? 0).toFixed(4),
        d.provider + " analyst · " + (d.llm_calls || 0) + " LLM calls", "warn"),
    kpi("Pipeline time", (d.total_wall_s ?? d.stage_times?.total_pipeline_s ?? 0) + " s",
        (d.stage_times?.events_per_sec ?? "—") + " events/s", "good"),
  ].join("");
}

/* ────────────────────────── charts ────────────────────────── */
const CHART_COLORS = ["#22d3ee", "#fbbf24", "#34d399", "#f87171", "#a78bfa"];
function baseOpts(extra = {}) {
  return Object.assign({
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: "#8aa0bf", font: { family: "JetBrains Mono", size: 11 } } } },
    scales: {
      x: { ticks: { color: "#8aa0bf", font: { family: "JetBrains Mono", size: 10.5 } }, grid: { color: "rgba(29,42,69,.5)" } },
      y: { beginAtZero: true, ticks: { color: "#8aa0bf", font: { family: "JetBrains Mono", size: 10.5 } }, grid: { color: "rgba(29,42,69,.5)" } },
    },
  }, extra);
}

function renderCharts(d) {
  const dets = ((d.evaluation && d.evaluation.detectors) || [])
    .filter((x) => x.detector !== "agentic_plus_review");
  const labels = dets.map((x) => x.detector);

  // 1 — precision / recall / F1
  const mk = (k) => dets.map((x) => (x[k] ?? 0).toFixed(3));
  if (charts.prf) charts.prf.destroy();
  charts.prf = new Chart($("#chart-prf"), {
    type: "bar",
    data: {
      labels,
      datasets: [
        { label: "precision", data: mk("precision"), backgroundColor: "#22d3ee88", borderColor: "#22d3ee", borderWidth: 1 },
        { label: "recall", data: mk("recall"), backgroundColor: "#fbbf2488", borderColor: "#fbbf24", borderWidth: 1 },
        { label: "F1", data: mk("f1"), backgroundColor: "#34d39988", borderColor: "#34d399", borderWidth: 1 },
      ],
    },
    options: baseOpts({ scales: { x: { ticks: { color: "#8aa0bf", font: { family: "JetBrains Mono", size: 10 } }, grid: { display: false } }, y: { beginAtZero: true, max: 1.1, ticks: { color: "#8aa0bf", font: { family: "JetBrains Mono", size: 10 } }, grid: { color: "rgba(29,42,69,.5)" } } }, plugins: { legend: { labels: { color: "#8aa0bf", font: { family: "JetBrains Mono", size: 11 } } }, title: { display: true, text: "Detection quality by detector", color: "#e6edf7", font: { family: "Inter", size: 13, weight: "700" } } } }),
  });

  // 2 — alerts vs true incidents
  if (charts.alerts) charts.alerts.destroy();
  charts.alerts = new Chart($("#chart-alerts"), {
    type: "bar",
    data: {
      labels,
      datasets: [
        { label: "alerts issued", data: dets.map((x) => x.alerts_issued ?? 0), backgroundColor: "#f8717188", borderColor: "#f87171", borderWidth: 1 },
        { label: "true incidents", data: dets.map((x) => x.true_incidents ?? 0), backgroundColor: "#34d39988", borderColor: "#34d399", borderWidth: 1 },
      ],
    },
    options: baseOpts({ plugins: { legend: { labels: { color: "#8aa0bf", font: { family: "JetBrains Mono", size: 11 } } }, title: { display: true, text: "Alert volume — the alert-fatigue story", color: "#e6edf7", font: { family: "Inter", size: 13, weight: "700" } } } }),
  });

  // 3 — latency
  if (charts.lat) charts.lat.destroy();
  charts.lat = new Chart($("#chart-latency"), {
    type: "bar",
    data: {
      labels,
      datasets: [{ label: "mean detection latency (min)", data: dets.map((x) => x.detection_latency_mean_min ?? 0), backgroundColor: CHART_COLORS.slice(0, labels.length).map((c) => c + "99"), borderColor: CHART_COLORS, borderWidth: 1 }],
    },
    options: baseOpts({ plugins: { legend: { display: false }, title: { display: true, text: "Detection latency", color: "#e6edf7", font: { family: "Inter", size: 13, weight: "700" } } } }),
  });
}

/* ────────────────────────── tables ────────────────────────── */
function renderTables(d) {
  const dets = (d.evaluation && d.evaluation.detectors) || [];
  const bestF1 = dets.length ? Math.max(...dets.map((x) => x.f1 ?? 0)) : 0;
  $("#cmp-table").innerHTML =
    `<thead><tr><th>detector</th><th class="num">TP</th><th class="num">FP</th><th class="num">FN</th>
     <th class="num">prec</th><th class="num">rec</th><th class="num">F1</th><th class="num">FPR</th>
     <th class="num">alerts</th><th class="num">lat(min)</th><th class="num">cost</th></tr></thead><tbody>` +
    dets.map((x) => `<tr>
      <td><span class="det-badge ${x.f1 === bestF1 ? "det-best" : ""}">${x.detector}</span></td>
      <td class="num">${x.tp}</td><td class="num">${x.fp}</td><td class="num">${x.fn}</td>
      <td class="num">${x.precision.toFixed(3)}</td><td class="num">${x.recall.toFixed(3)}</td>
      <td class="num"><b>${x.f1.toFixed(3)}</b></td><td class="num">${x.false_positive_rate.toFixed(3)}</td>
      <td class="num">${x.alerts_issued}</td><td class="num">${x.detection_latency_mean_min.toFixed(1)}</td>
      <td class="num">$${x.cost_usd.toFixed(4)}</td></tr>`).join("") + "</tbody>";

  const st = d.stage_times || {};
  const rows = [
    ["data generation", st.data_stage_s ?? "—"], ["statistical baseline", st.stats_stage_s ?? "—"],
    ["signature rules", st.rules_stage_s ?? "—"], ["agentic triage", st.agent_stage_s ?? "—"],
    ["total pipeline", st.total_pipeline_s ?? "—"], ["throughput", (st.events_per_sec ?? "—") + " ev/s"],
  ];
  $("#stage-table").innerHTML =
    `<thead><tr><th>stage</th><th class="num">time (s)</th></tr></thead><tbody>` +
    rows.map(([k, v]) => `<tr><td>${k}</td><td class="num">${v}</td></tr>`).join("") + "</tbody>";
}

/* ────────────────────────── incidents ────────────────────────── */
function sevPill(sev, review) {
  if (review && sev < 3) return `<span class="pill review"><span class="pdot"></span>REVIEW</span>`;
  const cls = sev >= 8 ? "crit" : sev >= 6 ? "high" : sev >= 3.5 ? "med" : "low";
  const label = cls === "crit" ? "CRITICAL" : cls === "high" ? "HIGH" : cls === "med" ? "MEDIUM" : "LOW";
  return `<span class="pill ${cls}"><span class="pdot"></span>${label} ${sev.toFixed(1)}</span>`;
}

function miniMarkdown(md) {
  if (!md) return "<em>no report body</em>";
  let h = md.replace(/&/g, "&amp;").replace(/</g, "&lt;");
  h = h.replace(/^# (.*)$/gm, "<h1>$1</h1>");
  h = h.replace(/^## (.*)$/gm, "<h2>$1</h2>");
  h = h.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
  h = h.replace(/`([^`]+)`/g, "<code>$1</code>");
  h = h.replace(/^- (.*)$/gm, "<li>$1</li>");
  h = h.replace(/(<li>.*<\/li>)/gs, "<ul>$1</ul>");
  return h.replace(/\n{2,}/g, "\n");
}

function renderIncidents(d) {
  const incs = d.incidents || [];
  $("#inc-count").textContent = incs.length + " generated";
  $("#incident-grid").innerHTML = incs.map((i) => {
    const v = i.verdict || {};
    const cls = v.needs_human_review && !v.is_threat ? "review"
      : v.severity >= 8 ? "crit" : v.severity >= 6 ? "high" : v.severity >= 3.5 ? "med" : "low";
    const timeline = (i.timeline || []).slice(0, 8);
    return `<article class="inc ${cls}" data-id="${esc(i.incident_id)}">
      <div class="inc-head">
        <span class="inc-id">${esc(i.incident_id)}</span>
        ${sevPill(v.severity, v.needs_human_review && !v.is_threat)}
      </div>
      <h4 class="inc-title">${esc(i.title)}</h4>
      <div class="inc-meta">
        <span>src <b>${esc(v.ip) || "—"}</b></span>
        <span>· ${esc(v.mitre_technique_id)} <b>${esc(v.mitre_technique_name)}</b></span>
        <span>· ${esc(v.mitre_tactic)}</span>
        <span>· ${esc(v.source)}</span>
      </div>
      <div class="conf-bar"><div style="width:${Math.min(100, Math.max(0, (v.confidence || 0) * 100)).toFixed(0)}%"></div></div>
      <div class="inc-detail">
        <h4>rationale</h4><p>${esc(v.rationale)}</p>
        <h4>recommended actions</h4>
        <ul>${(v.recommended_actions || []).map((a) => `<li>${esc(a)}</li>`).join("")}</ul>
        ${i.indicators ? `<h4>indicators</h4>
          <ul>${Object.entries(i.indicators).slice(0, 5).map(([k, val]) =>
            `<li><b>${esc(k)}:</b> ${esc(Array.isArray(val) ? val.slice(0, 4).join(", ") : val)}</li>`).join("")}</ul>` : ""}
        ${timeline.length ? `<h4>evidence timeline</h4>
          <div class="timeline"><ul>${timeline.map((e) =>
            `<li><span style="color:#5b6f8f">${esc(e.timestamp)}</span> ${esc(e.method)} ${esc(e.path)} → ${esc(e.status)}</li>`).join("")}</ul></div>` : ""}
        <h4>full report</h4>
        <div class="md">${miniMarkdown(i.markdown)}</div>
      </div>
    </article>`;
  }).join("");

  document.querySelectorAll(".inc").forEach((el) =>
    el.addEventListener("click", () => el.classList.toggle("open")));
}

/* ────────────────────────── figures ────────────────────────── */
function renderFigures(d) {
  const figs = d.figures || [];
  if (!figs.length) { $("#figures").innerHTML = ""; return; }
  const captions = {
    fig1_traffic_timeline: "Fig 1 — Traffic timeline: benign vs attack",
    fig2_anomaly_scores: "Fig 2 — Z-score distribution & flag threshold",
    fig3_alerts_vs_true: "Fig 3 — Alert volume by detector",
    fig4_detection_quality: "Fig 4 — Precision / recall / F1",
    fig5_latency: "Fig 5 — Detection latency",
  };
  $("#figures").innerHTML = `<h3 class="section-title">Publication figures</h3>` +
    figs.map((f) => `<figure class="fig-card"><img src="/api/figures/${f}" alt="${f}" loading="lazy" />
      <figcaption>${captions[f] || f}</figcaption></figure>`).join("");
}

/* ────────────────────────── upload ────────────────────────── */
function setupUpload() {
  const dz = $("#dropzone");
  dz.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => fileInput.files[0] && uploadFile(fileInput.files[0]));
  ["dragover", "dragenter"].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("dragover"); }));
  ["dragleave", "drop"].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("dragover"); }));
  dz.addEventListener("drop", (e) => {
    const f = e.dataTransfer.files[0];
    if (f) uploadFile(f);
  });
}

async function uploadFile(file) {
  setBusy(true);
  term.innerHTML = "";
  logTerm("uploading " + file.name + " (" + (file.size / 1024).toFixed(1) + " KB)…", "t-info");
  const fd = new FormData();
  fd.append("file", file);
  try {
    const res = await fetch("/api/analyze", { method: "POST", body: fd });
    const d = await parseResponse(res, "/api/analyze");
    logTerm("✓ parsed " + d.n_events.toLocaleString() + " events · " + d.n_anomalies + " anomalies · " + d.n_rule_hits + " rule hits", "t-ok");
    logTerm("✓ agent triage → " + d.verdict_counts.threats + " threats / " + d.verdict_counts.benign + " benign (" + d.provider + ")", "t-ok");
    renderRun({ ...d, dataset: { total_events: d.n_events, distinct_src_ips: "—", attacks_by_type: {} }, evaluation: null, stage_times: {}, total_wall_s: "—", figures: [] });
    toast("Analyzed " + file.name + " — " + d.verdict_counts.threats + " threats");
  } catch (err) {
    logTerm("✗ fatal: " + err.message, "t-warn");
    toast("Upload failed: " + err.message, true);
  } finally {
    setBusy(false);
    fileInput.value = "";
  }
}

/* ────────────────────────── misc ────────────────────────── */
function setBusy(b) {
  ["#btn-run", "#btn-run-2"].forEach((s) => {
    const el = $(s);
    el.disabled = b;
    const svg = el.querySelector("svg");
    if (svg) svg.style.animation = b ? "pulse 1s infinite" : "none";
  });
}
let toastTimer;
function toast(msg, isErr = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 3200);
}

/* ────────────────────────── boot ────────────────────────── */
$("#btn-run").addEventListener("click", runPipeline);
$("#btn-run-2").addEventListener("click", runPipeline);
setupUpload();
bootTerminal();
