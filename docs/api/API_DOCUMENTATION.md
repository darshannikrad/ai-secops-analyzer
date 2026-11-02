# AI SecOps Log Analyzer: REST API Documentation

**API Specification Version:** 1.0.0  
**Base URL:** `http://localhost:8000/api/v1`  
**OpenAPI Specification:** Available at `http://localhost:8000/docs` (Swagger UI) and `http://localhost:8000/redoc` (ReDoc)  

---

## 1. Authentication & Security Policy
- **Local Deployment:** No authentication tokens or headers are required for local or testing instances.
- **Enterprise Mode:** In production environments, reverse proxies (e.g. NGINX, Cloudflare) enforce mutual TLS or bearer token authorization (`Authorization: Bearer <TOKEN>`).
- **Rate Limiting:** Unauthenticated endpoints enforce a recommended gateway limit of 120 requests per minute per source IP. Heavy processing endpoints (`/upload`, `/analyze/{job_id}`, `/investigate/{incident_id}`) serialize background operations using asynchronous worker locks.

---

## 2. Standard HTTP Error Codes

| Status Code | Description | Typical Cause |
|:---|:---|:---|
| `200 OK` | Request succeeded | Standard retrieval or update operations |
| `201 Created` | Resource created | Successful file upload and job initialization |
| `400 Bad Request` | Invalid payload or missing parameters | Missing file, empty upload, unsupported report format |
| `404 Not Found` | Target entity not found | Invalid `job_id` or `incident_id` |
| `413 Payload Too Large`| Upload size exceeds maximum ceiling | Uploaded file > 100 MB |
| `422 Unprocessable` | Unparseable schema or syntax error | Malformed CSV/JSON format that cannot be parsed |
| `500 Server Error` | Unhandled backend failure | Analytical engine exception or database failure |

---

## 3. Endpoints

### 3.1 System & Diagnostic Endpoints

#### `GET /api/v1/health`
Checks server liveness, database connectivity, and uptime.

- **Parameters:** None
- **Response (200 OK):**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "database_ok": true,
  "uptime_seconds": 1420.55
}
```

---

#### `GET /api/v1/config`
Retrieves runtime configuration with sensitive API keys masked.

- **Parameters:** None
- **Response (200 OK):**
```json
{
  "config": {
    "app_env": "development",
    "database_url": "sqlite:///./secops.db",
    "llm_provider": "offline",
    "llm_model": "offline-heuristic-v1",
    "max_upload_size_mb": 100,
    "secret_key": "********",
    "openai_api_key": "********",
    "anthropic_api_key": "********",
    "google_api_key": "********"
  }
}
```

---

#### `GET /api/v1/stats`
Returns aggregated analytical metrics across all historical jobs, detections, and incidents.

- **Parameters:** None
- **Response (200 OK):**
```json
{
  "total_jobs": 12,
  "total_detections": 184,
  "total_incidents": 26,
  "total_investigations": 26,
  "jobs_by_status": {
    "COMPLETED": 12
  },
  "incidents_by_status": {
    "NEW": 10,
    "INVESTIGATING": 4,
    "RESOLVED": 12
  },
  "incidents_by_priority": {
    "P1_CRITICAL": 6,
    "P2_HIGH": 11,
    "P3_MEDIUM": 7,
    "P4_LOW": 2
  },
  "detections_by_severity": {
    "CRITICAL": 35,
    "HIGH": 64,
    "MEDIUM": 55,
    "LOW": 30
  }
}
```

---

### 3.2 Ingestion & Analysis Pipeline

#### `POST /api/v1/upload`
Uploads a raw security log file (`.csv`, `.json`, `.jsonl`), validates its schema, and creates an `AnalysisJob` entity.

- **Content-Type:** `multipart/form-data`
- **Request Parameters:**
  - `file` (File, Required): Binary stream of the log file.
- **Example cURL:**
```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -F "file=@data/sample/synthetic_dataset.csv"
```
- **Response (201 Created):**
```json
{
  "job_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "validation_result": {
    "valid_records": 535,
    "invalid_records": 0,
    "duplicate_count": 0,
    "schema_info": {
      "format": "csv",
      "detected_fields": ["timestamp", "source_ip", "method", "status", "uri"]
    }
  },
  "message": "Successfully ingested 535 valid records (0 malformed, 0 duplicates)."
}
```

---

#### `POST /api/v1/analyze/{job_id}`
Executes the full end-to-end security pipeline: Detection Engine $\to$ Correlation Engine $\to$ Prioritization Engine $\to$ Offline Agent Triage $\to$ Report Generation.

- **Parameters:**
  - `job_id` (Path, string, Required): ID returned by `/upload`.
- **Response (200 OK):**
```json
{
  "job_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "status": "COMPLETED",
  "detection_count": 14,
  "incident_count": 3,
  "message": "Analysis pipeline completed successfully"
}
```

---

### 3.3 Job Management

#### `GET /api/v1/jobs`
Retrieves a paginated list of analysis jobs.

- **Query Parameters:**
  - `page` (integer, default: 1): Page number (1-indexed).
  - `page_size` (integer, default: 50, max: 500): Items per page.
- **Response (200 OK):**
```json
{
  "jobs": [
    {
      "id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      "status": "COMPLETED",
      "filename": "synthetic_dataset.csv",
      "upload_time": "2026-10-12T10:15:30Z",
      "completion_time": "2026-10-12T10:15:34Z",
      "record_count": 535,
      "detection_count": 14,
      "incident_count": 3,
      "error_message": null,
      "config_snapshot": {"format": "csv"}
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 50
}
```

---

#### `GET /api/v1/jobs/{job_id}`
Retrieves detailed status and record metadata for a single job.

- **Parameters:**
  - `job_id` (Path, string, Required)
- **Response (200 OK):**
```json
{
  "id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "status": "COMPLETED",
  "filename": "synthetic_dataset.csv",
  "upload_time": "2026-10-12T10:15:30Z",
  "completion_time": "2026-10-12T10:15:34Z",
  "record_count": 535,
  "detection_count": 14,
  "incident_count": 3,
  "error_message": null,
  "config_snapshot": {"format": "csv"}
}
```

---

### 3.4 Detections & Incidents

#### `GET /api/v1/detections/{job_id}`
Returns all atomic security detections identified within a specific job.

- **Parameters:**
  - `job_id` (Path, string, Required)
  - `type` (Query, string, Optional): Filter by detection type (e.g., `BRUTE_FORCE`, `SQL_INJECTION`, `STATISTICAL_ANOMALY`).
  - `severity` (Query, string, Optional): Filter by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **Response (200 OK):**
```json
{
  "detections": [
    {
      "detection_id": "det-1a2b3c",
      "detection_type": "SQL_INJECTION",
      "severity": "CRITICAL",
      "confidence": 0.95,
      "description": "SQL injection signature detected in URI parameter",
      "evidence": {
        "pattern": "UNION SELECT",
        "matched_value": "id=1 UNION SELECT username, password FROM users"
      },
      "source_event_ids": ["evt-101", "evt-102"],
      "source_ips": ["198.51.100.25"],
      "timestamp_start": "2026-10-12T10:00:15Z",
      "timestamp_end": "2026-10-12T10:00:18Z"
    }
  ],
  "total": 1
}
```

---

#### `GET /api/v1/incidents/{job_id}`
Retrieves correlated incidents grouping related detections together.

- **Parameters:**
  - `job_id` (Path, string, Required)
- **Response (200 OK):**
```json
{
  "incidents": [
    {
      "incident_id": "inc-9f8e7d",
      "title": "Coordinated SQL Injection and Data Exfiltration Attack",
      "severity": "CRITICAL",
      "priority": "P1_CRITICAL",
      "status": "NEW",
      "correlation_explanation": "Correlated 3 detections sharing source IP 198.51.100.25 within 120s window.",
      "detections": [
        { "detection_id": "det-1a2b3c", "detection_type": "SQL_INJECTION", "severity": "CRITICAL" }
      ],
      "evidence_summary": {
        "source_ips": ["198.51.100.25"],
        "affected_endpoints": ["/api/users"],
        "detection_count": 3
      },
      "created_at": "2026-10-12T10:15:32Z",
      "updated_at": "2026-10-12T10:15:32Z"
    }
  ],
  "total": 1
}
```

---

#### `PATCH /api/v1/incidents/{incident_id}/status`
Updates an incident's lifecycle triage status.

- **Parameters:**
  - `incident_id` (Path, string, Required)
- **Request Body (`application/json`):**
```json
{
  "status": "INVESTIGATING"
}
```
*Allowed status values:* `NEW`, `TRIAGED`, `INVESTIGATING`, `RESOLVED`, `CLOSED`.
- **Response (200 OK):**
```json
{
  "message": "Incident status updated successfully",
  "incident_id": "inc-9f8e7d",
  "status": "INVESTIGATING",
  "updated_at": "2026-10-12T10:20:00Z"
}
```

---

### 3.5 Automated Agent Investigation

#### `POST /api/v1/investigate/{incident_id}`
Launches an autonomous, evidence-grounded agent investigation on a target incident.

- **Parameters:**
  - `incident_id` (Path, string, Required)
- **Request Body (`application/json`, Optional):**
```json
{
  "provider": "offline",
  "model": "offline-heuristic-v1",
  "include_remediation": true
}
```
*Supported providers:* `offline`, `openai`, `anthropic`, `google`, `ollama`.
- **Response (200 OK):**
```json
{
  "incident_id": "inc-9f8e7d",
  "investigation": {
    "investigation_id": "inv-554433",
    "incident_id": "inc-9f8e7d",
    "provider_used": "offline",
    "hypothesis_malicious": "Host 198.51.100.25 executed automated SQL extraction followed by bulk data download.",
    "hypothesis_benign": "Authorized vulnerability scanner or database admin export script.",
    "supporting_evidence": [
      "Event evt-101 contains UNION SELECT query payload",
      "Outbound payload size of 154,200 bytes exceeds baseline by 8.4 standard deviations"
    ],
    "contradictory_evidence": [
      "No internal change ticket or scheduled maintenance window registered"
    ],
    "threat_assessment": "Confirmed malicious exploit chain targeting customer database.",
    "recommendations": [
      "Isolate internal database host from egress network immediately",
      "Block IP 198.51.100.25 on edge firewall",
      "Rotate database credentials and audit affected tables"
    ],
    "confidence": 0.94,
    "duration_seconds": 0.42,
    "tool_call_count": 4,
    "created_at": "2026-10-12T10:20:05Z"
  },
  "message": "Investigation completed using provider 'offline'"
}
```

---

#### `GET /api/v1/investigation/{incident_id}`
Fetches persisted investigation findings for an incident.

- **Parameters:**
  - `incident_id` (Path, string, Required)
- **Response (200 OK):** Same schema as `/investigate/{incident_id}` response.

---

### 3.6 Reports & Compliance Export

#### `GET /api/v1/reports/{job_id}`
Retrieves synthesized threat intelligence and compliance reports in JSON or CSV format.

- **Parameters:**
  - `job_id` (Path, string, Required)
  - `format` (Query, string, Optional, default: `"json"`): `"json"` or `"csv"`.
- **Response (200 OK - JSON):**
```json
{
  "job_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "generated_at": "2026-10-12T10:15:35Z",
  "summary": {
    "record_count": 535,
    "detection_count": 14,
    "incident_count": 3
  },
  "incidents": [...],
  "detections": [...],
  "investigations": [...]
}
```
- **Response (200 OK - CSV):** Returns downloadable text/csv attachment with headers `Incident ID, Title, Severity, Priority, Status, Source IPs, Detection Count`.
