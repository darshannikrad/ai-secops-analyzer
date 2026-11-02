"""
Report generator for security incidents and analysis results.

Generates traceable JSON, CSV, and PDF reports with evidence attribution.
Never fabricates evidence or claims compromise without sufficient proof.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates security analysis reports in multiple formats."""

    def __init__(self):
        self.generated_at = None

    def generate_json_report(
        self,
        job_id: str,
        incidents: list,
        detections: list,
        investigations: list | None = None,
        validation_result: Any = None,
        metadata: dict | None = None,
    ) -> dict:
        """
        Generate a comprehensive JSON report.
        
        All data comes from actual analysis results. No fabrication.
        """
        self.generated_at = datetime.now(timezone.utc).isoformat()

        report = {
            "report_metadata": {
                "report_id": f"RPT-{job_id}",
                "analysis_job_id": job_id,
                "generated_at": self.generated_at,
                "generator": "AI SecOps Log Analyzer v1.0",
                "format": "json",
            },
            "executive_summary": self._build_executive_summary(
                incidents, detections, investigations
            ),
            "validation_summary": self._serialize_validation(validation_result),
            "detection_summary": self._build_detection_summary(detections),
            "incident_summary": self._build_incident_summary(incidents),
            "investigation_results": self._build_investigation_summary(investigations or []),
            "detailed_detections": [self._serialize_detection(d) for d in detections],
            "detailed_incidents": [self._serialize_incident(inc) for inc in incidents],
            "recommendations": self._aggregate_recommendations(investigations or []),
            "evidence_chain": self._build_evidence_chain(incidents, detections),
        }

        if metadata:
            report["analysis_metadata"] = metadata

        return report

    def generate_csv_report(
        self,
        job_id: str,
        incidents: list,
        detections: list,
    ) -> str:
        """Generate a CSV report of detections and incidents."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Detections sheet
        writer.writerow([
            "detection_id", "type", "severity", "confidence",
            "description", "measured_value", "threshold_value",
            "source_ips", "dest_ips", "timestamp_start",
            "timestamp_end", "source_event_count", "explanation"
        ])

        for d in detections:
            writer.writerow([
                getattr(d, 'detection_id', ''),
                str(getattr(d, 'detection_type', '')),
                str(getattr(d, 'severity', '')),
                getattr(d, 'confidence', ''),
                getattr(d, 'description', ''),
                getattr(d, 'measured_value', ''),
                getattr(d, 'threshold_value', ''),
                ';'.join(getattr(d, 'source_ips', []) or []),
                ';'.join(getattr(d, 'dest_ips', []) or []),
                str(getattr(d, 'timestamp_start', '')),
                str(getattr(d, 'timestamp_end', '')),
                len(getattr(d, 'source_event_ids', []) or []),
                getattr(d, 'explanation', ''),
            ])

        writer.writerow([])  # Blank line separator
        writer.writerow(["--- INCIDENTS ---"])
        writer.writerow([
            "incident_id", "title", "severity", "priority",
            "status", "detection_count", "correlation_explanation",
            "created_at"
        ])

        for inc in incidents:
            writer.writerow([
                getattr(inc, 'incident_id', ''),
                getattr(inc, 'title', ''),
                str(getattr(inc, 'severity', '')),
                str(getattr(inc, 'priority', '')),
                str(getattr(inc, 'status', '')),
                len(getattr(inc, 'detections', []) or []),
                getattr(inc, 'correlation_explanation', ''),
                str(getattr(inc, 'created_at', '')),
            ])

        return output.getvalue()

    def generate_pdf_report(
        self,
        job_id: str,
        incidents: list,
        detections: list,
        investigations: list | None = None,
    ) -> bytes | None:
        """
        Generate a PDF report. Returns None if fpdf2 is not available.
        """
        try:
            from fpdf import FPDF
        except ImportError:
            logger.warning("fpdf2 not installed; PDF generation unavailable")
            return None

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Title
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Security Analysis Report", ln=True, align="C")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 8, f"Job ID: {job_id}", ln=True, align="C")
        pdf.cell(0, 8, f"Generated: {datetime.now(timezone.utc).isoformat()}", ln=True, align="C")
        pdf.ln(10)

        # Executive Summary
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Executive Summary", ln=True)
        pdf.set_font("Helvetica", "", 10)

        summary = self._build_executive_summary(incidents, detections, investigations)
        pdf.multi_cell(0, 6, summary.get("text", "No summary available."))
        pdf.ln(5)

        # Detection Summary
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Detections", ln=True)
        pdf.set_font("Helvetica", "", 9)

        for d in detections[:50]:  # Limit for PDF size
            det_type = str(getattr(d, 'detection_type', 'Unknown'))
            severity = str(getattr(d, 'severity', 'Unknown'))
            desc = str(getattr(d, 'description', ''))[:200]
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 6, f"[{severity}] {det_type}", ln=True)
            pdf.set_font("Helvetica", "", 8)
            pdf.multi_cell(0, 5, desc)
            measured = getattr(d, 'measured_value', None)
            threshold = getattr(d, 'threshold_value', None)
            if measured is not None and threshold is not None:
                pdf.cell(0, 5, f"  Measured: {measured}, Threshold: {threshold}", ln=True)
            pdf.ln(2)

        # Incident Summary
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Incidents", ln=True)

        for inc in incidents:
            pdf.set_font("Helvetica", "B", 10)
            title = str(getattr(inc, 'title', 'Untitled'))
            priority = str(getattr(inc, 'priority', 'P4'))
            pdf.cell(0, 7, f"[{priority}] {title}", ln=True)
            pdf.set_font("Helvetica", "", 9)
            explanation = str(getattr(inc, 'correlation_explanation', ''))[:300]
            pdf.multi_cell(0, 5, explanation)
            pdf.ln(3)

        return pdf.output()

    def _build_executive_summary(
        self, incidents: list, detections: list, investigations: list | None
    ) -> dict:
        """Build executive summary from actual analysis data."""
        severity_counts = {}
        for d in detections:
            sev = str(getattr(d, 'severity', 'UNKNOWN'))
            if hasattr(d.severity, 'value'):
                sev = d.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        type_counts = {}
        for d in detections:
            dt = str(getattr(d, 'detection_type', 'UNKNOWN'))
            if hasattr(d.detection_type, 'value'):
                dt = d.detection_type.value
            type_counts[dt] = type_counts.get(dt, 0) + 1

        priority_counts = {}
        for inc in incidents:
            p = str(getattr(inc, 'priority', 'P4'))
            if hasattr(inc, 'priority') and hasattr(inc.priority, 'value'):
                p = inc.priority.value
            priority_counts[p] = priority_counts.get(p, 0) + 1

        total_detections = len(detections)
        total_incidents = len(incidents)
        critical_count = severity_counts.get("CRITICAL", 0)
        high_count = severity_counts.get("HIGH", 0)

        text_parts = [
            f"Analysis identified {total_detections} security detection(s) "
            f"grouped into {total_incidents} incident(s).",
        ]
        if critical_count > 0:
            text_parts.append(f"{critical_count} critical severity finding(s) require immediate attention.")
        if high_count > 0:
            text_parts.append(f"{high_count} high severity finding(s) detected.")

        if investigations:
            text_parts.append(f"{len(investigations)} investigation(s) completed.")

        return {
            "text": " ".join(text_parts),
            "total_detections": total_detections,
            "total_incidents": total_incidents,
            "severity_distribution": severity_counts,
            "detection_type_distribution": type_counts,
            "priority_distribution": priority_counts,
        }

    def _build_detection_summary(self, detections: list) -> dict:
        """Summarize detections by type and severity."""
        by_type = {}
        by_severity = {}
        for d in detections:
            dt = str(getattr(d, 'detection_type', 'UNKNOWN'))
            sev = str(getattr(d, 'severity', 'UNKNOWN'))
            by_type[dt] = by_type.get(dt, 0) + 1
            by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            "total": len(detections),
            "by_type": by_type,
            "by_severity": by_severity,
        }

    def _build_incident_summary(self, incidents: list) -> dict:
        """Summarize incidents."""
        by_status = {}
        by_priority = {}
        for inc in incidents:
            status = str(getattr(inc, 'status', 'NEW'))
            priority = str(getattr(inc, 'priority', 'P4'))
            by_status[status] = by_status.get(status, 0) + 1
            by_priority[priority] = by_priority.get(priority, 0) + 1

        return {
            "total": len(incidents),
            "by_status": by_status,
            "by_priority": by_priority,
        }

    def _build_investigation_summary(self, investigations: list) -> list:
        """Summarize investigation results."""
        summaries = []
        for inv in investigations:
            summaries.append({
                "investigation_id": getattr(inv, 'investigation_id', ''),
                "incident_id": getattr(inv, 'incident_id', ''),
                "provider_used": getattr(inv, 'provider_used', 'unknown'),
                "tool_call_count": getattr(inv, 'tool_call_count', 0),
                "confidence": getattr(inv, 'confidence', 0.0),
                "threat_assessment": getattr(inv, 'threat_assessment', ''),
                "duration_seconds": getattr(inv, 'duration_seconds', 0),
            })
        return summaries

    def _aggregate_recommendations(self, investigations: list) -> list:
        """Collect all unique recommendations from investigations."""
        seen = set()
        recommendations = []
        for inv in investigations:
            for rec in getattr(inv, 'recommendations', []) or []:
                if rec not in seen:
                    seen.add(rec)
                    recommendations.append(rec)
        return recommendations

    def _build_evidence_chain(self, incidents: list, detections: list) -> list:
        """Build evidence traceability chain."""
        chains = []
        for inc in incidents:
            chain = {
                "incident_id": getattr(inc, 'incident_id', ''),
                "detection_ids": [],
                "source_event_ids": [],
            }
            for d in getattr(inc, 'detections', []) or []:
                chain["detection_ids"].append(getattr(d, 'detection_id', ''))
                for eid in getattr(d, 'source_event_ids', []) or []:
                    if eid not in chain["source_event_ids"]:
                        chain["source_event_ids"].append(eid)
            chains.append(chain)
        return chains

    def _serialize_detection(self, d) -> dict:
        """Serialize a detection to dict."""
        try:
            if hasattr(d, 'model_dump'):
                return d.model_dump(mode='json')
            elif hasattr(d, 'dict'):
                return d.dict()
        except Exception:
            pass
        # Fallback manual serialization
        return {
            "detection_id": getattr(d, 'detection_id', ''),
            "detection_type": str(getattr(d, 'detection_type', '')),
            "severity": str(getattr(d, 'severity', '')),
            "confidence": getattr(d, 'confidence', 0.0),
            "description": getattr(d, 'description', ''),
            "measured_value": getattr(d, 'measured_value', None),
            "threshold_value": getattr(d, 'threshold_value', None),
            "explanation": getattr(d, 'explanation', ''),
        }

    def _serialize_incident(self, inc) -> dict:
        """Serialize an incident to dict."""
        try:
            if hasattr(inc, 'model_dump'):
                return inc.model_dump(mode='json')
            elif hasattr(inc, 'dict'):
                return inc.dict()
        except Exception:
            pass
        return {
            "incident_id": getattr(inc, 'incident_id', ''),
            "title": getattr(inc, 'title', ''),
            "severity": str(getattr(inc, 'severity', '')),
            "priority": str(getattr(inc, 'priority', '')),
            "status": str(getattr(inc, 'status', '')),
        }

    def _serialize_validation(self, vr) -> dict | None:
        """Serialize validation result."""
        if vr is None:
            return None
        try:
            if hasattr(vr, 'model_dump'):
                return vr.model_dump(mode='json')
        except Exception:
            pass
        return {
            "valid_count": getattr(vr, 'valid_count', 0),
            "invalid_count": getattr(vr, 'invalid_count', 0),
            "duplicate_count": getattr(vr, 'duplicate_count', 0),
        }
