"""Automated Investigation Timeline Generation Module.

Correlates heterogeneous evidence sources (DNS lookups, TCP handshakes,
cleartext HTTP requests, TLS handshakes, and detection findings) into a unified,
chronologically sorted investigation timeline.
Outputs structured CSV and Markdown tables with standardized UTC timestamps.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from pcap_analyzer.detection import DetectionReport
from pcap_analyzer.extraction import ExtractedMetadata


class TimelineEvent(BaseModel):
    """Normalized chronological timeline entry."""
    timestamp: str  # ISO-8601 UTC string
    event_type: str  # DNS Query, DNS Response, Outbound Connection, HTTP Request, TLS Handshake, Detection Alert
    evidence_source: str
    source_endpoint: str
    destination_endpoint: str
    summary: str
    interpretation: str


class InvestigationTimeline(BaseModel):
    """Chronologically correlated timeline of investigative events."""
    case_id: str
    pcap_filename: str
    events_count: int
    events: List[TimelineEvent] = Field(default_factory=list)


def parse_to_epoch(ts_str: str) -> float:
    """Parse an ISO-8601 timestamp string to float epoch for sorting."""
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return 0.0


def build_timeline(
    metadata: ExtractedMetadata, detection_report: Optional[DetectionReport] = None
) -> InvestigationTimeline:
    """Build unified chronological timeline from extracted metadata and detection findings.

    Args:
        metadata: Extracted connection, DNS, HTTP, and TLS events.
        detection_report: Optional correlated detection and behavioral findings.

    Returns:
        Sorted InvestigationTimeline model.
    """
    events: List[TimelineEvent] = []

    # 1. DNS Events
    for dns in metadata.dns_queries:
        if dns.response_code is not None:
            ans_str = ", ".join(dns.answers) if dns.answers else "No Answer"
            events.append(TimelineEvent(
                timestamp=dns.timestamp,
                event_type="DNS Response",
                evidence_source="DNS Log",
                source_endpoint=dns.dst_ip,
                destination_endpoint=dns.src_ip,
                summary=f"Resolved '{dns.query_name}' ({dns.query_type}) -> {ans_str}",
                interpretation=f"Host resolved domain '{dns.query_name}' prior to potential connection.",
            ))
        else:
            events.append(TimelineEvent(
                timestamp=dns.timestamp,
                event_type="DNS Query",
                evidence_source="DNS Log",
                source_endpoint=dns.src_ip,
                destination_endpoint=f"{dns.dst_ip}:53",
                summary=f"Lookup for '{dns.query_name}' (Type {dns.query_type})",
                interpretation=f"Host initiated domain name lookup for '{dns.query_name}'.",
            ))

    # 2. Connection Flows
    for conn in metadata.connections:
        events.append(TimelineEvent(
            timestamp=conn.start_time,
            event_type="Outbound Connection",
            evidence_source="Flow Record",
            source_endpoint=f"{conn.src_ip}:{conn.src_port}",
            destination_endpoint=f"{conn.dst_ip}:{conn.dst_port}",
            summary=f"L4 {conn.protocol} connection ({conn.packet_count} packets, {conn.byte_count} bytes)",
            interpretation=f"Host established network transport session to {conn.dst_ip}:{conn.dst_port}.",
        ))

    # 3. HTTP Transactions
    for http in metadata.http_requests:
        events.append(TimelineEvent(
            timestamp=http.timestamp,
            event_type="HTTP Request",
            evidence_source="HTTP Log",
            source_endpoint=f"{http.src_ip}:{http.src_port}",
            destination_endpoint=f"{http.dst_ip}:{http.dst_port}",
            summary=f"{http.method} {http.uri} (Host: {http.host})",
            interpretation=f"Application-layer cleartext request to '{http.host}{http.uri}'.",
        ))

    # 4. TLS Handshakes
    for tls in metadata.tls_handshakes:
        sni_label = tls.server_name or "Unknown SNI"
        events.append(TimelineEvent(
            timestamp=tls.timestamp,
            event_type="TLS Handshake",
            evidence_source="TLS Handshake Log",
            source_endpoint=f"{tls.src_ip}:{tls.src_port}",
            destination_endpoint=f"{tls.dst_ip}:{tls.dst_port}",
            summary=f"ClientHello to SNI: {sni_label}",
            interpretation=f"Host initiated TLS encrypted tunnel negotiating server name '{sni_label}'.",
        ))

    # 5. Detection Engine Alerts
    if detection_report:
        for finding in detection_report.findings:
            events.append(TimelineEvent(
                timestamp=finding.timestamp,
                event_type="Detection Alert",
                evidence_source=finding.evidence_source,
                source_endpoint=finding.source_endpoint,
                destination_endpoint=finding.destination_endpoint,
                summary=finding.observed_behavior,
                interpretation=f"Matched detection rule {finding.rule_id or 'behavior'}: {finding.why_suspicious[:80]}...",
            ))

    # Sort strictly chronologically by epoch timestamp
    events.sort(key=lambda e: parse_to_epoch(e.timestamp))

    return InvestigationTimeline(
        case_id=metadata.case_id,
        pcap_filename=metadata.pcap_filename,
        events_count=len(events),
        events=events,
    )


def export_timeline_csv(timeline: InvestigationTimeline, output_file: Path) -> None:
    """Export chronologically ordered timeline to CSV."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp (UTC)", "Event_Type", "Evidence_Source", "Source", "Destination", "Summary", "Interpretation"])
        for e in timeline.events:
            writer.writerow([e.timestamp, e.event_type, e.evidence_source, e.source_endpoint, e.destination_endpoint, e.summary, e.interpretation])


def export_timeline_markdown(timeline: InvestigationTimeline) -> str:
    """Format timeline as a human-readable Markdown table for reporting."""
    lines = [
        "| Timestamp (UTC) | Event | Source | Destination | Summary | Interpretation |",
        "|---|---|---|---|---|---|",
    ]
    for e in timeline.events:
        summary_esc = e.summary.replace("|", "\\|")
        interp_esc = e.interpretation.replace("|", "\\|")
        lines.append(
            f"| `{e.timestamp}` | **{e.event_type}** | `{e.source_endpoint}` | `{e.destination_endpoint}` | {summary_esc} | {interp_esc} |"
        )
    return "\n".join(lines)
