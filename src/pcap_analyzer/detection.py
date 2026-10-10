"""Network Detection and Suspicious Behavior Analysis Module.

Runs Suricata in offline analysis mode (with fallback signature matching),
detects anomalous egress behaviors (beaconing intervals, non-standard ports),
and correlates detections into structured finding objects with confidence scores,
alternative benign explanations, and actionable next steps.
"""

from __future__ import annotations

import json
import math
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from pcap_analyzer.extraction import ExtractedMetadata


class Finding(BaseModel):
    """Structured network anomaly or detection finding."""
    finding_id: str
    evidence_source: str
    timestamp: str
    source_endpoint: str
    destination_endpoint: str
    observed_behavior: str
    why_suspicious: str
    alternative_benign_explanations: str
    confidence_level: str = "Low"  # Low, Medium, High
    recommended_follow_up: str
    rule_id: Optional[str] = None


class DetectionReport(BaseModel):
    """Aggregate findings report from signatures and behavioral analysis."""
    case_id: str
    pcap_filename: str
    findings: List[Finding] = Field(default_factory=list)
    suricata_alerts_count: int = 0
    behavioral_anomalies_count: int = 0


def detect_beaconing_intervals(
    timestamps: List[str], min_hits: int = 3, cv_threshold: float = 0.25
) -> Optional[Dict[str, float]]:
    """Analyze inter-arrival time consistency to detect automated beaconing.

    Args:
        timestamps: Chronologically sorted ISO-8601 UTC timestamp strings.
        min_hits: Minimum occurrences to compute variance.
        cv_threshold: Maximum Coefficient of Variation (std_dev / mean) indicating regularity.

    Returns:
        Dict with mean interval and coefficient of variation if beaconing detected, else None.
    """
    if len(timestamps) < min_hits:
        return None

    epochs = []
    for ts in timestamps:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            epochs.append(dt.timestamp())
        except Exception:
            continue

    if len(epochs) < min_hits:
        return None

    epochs.sort()
    deltas = [epochs[i] - epochs[i - 1] for i in range(1, len(epochs))]
    if not deltas or any(d < 0.001 for d in deltas):  # Ignore instant bursts
        return None

    mean_delta = sum(deltas) / len(deltas)
    if mean_delta < 1.0:  # Rapid burst, not periodic beacon
        return None

    variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
    std_dev = math.sqrt(variance)
    cv = std_dev / mean_delta if mean_delta > 0 else 1.0

    if cv <= cv_threshold:
        return {"mean_interval_sec": round(mean_delta, 2), "coefficient_of_variation": round(cv, 3)}
    return None


def run_suricata_offline(
    pcap_path: Path, rules_file: Path, output_dir: Path
) -> List[Dict[str, Any]]:
    """Execute Suricata offline engine (`suricata -r`) and parse eve.json output."""
    suricata_bin = shutil.which("suricata")
    if not suricata_bin:
        return []

    output_dir.mkdir(parents=True, exist_ok=True)
    eve_path = output_dir / "eve.json"
    if eve_path.exists():
        eve_path.unlink()

    cmd = [
        suricata_bin,
        "-r", str(pcap_path),
        "-S", str(rules_file),
        "-l", str(output_dir),
        "--runmode", "single",
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60)
    except Exception:
        return []

    alerts = []
    if eve_path.exists():
        with open(eve_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alerts.append(event)
                except Exception:
                    continue
    return alerts


def evaluate_custom_rules_fallback(
    metadata: ExtractedMetadata, rules_file: Optional[Path] = None
) -> List[Finding]:
    """Pure-Python signature rule evaluation matching custom.rules logic."""
    findings: List[Finding] = []
    f_idx = 1

    # Rule 1: HTTP Executable download (.exe)
    for http in metadata.http_requests:
        if http.method.upper() == "GET" and http.uri.lower().endswith(".exe"):
            findings.append(Finding(
                finding_id=f"FIND-{f_idx:03d}",
                evidence_source="HTTP Log / Rule SID 1000001",
                timestamp=http.timestamp,
                source_endpoint=f"{http.src_ip}:{http.src_port}",
                destination_endpoint=f"{http.dst_ip}:{http.dst_port}",
                observed_behavior=f"GET request for binary file '{http.uri}' to host '{http.host}'",
                why_suspicious="Adversaries frequently deliver second-stage implants, drop-executables, or tools via direct unencrypted HTTP requests.",
                alternative_benign_explanations="Legitimate legacy software update or internal administrative installer fetch over HTTP.",
                confidence_level="High",
                recommended_follow_up="Investigate endpoint process creation logs (Sysmon EID 1) around timestamp; acquire downloaded file if available to compute hash.",
                rule_id="1000001",
            ))
            f_idx += 1

    # Rule 2: Suspicious Dynamic DNS / TLD query (.xyz)
    for dns in metadata.dns_queries:
        if dns.query_name.lower().endswith(".xyz") or "malicious" in dns.query_name.lower() or "evil" in dns.query_name.lower():
            findings.append(Finding(
                finding_id=f"FIND-{f_idx:03d}",
                evidence_source="DNS Log / Rule SID 1000002",
                timestamp=dns.timestamp,
                source_endpoint=f"{dns.src_ip}",
                destination_endpoint=f"{dns.dst_ip}:53",
                observed_behavior=f"DNS query for '{dns.query_name}' resolving to {dns.answers}",
                why_suspicious="High-abuse TLDs and dynamic DNS domains are commonly registered by threat actors for short-lived C2 infrastructure.",
                alternative_benign_explanations="Benign web navigation to a legitimate business website utilizing non-standard TLDs.",
                confidence_level="Medium",
                recommended_follow_up="Check passive DNS history for domain; query endpoint proxy/web browsing logs for referer URL.",
                rule_id="1000002",
            ))
            f_idx += 1

    # Rule 4: TLS SNI Matching C2 pattern
    for tls in metadata.tls_handshakes:
        if tls.server_name and ("beacon" in tls.server_name.lower() or "c2" in tls.server_name.lower()):
            findings.append(Finding(
                finding_id=f"FIND-{f_idx:03d}",
                evidence_source="TLS Handshake / Rule SID 1000004",
                timestamp=tls.timestamp,
                source_endpoint=f"{tls.src_ip}:{tls.src_port}",
                destination_endpoint=f"{tls.dst_ip}:{tls.dst_port}",
                observed_behavior=f"TLS ClientHello SNI header requesting server name '{tls.server_name}'",
                why_suspicious="Observed TLS SNI matches suspected command-and-control server naming patterns.",
                alternative_benign_explanations="Coincidental naming in internal testing or legitimate telemetry service.",
                confidence_level="High",
                recommended_follow_up="Inspect active network connections and memory artifacts of the source host for injected beacon threads.",
                rule_id="1000004",
            ))
            f_idx += 1

    return findings


def analyze_suspicious_behavior(
    metadata: ExtractedMetadata,
    rules_file: Optional[Path] = None,
    output_dir: Optional[Path] = None,
) -> DetectionReport:
    """Perform comprehensive network detection combining Suricata and behavioral analysis."""
    all_findings: List[Finding] = []
    suricata_count = 0

    # 1. Attempt Suricata offline if available and rules provided
    if rules_file and rules_file.exists() and output_dir and shutil.which("suricata"):
        raw_alerts = run_suricata_offline(Path(metadata.pcap_filename), rules_file, output_dir)
        suricata_count = len(raw_alerts)
        for idx, alert in enumerate(raw_alerts, start=1):
            alert_data = alert.get("alert", {})
            all_findings.append(Finding(
                finding_id=f"SURI-{idx:03d}",
                evidence_source="Suricata IDS Alert",
                timestamp=alert.get("timestamp", datetime.utcnow().isoformat()),
                source_endpoint=f"{alert.get('src_ip')}:{alert.get('src_port')}",
                destination_endpoint=f"{alert.get('dest_ip')}:{alert.get('dest_port')}",
                observed_behavior=alert_data.get("signature", "Suricata Alert"),
                why_suspicious=f"Triggered signature SID {alert_data.get('signature_id')} categorized under {alert_data.get('category')}.",
                alternative_benign_explanations="Signature match could represent benign traffic matching low-specificity rule syntax.",
                confidence_level="High" if alert_data.get("severity", 3) <= 2 else "Medium",
                recommended_follow_up="Validate underlying packet payload matching signature condition.",
                rule_id=str(alert_data.get("signature_id")),
            ))

    # 2. Signature Fallback Evaluation (ensures detection works offline and without external binaries)
    if not all_findings:
        fallback_hits = evaluate_custom_rules_fallback(metadata, rules_file)
        all_findings.extend(fallback_hits)

    # 3. Behavioral Analysis: Non-Standard Outbound High Ports
    standard_ports = {80, 443, 53, 123, 67, 68, 8080}
    for conn in metadata.connections:
        if conn.protocol == "TCP" and conn.dst_port not in standard_ports and conn.dst_port > 1024:
            all_findings.append(Finding(
                finding_id=f"BEHAV-{len(all_findings)+1:03d}",
                evidence_source="Flow Connection Log",
                timestamp=conn.start_time,
                source_endpoint=f"{conn.src_ip}:{conn.src_port}",
                destination_endpoint=f"{conn.dst_ip}:{conn.dst_port}",
                observed_behavior=f"Direct outbound TCP connection to non-standard port {conn.dst_port}",
                why_suspicious="Threat actors often host C2 listeners on unusual or ephemeral high ports to evade default port inspection.",
                alternative_benign_explanations="Legitimate custom internal applications, P2P network services, or cloud database connections.",
                confidence_level="Low",
                recommended_follow_up="Determine what application on the source host initiated the connection via netstat or EDR socket telemetry.",
            ))

    # 4. Behavioral Analysis: Beaconing Clustering
    dest_timestamps: Dict[str, List[str]] = {}
    for conn in metadata.connections:
        dest_key = f"{conn.dst_ip}:{conn.dst_port}"
        dest_timestamps.setdefault(dest_key, []).append(conn.start_time)

    for dst_endpoint, ts_list in dest_timestamps.items():
        beacon_stats = detect_beaconing_intervals(ts_list)
        if beacon_stats:
            all_findings.append(Finding(
                finding_id=f"BEACON-{len(all_findings)+1:03d}",
                evidence_source="Connection Interval Clustering",
                timestamp=ts_list[0],
                source_endpoint="Multiple",
                destination_endpoint=dst_endpoint,
                observed_behavior=f"Repeated outbound connections with strict periodic regularity: mean interval {beacon_stats['mean_interval_sec']}s, CV {beacon_stats['coefficient_of_variation']}",
                why_suspicious="Consistent low variance in connection inter-arrival times strongly correlates with automated malware heartbeat/check-in polling.",
                alternative_benign_explanations="Automated software telemetry check, NTP heartbeat, or persistent health ping.",
                confidence_level="Medium",
                recommended_follow_up="Examine process sleep timers and call stacks for loop/interval patterns.",
            ))

    return DetectionReport(
        case_id=metadata.case_id,
        pcap_filename=metadata.pcap_filename,
        findings=all_findings,
        suricata_alerts_count=suricata_count,
        behavioral_anomalies_count=len(all_findings) - suricata_count,
    )
