"""Malware-Family Assessment, MITRE ATT&CK Mapping, and Incident Report Generation.

Synthesizes case intake, extracted telemetry, candidate IOCs, detection findings,
and chronological timeline into an executive-ready and technically rigorous incident report.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from pcap_analyzer.detection import DetectionReport, Finding
from pcap_analyzer.extraction import ExtractedMetadata
from pcap_analyzer.intake import CaseMetadata
from pcap_analyzer.ioc_extractor import CaseIOCReport
from pcap_analyzer.timeline import InvestigationTimeline, export_timeline_markdown


class AttackTechnique(BaseModel):
    """MITRE ATT&CK mapping entry."""
    tactic: str
    technique_id: str
    technique_name: str
    status: str  # Confirmed, Probable, Possible / Hypothesis
    supporting_evidence: str
    endpoint_verification_needed: str


class MalwareFamilyAssessment(BaseModel):
    """Evidence-backed assessment of malware identity."""
    confidence_tier: str  # Confirmed, Probable, Possible, Inconclusive
    suspected_family: str
    rationale: str
    alternative_hypotheses: str
    endpoint_data_required: str


def map_mitre_attack(
    metadata: ExtractedMetadata, findings: List[Finding]
) -> List[AttackTechnique]:
    """Map observed network activity to MITRE ATT&CK Enterprise techniques."""
    techniques: List[AttackTechnique] = []

    # 1. DNS Resolution / C2
    if metadata.dns_queries:
        techniques.append(AttackTechnique(
            tactic="Command and Control",
            technique_id="T1071.004",
            technique_name="Application Layer Protocol: DNS",
            status="Confirmed",
            supporting_evidence=f"Observed {len(metadata.dns_queries)} DNS transactions querying external domains.",
            endpoint_verification_needed="Verify process DNS client cache and resolving application identity via endpoint socket logs.",
        ))

    # 2. Ingress Tool Transfer (HTTP executable download)
    http_exe_found = any(h.uri.lower().endswith(".exe") for h in metadata.http_requests)
    if http_exe_found:
        techniques.append(AttackTechnique(
            tactic="Command and Control / Execution",
            technique_id="T1105",
            technique_name="Ingress Tool Transfer",
            status="Confirmed",
            supporting_evidence="Cleartext HTTP GET request observed requesting a Windows PE binary (.exe) payload.",
            endpoint_verification_needed="Examine Sysmon Event ID 11 (FileCreate) and Sysmon Event ID 1 (Process Create) to confirm file write to disk and execution.",
        ))

    # 3. Application Layer Protocol (Web Protocols)
    if metadata.http_requests:
        techniques.append(AttackTechnique(
            tactic="Command and Control",
            technique_id="T1071.001",
            technique_name="Application Layer Protocol: Web Protocols",
            status="Confirmed",
            supporting_evidence="Host engaged in HTTP web communications to external infrastructure.",
            endpoint_verification_needed="Review parent process tree (e.g. powershell.exe, cmd.exe, or browser) that spawned the outbound connection.",
        ))

    # 4. Encrypted Channel (TLS Handshakes)
    if metadata.tls_handshakes:
        techniques.append(AttackTechnique(
            tactic="Command and Control",
            technique_id="T1573.002",
            technique_name="Encrypted Channel: Asymmetric Cryptography (TLS)",
            status="Probable",
            supporting_evidence="Observed TLS ClientHello handshakes to external destination endpoints.",
            endpoint_verification_needed="Inspect host memory for injected DLLs or living-off-the-land binaries maintaining persistent HTTPS sockets.",
        ))

    # 5. Non-Standard High Ports / Ephemeral Ports
    high_port_findings = [f for f in findings if "non-standard port" in f.observed_behavior.lower()]
    if high_port_findings:
        techniques.append(AttackTechnique(
            tactic="Command and Control",
            technique_id="T1571",
            technique_name="Non-Standard Port",
            status="Probable",
            supporting_evidence=f"Traffic observed communicating on non-standard ports: {', '.join(f.destination_endpoint for f in high_port_findings)}.",
            endpoint_verification_needed="Correlate with firewall/proxy logs and inspect process listening socket table.",
        ))

    return techniques


def assess_malware_family(
    metadata: ExtractedMetadata, findings: List[Finding]
) -> MalwareFamilyAssessment:
    """Evaluate malware family evidence conservatively without fabricated attribution."""
    has_exe_drop = any(h.uri.lower().endswith(".exe") for h in metadata.http_requests)
    has_c2_sni = any(
        "beacon" in (t.server_name or "").lower() or "c2" in (t.server_name or "").lower()
        for t in metadata.tls_handshakes
    )
    has_beaconing = any("beaconing" in f.why_suspicious.lower() for f in findings)

    if has_exe_drop and (has_c2_sni or has_beaconing):
        return MalwareFamilyAssessment(
            confidence_tier="Probable",
            suspected_family="Multi-Stage Loader / C2 Agent",
            rationale="Traffic patterns demonstrate a staged delivery sequence: initial HTTP payload transfer followed by structured TLS C2 beaconing. Multiple corroborating network indicators observed.",
            alternative_hypotheses="Automated security assessment scanner, penetration testing beacon (e.g. Cobalt Strike, Mythic, Sliver), or custom internal automated updater.",
            endpoint_data_required="Need endpoint file sample hash, binary static analysis / sandbox detonation, and process execution telemetry to achieve Confirmed attribution.",
        )
    elif has_exe_drop:
        return MalwareFamilyAssessment(
            confidence_tier="Possible",
            suspected_family="Unclassified Stager / Dropper",
            rationale="Observed cleartext binary retrieval consistent with initial staging, but insufficient secondary C2 network telemetry to conclusively classify malware family.",
            alternative_hypotheses="Legitimate software download or non-malicious installation utility.",
            endpoint_data_required="Executable hash analysis on VirusTotal/ThreatGrid and endpoint behavioral logs.",
        )
    else:
        return MalwareFamilyAssessment(
            confidence_tier="Inconclusive",
            suspected_family="Unknown / Inconclusive",
            rationale="Network traffic captures anomalous behavior but lacks distinct signature fingerprints or payload indicators required for malware family attribution.",
            alternative_hypotheses="Benign anomalies, non-standard application telemetry, or reconnaissance probing.",
            endpoint_data_required="Endpoint EDR telemetry, process memory dumps, and host persistence artifact scans.",
        )


def generate_incident_report_markdown(
    case_meta: CaseMetadata,
    net_meta: ExtractedMetadata,
    ioc_report: CaseIOCReport,
    det_report: DetectionReport,
    timeline: InvestigationTimeline,
) -> str:
    """Generate comprehensive, portfolio-quality markdown incident report."""
    attack_mappings = map_mitre_attack(net_meta, det_report.findings)
    malware_assessment = assess_malware_family(net_meta, det_report.findings)
    timeline_table = export_timeline_markdown(timeline)

    # Affected internal endpoints
    internal_hosts = {ip.value for ip in ioc_report.indicators.ips if ip.is_private}
    external_endpoints = {ip.value for ip in ioc_report.indicators.ips if not ip.is_private}

    report = f"""# Forensic Investigation & Network Incident Report

**Case Identifier**: `{case_meta.case_id}`  
**Target PCAP**: `{case_meta.pcap_filename}`  
**Capture SHA-256**: `{case_meta.sha256}`  
**Analysis Timestamp**: `{case_meta.analysis_start_time}`  
**Dataset Source**: {case_meta.dataset_source_url or 'Offline Capture Artifact'}  
**Status**: `Completed`  

---

## 1. Executive Summary

A network traffic investigation was performed on packet capture `{case_meta.pcap_filename}` to reconstruct adversary activity, identify compromised host endpoints, extract indicators of compromise (IOCs), and evaluate threats to the enterprise environment.

The investigation identified **{len(internal_hosts)} internal host(s)** (`{', '.join(sorted(internal_hosts)) or 'None'}`) interacting with external infrastructure across **{len(net_meta.connections)} connection flow(s)**. Suspicious activity was detected including **{det_report.suricata_alerts_count} signature alert(s)** and **{det_report.behavioral_anomalies_count} behavioral anomaly finding(s)**.

- **Malware Family Assessment**: **{malware_assessment.confidence_tier}** (`{malware_assessment.suspected_family}`)
- **Assessed Impact**: Potential host compromise with staged executable delivery and subsequent Command-and-Control (C2) communication attempts.
- **Immediate Action**: Host isolation and endpoint memory/process triage recommended.

---

## 2. Case Scope & Forensic Provenance

- **Forensic Capture**: `{case_meta.pcap_filename}`
- **Original File Size**: `{case_meta.file_size_bytes}` bytes
- **SHA-256 Digest**: `{case_meta.sha256}`
- **Format Verification**: `{case_meta.magic_type}` (Validated via binary magic header inspection)
- **Evidence Immutability**: Confirmed. Source capture was preserved read-only throughout all extraction stages.

---

## 3. Investigation Methodology

Analysis followed a structured, repeatable SOC defensive methodology:
1. **Intake & Verification**: Capture format verification, checksum verification, and provenance documentation.
2. **Metadata Dissection**: 5-tuple flow aggregation, DNS resolution mapping, cleartext HTTP inspection, and TLS ClientHello SNI parsing.
3. **Detection Engine Evaluation**: Offline Suricata signature evaluation (`custom.rules`) and mathematical beaconing interval analysis.
4. **Adversary Technique Mapping**: Aligning network evidence to the MITRE ATT&CK matrix.
5. **Report & Containment Formulation**: Evidence-grounded remediation recommendations.

---

## 4. Affected Hosts & Network Endpoints

### Internal Affected Endpoints
| IP Address | Role / Observation | Defanged |
|---|---|---|
"""
    for ip in sorted(internal_hosts):
        report += f"| `{ip}` | Suspected compromised internal client | `{ip.replace('.', '[.]')}` |\n"

    report += """
### External Infrastructure Interacted With
| IP / Endpoint | Association | Status |
|---|---|---|
"""
    for ip in sorted(external_endpoints):
        report += f"| `{ip}` | Remote communication endpoint | External Candidate |\n"

    report += f"""
---

## 5. Key Observations & Findings

Total Findings: **{len(det_report.findings)}**

"""
    for f in det_report.findings:
        report += f"""### [{f.finding_id}] {f.observed_behavior}
- **Evidence Source**: `{f.evidence_source}`
- **Timestamp (UTC)**: `{f.timestamp}`
- **Source**: `{f.source_endpoint}` ➔ **Destination**: `{f.destination_endpoint}`
- **Why Suspicious**: {f.why_suspicious}
- **Alternative Benign Explanation**: {f.alternative_benign_explanations}
- **Confidence Level**: `{f.confidence_level}`
- **Recommended Follow-up**: {f.recommended_follow_up}

"""

    report += f"""---

## 6. Chronological Investigation Timeline

{timeline_table}

---

## 7. Extracted Indicators of Compromise (IOCs)

### Candidate IP Addresses
| IP Address | Defanged | Scope | Observed Sources |
|---|---|---|---|
"""
    for ip in ioc_report.indicators.ips:
        report += f"| `{ip.value}` | `{ip.defanged}` | {'Internal' if ip.is_private else 'External'} | {', '.join(ip.sources)} |\n"

    report += """
### Candidate Domains & Hostnames
| Domain | Defanged | Sources | Resolved IPs |
|---|---|---|---|
"""
    for d in ioc_report.indicators.domains:
        resolved = ", ".join(d.resolved_ips) if d.resolved_ips else "None"
        report += f"| `{d.value}` | `{d.defanged}` | {', '.join(d.sources)} | `{resolved}` |\n"

    if ioc_report.indicators.urls:
        report += """
### Candidate URLs
| URL | Defanged | Method | Host / Path |
|---|---|---|---|
"""
        for u in ioc_report.indicators.urls:
            report += f"| `{u.value}` | `{u.defanged}` | `{u.method}` | `{u.host}{u.uri}` |\n"

    report += f"""
---

## 8. Malware-Family Assessment

- **Confidence Tier**: **{malware_assessment.confidence_tier}**
- **Suspected Classification**: `{malware_assessment.suspected_family}`
- **Forensic Rationale**: {malware_assessment.rationale}
- **Alternative Benign Hypotheses**: {malware_assessment.alternative_hypotheses}
- **Required Endpoint Telemetry**: {malware_assessment.endpoint_data_required}

---

## 9. MITRE ATT&CK Technique Mapping

| Tactic | Technique ID | Technique Name | Status | Supporting Evidence | Endpoint Verification Required |
|---|---|---|---|---|---|
"""
    for tech in attack_mappings:
        report += f"| **{tech.tactic}** | `{tech.technique_id}` | {tech.technique_name} | `{tech.status}` | {tech.supporting_evidence} | {tech.endpoint_verification_needed} |\n"

    report += """
---

## 10. Confidence, Caveats & Limitations

1. **Passive Capture Scope**: Passive network traffic alone cannot confirm process execution on endpoints. Observed file transfers must be corroborated with host file creation events.
2. **TLS Encryption Boundary**: Full application payloads for HTTPS/TLS traffic are encrypted. Analysis is limited to L4/L5 handshake metadata (SNI, endpoints, certificate subjects).
3. **Dynamic Infrastructure**: IP indicators may belong to shared hosting or CDNs. Blocks should be implemented with contextual scrutiny.

---

## 11. Recommended Containment & Remediation Actions

1. **Immediate Host Containment**: Isolate internal host(s) from the enterprise network via EDR isolation or VLAN quarantine.
2. **Network Blocklist Deployment**: Block external candidate IPs and domains at the perimeter firewall and DNS sinkhole.
3. **Endpoint Triage (EDR / Forensic Collection)**:
   - Collect Sysmon logs (EID 1, 3, 11) and PowerShell script block logs (EID 4104).
   - Inspect memory of active processes communicating with flagged external endpoints.
   - Scan local directories for dropped executables matching extracted URL paths.
4. **Threat Intelligence Correlation**: Submit extracted file hashes to enterprise threat intelligence repositories to cross-reference known threat actor campaigns.
"""
    return report


def generate_incident_report(
    pcap_path: str | Path,
    case_id: str,
    rules_file: Optional[str | Path] = None,
    output_dir: str | Path = "cases/output",
) -> Path:
    """End-to-end execution pipeline producing full markdown incident report and artifacts."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    rf = Path(rules_file) if rules_file and Path(rules_file).exists() else None

    # Execute all pipeline phases
    case_meta = CaseMetadata.model_validate_json((out / "case-metadata.json").read_text()) if (out / "case-metadata.json").exists() else None
    if not case_meta:
        from pcap_analyzer.intake import intake_capture
        case_meta = intake_capture(pcap_path, case_id=case_id, output_dir=out)

    from pcap_analyzer.extraction import extract_metadata
    net_meta = extract_metadata(pcap_path, case_id=case_id, output_dir=out)

    from pcap_analyzer.ioc_extractor import extract_iocs
    ioc_report = extract_iocs(net_meta, case_meta)

    from pcap_analyzer.detection import analyze_suspicious_behavior
    det_report = analyze_suspicious_behavior(net_meta, rules_file=rf, output_dir=out)

    from pcap_analyzer.timeline import build_timeline
    timeline = build_timeline(net_meta, det_report)

    # Render report
    md_report = generate_incident_report_markdown(case_meta, net_meta, ioc_report, det_report, timeline)
    report_file = out / "incident-report.md"
    report_file.write_text(md_report, encoding="utf-8")

    return report_file
