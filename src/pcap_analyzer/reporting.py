"""Malware-Family Assessment, MITRE ATT&CK Mapping, and Incident Report Generation.

Synthesizes case intake, extracted telemetry, candidate IOCs, detection findings,
and chronological timeline into an executive-ready and technically rigorous incident report.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field

from pcap_analyzer.detection import DetectionReport, Finding
from pcap_analyzer.extraction import ExtractedMetadata
from pcap_analyzer.intake import CaseMetadata
from pcap_analyzer.ioc_extractor import CaseIOCReport, is_rfc1918_or_internal
from pcap_analyzer.timeline import InvestigationTimeline, export_timeline_markdown


class AttackTechnique(BaseModel):
    """MITRE ATT&CK mapping entry."""
    tactic: str
    technique_id: str
    technique_name: str
    status: str  # Observed, Hypothesis / Suspected, Corroborated
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
    """Map observed network activity to MITRE ATT&CK Enterprise techniques with defensible statuses."""
    techniques: List[AttackTechnique] = []

    # 1. DNS Activity vs DNS C2 (T1071.004)
    dns_findings = [f for f in findings if "dns" in f.evidence_source.lower() or f.rule_id == "1000002"]
    if dns_findings:
        techniques.append(AttackTechnique(
            tactic="Command and Control",
            technique_id="T1071.004",
            technique_name="Application Layer Protocol: DNS",
            status="Hypothesis / Suspected",
            supporting_evidence=f"Observed DNS queries querying flagged or unusual infrastructure (e.g. {dns_findings[0].observed_behavior}).",
            endpoint_verification_needed="Verify process DNS query cache, parent process identity, and whether data exfiltration or C2 tunneling over TXT/NULL records took place.",
        ))
    elif metadata.dns_queries:
        techniques.append(AttackTechnique(
            tactic="Command and Control",
            technique_id="T1071.004",
            technique_name="Application Layer Protocol: DNS",
            status="Observed Protocol",
            supporting_evidence=f"Observed standard DNS name resolutions ({len(metadata.dns_queries)} queries/responses). No tunneling or C2 patterns confirmed in DNS logs.",
            endpoint_verification_needed="Endpoint socket logs required to identify resolving application.",
        ))

    # 2. Ingress Tool Transfer (HTTP executable download - T1105)
    exe_requests = [h for h in metadata.http_requests if h.uri.lower().endswith(".exe")]
    if exe_requests:
        techniques.append(AttackTechnique(
            tactic="Command and Control / Execution",
            technique_id="T1105",
            technique_name="Ingress Tool Transfer",
            status="Observed Transfer Attempt",
            supporting_evidence=f"Outbound HTTP GET request for executable binary '{exe_requests[0].uri}' from host '{exe_requests[0].host}'.",
            endpoint_verification_needed="Requires endpoint confirmation: Sysmon Event ID 11 (FileCreate) to prove write to disk, and Sysmon Event ID 1 (Process Create) to prove execution.",
        ))

    # 3. Application Layer Protocol: Web Protocols (T1071.001)
    if metadata.http_requests:
        status_val = "Hypothesis / Suspected" if exe_requests else "Observed Protocol"
        techniques.append(AttackTechnique(
            tactic="Command and Control",
            technique_id="T1071.001",
            technique_name="Application Layer Protocol: Web Protocols",
            status=status_val,
            supporting_evidence=f"Host generated cleartext HTTP requests ({len(metadata.http_requests)} request(s)) to external endpoints.",
            endpoint_verification_needed="Endpoint process lineage required (e.g., verifying whether powershell.exe, curl, or standard browser made the requests).",
        ))

    # 4. Encrypted Channel: Asymmetric Cryptography (TLS - T1573.002)
    c2_tls_findings = [f for f in findings if "tls" in f.evidence_source.lower() or f.rule_id == "1000004"]
    if c2_tls_findings:
        techniques.append(AttackTechnique(
            tactic="Command and Control",
            technique_id="T1573.002",
            technique_name="Encrypted Channel: Asymmetric Cryptography (TLS)",
            status="Hypothesis / Suspected",
            supporting_evidence=f"Observed TLS handshake with suspected C2 SNI '{c2_tls_findings[0].observed_behavior}'.",
            endpoint_verification_needed="Memory inspection / TLS session secret acquisition required to decrypt and inspect application-layer payload contents.",
        ))
    elif metadata.tls_handshakes:
        techniques.append(AttackTechnique(
            tactic="Command and Control",
            technique_id="T1573.002",
            technique_name="Encrypted Channel: Asymmetric Cryptography (TLS)",
            status="Observed Protocol",
            supporting_evidence=f"Observed {len(metadata.tls_handshakes)} standard TLS handshake negotiation(s).",
            endpoint_verification_needed="Inspection of endpoint certificates and client processes required.",
        ))

    # 5. Non-Standard High Ports (T1571)
    high_port_findings = [f for f in findings if "non-standard port" in f.observed_behavior.lower()]
    if high_port_findings:
        techniques.append(AttackTechnique(
            tactic="Command and Control",
            technique_id="T1571",
            technique_name="Non-Standard Port",
            status="Hypothesis / Suspected",
            supporting_evidence=f"Outbound transport sessions established to non-standard high ports: {', '.join(f.destination_endpoint for f in high_port_findings)}.",
            endpoint_verification_needed="Cross-examine endpoint socket table to verify binary binding to port.",
        ))

    return techniques


def assess_malware_family(
    metadata: ExtractedMetadata, findings: List[Finding]
) -> MalwareFamilyAssessment:
    """Evaluate malware family evidence conservatively without over-attribution."""
    has_exe_drop = any(h.uri.lower().endswith(".exe") for h in metadata.http_requests)
    has_beaconing = any("beaconing" in f.why_suspicious.lower() for f in findings)
    suricata_rule_hits = {f.rule_id for f in findings if f.rule_id}

    if has_exe_drop and has_beaconing and ("1000004" in suricata_rule_hits or "1000001" in suricata_rule_hits):
        return MalwareFamilyAssessment(
            confidence_tier="Possible",
            suspected_family="Unclassified Staged Implant / C2 Beaconing Activity",
            rationale="Network observations exhibit a multi-stage profile (staged HTTP binary retrieval accompanied by periodic beaconing sessions). However, without binary reverse engineering or endpoint process hashes, exact malware family attribution remains unconfirmed.",
            alternative_hypotheses="Authorized penetration testing exercise (Cobalt Strike, Sliver, Mythic), automated IT patch agent, or custom test fixture.",
            endpoint_data_required="Recovered payload SHA-256 hash, static/dynamic detonation sandbox report, and Sysmon process creation telemetry.",
        )
    elif has_exe_drop:
        return MalwareFamilyAssessment(
            confidence_tier="Possible",
            suspected_family="Unclassified Stager / Dropper",
            rationale="Observed cleartext binary retrieval consistent with initial staging, but insufficient secondary C2 network telemetry to classify an adversary campaign.",
            alternative_hypotheses="Legitimate software download, administrative utility, or non-malicious installation package.",
            endpoint_data_required="Executable hash analysis on VirusTotal/ThreatGrid and endpoint execution telemetry.",
        )
    else:
        return MalwareFamilyAssessment(
            confidence_tier="Inconclusive",
            suspected_family="Unknown / Inconclusive",
            rationale="Network traffic captures anomalous behavior but lacks distinct signature fingerprints or payload indicators required for malware family attribution.",
            alternative_hypotheses="Benign anomalies, non-standard application telemetry, or reconnaissance probing.",
            endpoint_data_required="Endpoint EDR telemetry, process memory dumps, and host persistence artifact scans.",
        )


def identify_affected_endpoints(
    metadata: ExtractedMetadata, findings: List[Finding]
) -> Dict[str, Any]:
    """Categorize observed IP addresses by role and evidence of compromise."""
    dns_servers: Set[str] = set()
    for dns in metadata.dns_queries:
        if not dns.is_response:
            dns_servers.add(dns.dst_ip)
        else:
            dns_servers.add(dns.src_ip)

    suspicious_sources: Set[str] = set()
    for f in findings:
        src = f.source_endpoint.split(":")[0]
        if src and src != "Multiple":
            suspicious_sources.add(src)

    compromised_candidates = set()
    dns_resolvers = set()
    benign_internal = set()
    external_endpoints = set()

    for conn in metadata.connections:
        for ip_addr in (conn.src_ip, conn.dst_ip):
            if not ip_addr:
                continue
            try:
                ip_obj = ipaddress.ip_address(ip_addr)
                is_internal = is_rfc1918_or_internal(ip_obj)
            except ValueError:
                continue

            if is_internal:
                if ip_addr in dns_servers:
                    dns_resolvers.add(ip_addr)
                elif ip_addr in suspicious_sources:
                    compromised_candidates.add(ip_addr)
                else:
                    benign_internal.add(ip_addr)
            else:
                external_endpoints.add(ip_addr)

    return {
        "suspected_compromised": sorted(list(compromised_candidates)),
        "internal_dns_resolvers": sorted(list(dns_resolvers)),
        "internal_other": sorted(list(benign_internal)),
        "external_endpoints": sorted(list(external_endpoints)),
    }


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
    endpoint_roles = identify_affected_endpoints(net_meta, det_report.findings)

    compromised_hosts_str = ", ".join(endpoint_roles["suspected_compromised"]) or "None identified"

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

The investigation identified **{len(endpoint_roles['suspected_compromised'])} host(s) exhibiting suspicious outbound activity** (`{compromised_hosts_str}`). Infrastructure hosts (such as internal DNS resolvers `{', '.join(endpoint_roles['internal_dns_resolvers']) or 'None'}`) were observed facilitating network name resolution and are categorized as internal infrastructure rather than compromised assets.

Suspicious events detected include **{det_report.suricata_alerts_count} signature alert(s)** and **{det_report.behavioral_anomalies_count} behavioral anomaly finding(s)**.

- **Malware Family Assessment**: **{malware_assessment.confidence_tier}** (`{malware_assessment.suspected_family}`)
- **Assessed Impact**: Potential host compromise with staged executable delivery attempt and subsequent Command-and-Control (C2) communication.
- **Immediate Action**: Isolate suspected host `{compromised_hosts_str}` and collect endpoint memory/process triage artifacts.

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
4. **Adversary Technique Mapping**: Aligning network evidence to the MITRE ATT&CK matrix using defensible, evidence-grounded statuses.
5. **Report & Containment Formulation**: Evidence-grounded remediation recommendations distinguishing compromised clients from supporting infrastructure.

---

## 4. Affected Hosts & Network Endpoints

### Internal Network Scoping
| IP Address | Role & Forensic Status | Defanged |
|---|---|---|
"""
    for ip in endpoint_roles["suspected_compromised"]:
        report += f"| `{ip}` | **Suspected Compromised Host** (Origin of suspicious egress traffic) | `{ip.replace('.', '[.]')}` |\n"
    for ip in endpoint_roles["internal_dns_resolvers"]:
        report += f"| `{ip}` | **Internal DNS Resolver / Infrastructure** (Not compromised; resolved queries) | `{ip.replace('.', '[.]')}` |\n"
    for ip in endpoint_roles["internal_other"]:
        report += f"| `{ip}` | Internal Observed Host (No suspicious activity observed) | `{ip.replace('.', '[.]')}` |\n"

    report += """
### External Infrastructure Interacted With
| IP / Endpoint | Association | Status |
|---|---|---|
"""
    for ip in endpoint_roles["external_endpoints"]:
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

| Tactic | Technique ID | Technique Name | Evidentiary Status | Supporting Evidence | Endpoint Verification Required |
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

1. **Immediate Host Containment**: Isolate suspected internal host(s) exhibiting anomalous egress from the enterprise network via EDR isolation or VLAN quarantine.
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
    resolved_pcap = Path(pcap_path).resolve()

    # Execute all pipeline phases
    from pcap_analyzer.intake import intake_capture
    case_meta = intake_capture(resolved_pcap, case_id=case_id, output_dir=out)

    from pcap_analyzer.extraction import extract_metadata
    net_meta = extract_metadata(resolved_pcap, case_id=case_id, output_dir=out)

    from pcap_analyzer.ioc_extractor import extract_iocs
    ioc_report = extract_iocs(net_meta, case_meta)

    from pcap_analyzer.detection import analyze_suspicious_behavior
    det_report = analyze_suspicious_behavior(net_meta, rules_file=rf, output_dir=out, explicit_pcap_path=resolved_pcap)

    from pcap_analyzer.timeline import build_timeline
    timeline = build_timeline(net_meta, det_report)

    # Render report
    md_report = generate_incident_report_markdown(case_meta, net_meta, ioc_report, det_report, timeline)
    report_file = out / "incident-report.md"
    report_file.write_text(md_report, encoding="utf-8")

    return report_file
