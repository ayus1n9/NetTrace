"""Unit tests for Feature G, H, I: Malware Assessment, ATT&CK Mapping & Incident Reporting."""

from pathlib import Path
import pytest

from pcap_analyzer.detection import analyze_suspicious_behavior
from pcap_analyzer.extraction import extract_metadata_scapy
from pcap_analyzer.intake import intake_capture
from pcap_analyzer.ioc_extractor import extract_iocs
from pcap_analyzer.reporting import (
    assess_malware_family,
    generate_incident_report,
    generate_incident_report_markdown,
    identify_affected_endpoints,
    map_mitre_attack,
)
from pcap_analyzer.timeline import build_timeline
from tests.test_extraction import traffic_pcap_file


def test_map_mitre_attack_defensible_statuses(traffic_pcap_file: Path, tmp_path: Path):
    """Verify ATT&CK techniques mapped to observed network behaviors with defensible evidentiary statuses."""
    metadata = extract_metadata_scapy(traffic_pcap_file, case_id="CASE-ATTACK-001")
    det_report = analyze_suspicious_behavior(metadata, output_dir=tmp_path)

    techniques = map_mitre_attack(metadata, det_report.findings)
    assert len(techniques) >= 3

    tech_map = {t.technique_id: t for t in techniques}
    assert "T1071.004" in tech_map  # DNS
    assert "T1105" in tech_map      # Ingress Tool Transfer (.exe)

    # Critical 3 assertion: Status must NOT be unconditionally 'Confirmed'
    # It must be evidence-grounded like 'Observed Transfer Attempt' or 'Hypothesis / Suspected'
    assert tech_map["T1105"].status == "Observed Transfer Attempt"
    assert "Requires endpoint confirmation" in tech_map["T1105"].endpoint_verification_needed


def test_identify_affected_endpoints_scoping(traffic_pcap_file: Path, tmp_path: Path):
    """Verify Critical 4: DNS resolvers and infrastructure are not labeled as compromised."""
    metadata = extract_metadata_scapy(traffic_pcap_file, case_id="CASE-ROLES-001")
    det_report = analyze_suspicious_behavior(metadata, output_dir=tmp_path)

    roles = identify_affected_endpoints(metadata, det_report.findings)
    assert "192.168.1.100" in roles["suspected_compromised"]
    assert "8.8.8.8" in roles["external_endpoints"]


def test_assess_malware_family_conservative(traffic_pcap_file: Path, tmp_path: Path):
    """Test Critical 5: Evidence-backed conservative malware classification."""
    metadata = extract_metadata_scapy(traffic_pcap_file, case_id="CASE-MAL-001")
    det_report = analyze_suspicious_behavior(metadata, output_dir=tmp_path)

    assessment = assess_malware_family(metadata, det_report.findings)
    # Without dynamic execution confirmation, must remain Possible or Inconclusive
    assert assessment.confidence_tier in ("Possible", "Inconclusive")
    assert assessment.rationale
    assert assessment.alternative_hypotheses
    assert assessment.endpoint_data_required


def test_generate_incident_report_end_to_end(traffic_pcap_file: Path, tmp_path: Path):
    """Test full execution of incident report generation."""
    report_file = generate_incident_report(
        pcap_path=traffic_pcap_file,
        case_id="PCAP-REP-001",
        output_dir=tmp_path,
    )
    assert report_file.exists()
    content = report_file.read_text(encoding="utf-8")

    assert "# Forensic Investigation & Network Incident Report" in content
    assert "PCAP-REP-001" in content
    assert "## 1. Executive Summary" in content
    assert "## 4. Affected Hosts & Network Endpoints" in content
    assert "Internal Network Scoping" in content
    assert "## 6. Chronological Investigation Timeline" in content
    assert "## 7. Extracted Indicators of Compromise (IOCs)" in content
    assert "## 9. MITRE ATT&CK Technique Mapping" in content
    assert "Evidentiary Status" in content
    assert "## 11. Recommended Containment & Remediation Actions" in content


from click.testing import CliRunner
from pcap_analyzer.cli import main


def test_cli_report_command(traffic_pcap_file: Path, tmp_path: Path):
    """Test CLI report command invocation."""
    runner = CliRunner()
    out_dir = tmp_path / "cli_rep_out"
    result = runner.invoke(main, [
        "report",
        str(traffic_pcap_file),
        "-c", "PCAP-CLI-REP-001",
        "-o", str(out_dir),
    ])
    assert result.exit_code == 0
    assert "Incident report generated successfully" in result.output
    assert (out_dir / "incident-report.md").exists()
