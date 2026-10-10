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
    map_mitre_attack,
)
from pcap_analyzer.timeline import build_timeline
from tests.test_extraction import traffic_pcap_file


def test_map_mitre_attack(traffic_pcap_file: Path, tmp_path: Path):
    """Verify ATT&CK techniques mapped to observed network behaviors."""
    metadata = extract_metadata_scapy(traffic_pcap_file, case_id="CASE-ATTACK-001")
    det_report = analyze_suspicious_behavior(metadata, output_dir=tmp_path)

    techniques = map_mitre_attack(metadata, det_report.findings)
    assert len(techniques) >= 3

    tech_ids = {t.technique_id for t in techniques}
    assert "T1071.004" in tech_ids  # DNS
    assert "T1105" in tech_ids      # Ingress Tool Transfer (.exe)
    assert "T1071.001" in tech_ids  # Web Protocols
    assert "T1573.002" in tech_ids  # TLS


def test_assess_malware_family(traffic_pcap_file: Path, tmp_path: Path):
    """Test evidence-backed malware classification."""
    metadata = extract_metadata_scapy(traffic_pcap_file, case_id="CASE-MAL-001")
    det_report = analyze_suspicious_behavior(metadata, output_dir=tmp_path)

    assessment = assess_malware_family(metadata, det_report.findings)
    assert assessment.confidence_tier in ("Probable", "Possible")
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
    assert "## 6. Chronological Investigation Timeline" in content
    assert "## 7. Extracted Indicators of Compromise (IOCs)" in content
    assert "## 9. MITRE ATT&CK Technique Mapping" in content
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
