"""Unit tests for Feature D & E: Network Detection and Suspicious Behavior Analysis."""

from pathlib import Path
import pytest

from pcap_analyzer.detection import (
    analyze_suspicious_behavior,
    detect_beaconing_intervals,
    evaluate_custom_rules_fallback,
)
from pcap_analyzer.extraction import extract_metadata_scapy
from tests.test_extraction import traffic_pcap_file


def test_detect_beaconing_intervals():
    """Verify statistical detection of periodic connection intervals."""
    # Periodic intervals: every 10 seconds (10.0, 10.1, 9.9, 10.0)
    periodic_ts = [
        "2026-10-10T10:00:00+00:00",
        "2026-10-10T10:00:10+00:00",
        "2026-10-10T10:00:20+00:00",
        "2026-10-10T10:00:30+00:00",
        "2026-10-10T10:00:40+00:00",
    ]
    res = detect_beaconing_intervals(periodic_ts, min_hits=3, cv_threshold=0.25)
    assert res is not None
    assert res["mean_interval_sec"] == 10.0
    assert res["coefficient_of_variation"] < 0.05

    # Random jitter intervals (1s, 45s, 3s, 120s)
    irregular_ts = [
        "2026-10-10T10:00:00+00:00",
        "2026-10-10T10:00:01+00:00",
        "2026-10-10T10:00:46+00:00",
        "2026-10-10T10:00:49+00:00",
        "2026-10-10T10:02:49+00:00",
    ]
    res_irregular = detect_beaconing_intervals(irregular_ts, min_hits=3, cv_threshold=0.25)
    assert res_irregular is None


def test_evaluate_custom_rules_fallback(traffic_pcap_file: Path):
    """Verify fallback signature detection on synthetic malware traffic."""
    metadata = extract_metadata_scapy(traffic_pcap_file, case_id="CASE-DET-001")
    findings = evaluate_custom_rules_fallback(metadata)

    assert len(findings) >= 2

    # Check executable download rule hit (SID 1000001)
    exe_hits = [f for f in findings if f.rule_id == "1000001"]
    assert len(exe_hits) == 1
    assert "payload.exe" in exe_hits[0].observed_behavior
    assert exe_hits[0].confidence_level == "High"
    assert "Sysmon" in exe_hits[0].recommended_follow_up

    # Check TLS SNI beacon rule hit (SID 1000004)
    c2_hits = [f for f in findings if f.rule_id == "1000004"]
    assert len(c2_hits) == 1
    assert "beacon-c2.net" in c2_hits[0].observed_behavior


def test_analyze_suspicious_behavior(traffic_pcap_file: Path, tmp_path: Path):
    """Test integrated detection reporting."""
    metadata = extract_metadata_scapy(traffic_pcap_file, case_id="CASE-DET-002")
    report = analyze_suspicious_behavior(metadata, output_dir=tmp_path)

    assert report.case_id == "CASE-DET-002"
    assert len(report.findings) > 0
    for finding in report.findings:
        assert finding.finding_id
        assert finding.evidence_source
        assert finding.why_suspicious
        assert finding.alternative_benign_explanations
        assert finding.recommended_follow_up

from click.testing import CliRunner
from pcap_analyzer.cli import main


def test_cli_detect_command(traffic_pcap_file: Path, tmp_path: Path):
    """Test CLI detect command invocation."""
    runner = CliRunner()
    out_dir = tmp_path / "cli_detect_out"
    result = runner.invoke(main, [
        "detect",
        str(traffic_pcap_file),
        "-c", "PCAP-CLI-DET-001",
        "-o", str(out_dir),
    ])
    assert result.exit_code == 0
    assert "Network detection analysis complete" in result.output
    assert (out_dir / "findings.json").exists()
