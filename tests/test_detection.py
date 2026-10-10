"""Unit tests for Feature D & E: Network Detection and Suspicious Behavior Analysis."""

from pathlib import Path
import pytest

from pcap_analyzer.detection import (
    analyze_suspicious_behavior,
    detect_beaconing_intervals,
    evaluate_custom_rules_fallback,
    run_suricata_offline,
)
from pcap_analyzer.extraction import extract_metadata_scapy
from tests.test_extraction import traffic_pcap_file


def test_detect_beaconing_intervals():
    """Verify statistical detection of periodic connection intervals."""
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


def test_suricata_execution_reporting_missing_or_failed(traffic_pcap_file: Path, tmp_path: Path):
    """Verify run_suricata_offline returns diagnostic execution result when missing or failed."""
    fake_rules = tmp_path / "dummy.rules"
    fake_rules.write_text("alert http any any -> any any (msg:\"test\"; sid:1;)\n")

    # Call with non-existent PCAP
    non_existent = tmp_path / "does_not_exist.pcap"
    alerts, res = run_suricata_offline(non_existent, fake_rules, tmp_path)
    assert len(alerts) == 0
    assert res.success is False


def test_analyze_suspicious_behavior(traffic_pcap_file: Path, tmp_path: Path):
    """Test integrated detection reporting."""
    metadata = extract_metadata_scapy(traffic_pcap_file, case_id="CASE-DET-002")
    report = analyze_suspicious_behavior(metadata, output_dir=tmp_path, explicit_pcap_path=traffic_pcap_file)

    assert report.case_id == "CASE-DET-002"
    assert report.pcap_path == str(traffic_pcap_file.resolve())
    assert len(report.findings) > 0
    for finding in report.findings:
        assert finding.finding_id
        assert finding.evidence_source
        assert finding.why_suspicious
        assert finding.alternative_benign_explanations
        assert finding.recommended_follow_up


def test_dns_response_not_duplicated_in_findings(tmp_path: Path):
    """Test Critical 2: DNS queries and responses are not flagged as duplicate suspicious events."""
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, UDP
    from scapy.utils import wrpcap

    pcap_file = tmp_path / "dns_dup_test.pcap"
    # Query for .xyz domain
    q = IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=5000, dport=53) / DNS(rd=1, qd=DNSQR(qname="malicious-site.xyz", qtype="A"))
    # Response for same .xyz domain
    r = IP(src="10.0.0.1", dst="10.0.0.5") / UDP(sport=53, dport=5000) / DNS(qr=1, aa=1, qd=DNSQR(qname="malicious-site.xyz", qtype="A"), an=DNSRR(rrname="malicious-site.xyz", rdata="198.51.100.99"))

    wrpcap(str(pcap_file), [q, r])
    meta = extract_metadata_scapy(pcap_file, "CASE-DNS-DUP")
    findings = evaluate_custom_rules_fallback(meta)

    # Exactly 1 finding for the query, NOT 2 (no duplicate on response)
    dns_hits = [f for f in findings if f.rule_id == "1000002"]
    assert len(dns_hits) == 1
    assert "malicious-site.xyz" in dns_hits[0].observed_behavior
    assert "198.51.100.99" in dns_hits[0].observed_behavior  # correlated answer tracked
    assert dns_hits[0].source_endpoint == "10.0.0.5"  # query source preserved, not response sender

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
