"""Unit tests for Feature C: Structured IOC Extraction & Normalization."""

import json
from pathlib import Path
import pytest

from pcap_analyzer.extraction import extract_metadata_scapy
from pcap_analyzer.intake import intake_capture
from pcap_analyzer.ioc_extractor import (
    defang_domain,
    defang_ip,
    defang_url,
    export_iocs_to_csv,
    export_iocs_to_json,
    extract_iocs,
)
from tests.test_extraction import traffic_pcap_file


def test_defanging_utilities():
    """Verify standard defensive indicator defanging."""
    assert defang_ip("192.168.1.100") == "192.168.1[.]100"
    assert defang_ip("8.8.8.8") == "8.8.8[.]8"
    assert defang_ip("2001:db8::1") == "2001:db8[:]:1"

    assert defang_domain("evil-c2.net") == "evil-c2[.]net"
    assert defang_domain("sub.malicious.co.uk") == "sub.malicious.co[.]uk"

    assert defang_url("http://malware.org/loader.exe") == "hxxp://malware[.]org/loader.exe"
    assert defang_url("https://c2.xyz/beacon") == "hxxps://c2[.]xyz/beacon"


def test_extract_iocs_from_traffic(traffic_pcap_file: Path, tmp_path: Path):
    """Test full IOC extraction pipeline on multi-protocol capture."""
    case_meta = intake_capture(
        pcap_path=traffic_pcap_file,
        case_id="PCAP-IOC-001",
        output_dir=tmp_path,
    )
    net_meta = extract_metadata_scapy(traffic_pcap_file, case_id="PCAP-IOC-001")
    report = extract_iocs(net_meta, case_meta)

    assert report.case_id == "PCAP-IOC-001"
    assert report.source_file == "traffic_sample.pcap"
    assert report.analysis_status == "completed"

    # IPs
    ip_values = [i.value for i in report.indicators.ips]
    assert "192.168.1.100" in ip_values
    assert "198.51.100.25" in ip_values
    assert "8.8.8.8" in ip_values

    # Internal vs External distinction
    for ip_entry in report.indicators.ips:
        if ip_entry.value == "192.168.1.100":
            assert ip_entry.is_private is True
            assert "Internal host" in ip_entry.relevance_notes
        elif ip_entry.value in ("198.51.100.25", "203.0.113.15"):
            assert ip_entry.is_private is False

    # Domains
    domain_values = [d.value for d in report.indicators.domains]
    assert "evil-domain.com" in domain_values
    assert "beacon-c2.net" in domain_values

    # Check that evil-domain.com has resolved IP tracked
    for d in report.indicators.domains:
        if d.value == "evil-domain.com":
            assert "198.51.100.25" in d.resolved_ips
            assert "dns_query" in d.sources

    # URLs
    assert len(report.indicators.urls) == 1
    url_entry = report.indicators.urls[0]
    assert url_entry.host == "evil-domain.com"
    assert url_entry.uri == "/payload.exe"
    assert url_entry.defanged.startswith("hxxp://evil-domain[.]com")


def test_export_iocs_json_and_csv(traffic_pcap_file: Path, tmp_path: Path):
    """Verify export files match schema and CSV conventions."""
    case_meta = intake_capture(traffic_pcap_file, case_id="CASE-EXPORT-001")
    net_meta = extract_metadata_scapy(traffic_pcap_file, case_id="CASE-EXPORT-001")
    report = extract_iocs(net_meta, case_meta)

    json_path = tmp_path / "iocs.json"
    csv_path = tmp_path / "iocs.csv"

    export_iocs_to_json(report, json_path)
    export_iocs_to_csv(report, csv_path)

    assert json_path.exists()
    assert csv_path.exists()

    data = json.loads(json_path.read_text())
    assert data["case_id"] == "CASE-EXPORT-001"
    assert len(data["indicators"]["ips"]) > 0

    csv_content = csv_path.read_text()
    assert "Indicator_Type,Value,Defanged,Sources,Relevance_Notes" in csv_content
    assert "evil-domain[.]com" in csv_content

from click.testing import CliRunner
from pcap_analyzer.cli import main


def test_cli_ioc_command(traffic_pcap_file: Path, tmp_path: Path):
    """Test CLI ioc command end-to-end."""
    runner = CliRunner()
    out_dir = tmp_path / "cli_ioc_out"
    result = runner.invoke(main, [
        "ioc",
        str(traffic_pcap_file),
        "-c", "PCAP-CLI-IOC-001",
        "-o", str(out_dir),
    ])
    assert result.exit_code == 0
    assert "Structured IOC extraction complete" in result.output
    assert (out_dir / "iocs.json").exists()
    assert (out_dir / "iocs.csv").exists()
