"""Unit tests covering CLI error handling paths and edge cases."""

import os
from pathlib import Path
from click.testing import CliRunner
import pytest
import ipaddress

from pcap_analyzer.cli import main
from pcap_analyzer.intake import IntakeValidationError, intake_capture
from pcap_analyzer.ioc_extractor import defang_ip, defang_url, is_rfc1918_or_internal


def test_cli_extract_cmd_failure(tmp_path: Path):
    """Test CLI extract command when given a missing file."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "extract",
        str(tmp_path / "nonexistent.pcap"),
        "-c", "CASE-CLI-ERR",
    ])
    assert result.exit_code != 0
    assert "Extraction error:" in result.output


def test_cli_ioc_cmd_failure(tmp_path: Path):
    """Test CLI ioc command when given a missing file."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "ioc",
        str(tmp_path / "nonexistent.pcap"),
        "-c", "CASE-CLI-ERR",
    ])
    assert result.exit_code != 0
    assert "IOC extraction error:" in result.output


def test_cli_detect_cmd_failure(tmp_path: Path):
    """Test CLI detect command when given a missing file."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "detect",
        str(tmp_path / "nonexistent.pcap"),
        "-c", "CASE-CLI-ERR",
    ])
    assert result.exit_code != 0
    assert "Detection analysis error:" in result.output


def test_cli_timeline_cmd_failure(tmp_path: Path):
    """Test CLI timeline command when given a missing file."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "timeline",
        str(tmp_path / "nonexistent.pcap"),
        "-c", "CASE-CLI-ERR",
    ])
    assert result.exit_code != 0
    assert "Timeline generation error:" in result.output


def test_cli_report_cmd_failure(tmp_path: Path):
    """Test CLI report command when given a missing file."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "report",
        str(tmp_path / "nonexistent.pcap"),
        "-c", "CASE-CLI-ERR",
    ])
    assert result.exit_code != 0
    assert "Report generation error:" in result.output


def test_defang_ipv6_and_urls():
    """Test defanging for IPv6 and URLs."""
    assert "2001:db8[:]:1" == defang_ip("2001:db8::1")
    assert "hxxp://example[.]com/download" == defang_url("http://example.com/download")
    assert "hxxps://example[.]com" == defang_url("https://example.com")
    assert "custom[.]protocol" == defang_url("custom.protocol")


def test_rfc1918_internal_ipv6():
    """Test internal IP classification for IPv6 and loopbacks."""
    loopback_v4 = ipaddress.ip_address("127.0.0.1")
    loopback_v6 = ipaddress.ip_address("::1")
    link_local_v6 = ipaddress.ip_address("fe80::1")
    public_v6 = ipaddress.ip_address("2606:4700:4700::1111")

    assert is_rfc1918_or_internal(loopback_v4) is True
    assert is_rfc1918_or_internal(loopback_v6) is True
    assert is_rfc1918_or_internal(link_local_v6) is True
    assert is_rfc1918_or_internal(public_v6) is False


def test_intake_directory_instead_of_file(tmp_path: Path):
    """Test intake raises IntakeValidationError when passed a directory."""
    with pytest.raises(IntakeValidationError, match="not a regular file"):
        intake_capture(pcap_path=tmp_path, case_id="CASE-DIR-TEST")
