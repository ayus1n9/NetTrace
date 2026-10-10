"""Unit tests for Feature A: PCAP Case Intake and Integrity Verification."""

import hashlib
import json
from pathlib import Path
import pytest

from pcap_analyzer.intake import (
    IntakeValidationError,
    calculate_sha256,
    intake_capture,
    validate_pcap_magic,
)


def test_calculate_sha256(valid_pcap_file: Path):
    """Test deterministic SHA-256 calculation."""
    calculated = calculate_sha256(valid_pcap_file)
    content = valid_pcap_file.read_bytes()
    expected = hashlib.sha256(content).hexdigest()
    assert calculated == expected
    assert len(calculated) == 64


def test_validate_pcap_magic_valid(valid_pcap_file: Path, valid_pcapng_file: Path):
    """Test recognition of standard pcap and pcapng headers."""
    desc_pcap = validate_pcap_magic(valid_pcap_file)
    assert "pcap" in desc_pcap

    desc_pcapng = validate_pcap_magic(valid_pcapng_file)
    assert "pcapng" in desc_pcapng


def test_validate_pcap_magic_invalid(invalid_text_file: Path):
    """Test rejection of non-pcap files."""
    with pytest.raises(IntakeValidationError) as excinfo:
        validate_pcap_magic(invalid_text_file)
    assert "lacks valid PCAP/PCAPNG magic header bytes" in str(excinfo.value)


def test_intake_capture_success(valid_pcap_file: Path, tmp_path: Path):
    """Test full intake workflow execution and metadata export."""
    out_dir = tmp_path / "case_output"
    metadata = intake_capture(
        pcap_path=valid_pcap_file,
        case_id="PCAP-2026-TEST-001",
        source_url="https://www.malware-traffic-analysis.net/sample.html",
        publication_date="2026-10-10",
        analyst_notes="Unit test intake verification.",
        output_dir=out_dir,
    )

    assert metadata.case_id == "PCAP-2026-TEST-001"
    assert metadata.pcap_filename == "sample_valid.pcap"
    assert metadata.file_size_bytes == 24
    assert metadata.file_preserved is True
    assert metadata.sha256 == calculate_sha256(valid_pcap_file)

    meta_file = out_dir / "case-metadata.json"
    assert meta_file.exists()
    saved_data = json.loads(meta_file.read_text())
    assert saved_data["case_id"] == "PCAP-2026-TEST-001"
    assert saved_data["sha256"] == metadata.sha256


def test_intake_missing_file(tmp_path: Path):
    """Test intake response when input file does not exist."""
    missing = tmp_path / "does_not_exist.pcap"
    with pytest.raises(FileNotFoundError):
        intake_capture(pcap_path=missing, case_id="CASE-ERR")


def test_intake_empty_file(empty_file: Path):
    """Test intake rejection of zero-byte files."""
    with pytest.raises(IntakeValidationError) as excinfo:
        intake_capture(pcap_path=empty_file, case_id="CASE-EMPTY")
    assert "empty" in str(excinfo.value).lower()

from click.testing import CliRunner
from pcap_analyzer.cli import main


def test_cli_intake_success(valid_pcap_file: Path, tmp_path: Path):
    """Test CLI intake invocation."""
    runner = CliRunner()
    out_dir = tmp_path / "cli_out"
    result = runner.invoke(main, [
        "intake",
        str(valid_pcap_file),
        "-c", "PCAP-CLI-001",
        "-u", "https://example.com/pcap",
        "-d", "2026-10-10",
        "-n", "CLI Test Notes",
        "-o", str(out_dir),
    ])
    assert result.exit_code == 0
    assert "Case intake successful" in result.output
    assert (out_dir / "case-metadata.json").exists()


def test_cli_intake_failure(invalid_text_file: Path):
    """Test CLI intake failure on malformed input."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "intake",
        str(invalid_text_file),
        "-c", "PCAP-FAIL-001",
    ])
    assert result.exit_code != 0
    assert "Intake error" in result.output
