"""Unit tests for Feature F: Automated Chronological Timeline."""

from pathlib import Path
import pytest

from pcap_analyzer.detection import analyze_suspicious_behavior
from pcap_analyzer.extraction import extract_metadata_scapy
from pcap_analyzer.timeline import (
    build_timeline,
    export_timeline_csv,
    export_timeline_markdown,
    parse_to_epoch,
)
from tests.test_extraction import traffic_pcap_file


def test_parse_to_epoch():
    """Verify ISO timestamp conversion to sorting epoch."""
    epoch = parse_to_epoch("2026-10-10T12:00:00+00:00")
    assert epoch > 1700000000.0

    epoch_z = parse_to_epoch("2026-10-10T12:00:00Z")
    assert epoch_z == epoch

    assert parse_to_epoch("invalid-date") == 0.0


def test_build_timeline_chronological_ordering(traffic_pcap_file: Path, tmp_path: Path):
    """Test correlation and strict temporal sequence sorting."""
    metadata = extract_metadata_scapy(traffic_pcap_file, case_id="CASE-TL-001")
    det_report = analyze_suspicious_behavior(metadata, output_dir=tmp_path)
    timeline = build_timeline(metadata, det_report)

    assert timeline.case_id == "CASE-TL-001"
    assert timeline.events_count > 0
    assert len(timeline.events) == timeline.events_count

    # Check that events are strictly sorted in ascending temporal order
    epochs = [parse_to_epoch(e.timestamp) for e in timeline.events]
    assert epochs == sorted(epochs)

    # Check event types present
    event_types = {e.event_type for e in timeline.events}
    assert "DNS Query" in event_types
    assert "DNS Response" in event_types
    assert "HTTP Request" in event_types
    assert "TLS Handshake" in event_types
    assert "Detection Alert" in event_types


def test_export_timeline_csv_and_markdown(traffic_pcap_file: Path, tmp_path: Path):
    """Test timeline exports to CSV file and Markdown table string."""
    metadata = extract_metadata_scapy(traffic_pcap_file, case_id="CASE-TL-002")
    det_report = analyze_suspicious_behavior(metadata, output_dir=tmp_path)
    timeline = build_timeline(metadata, det_report)

    csv_file = tmp_path / "timeline.csv"
    export_timeline_csv(timeline, csv_file)
    assert csv_file.exists()
    csv_text = csv_file.read_text()
    assert "Timestamp (UTC),Event_Type,Evidence_Source" in csv_text
    assert "evil-domain.com" in csv_text

    md_table = export_timeline_markdown(timeline)
    assert "| Timestamp (UTC) | Event | Source | Destination | Summary | Interpretation |" in md_table
    assert "**DNS Query**" in md_table

from click.testing import CliRunner
from pcap_analyzer.cli import main


def test_cli_timeline_command(traffic_pcap_file: Path, tmp_path: Path):
    """Test CLI timeline command invocation."""
    runner = CliRunner()
    out_dir = tmp_path / "cli_tl_out"
    result = runner.invoke(main, [
        "timeline",
        str(traffic_pcap_file),
        "-c", "PCAP-CLI-TL-001",
        "-o", str(out_dir),
    ])
    assert result.exit_code == 0
    assert "Investigation timeline built" in result.output
    assert (out_dir / "timeline.csv").exists()
