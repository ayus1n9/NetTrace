"""Command-Line Interface for NetTrace."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from pcap_analyzer.extraction import extract_metadata
from pcap_analyzer.intake import IntakeValidationError, intake_capture


@click.group()
@click.version_option()
def main() -> None:
    """NetTrace: Network Threat Hunting & Malware Traffic Investigation Toolkit."""
    pass


@main.command(name="intake")
@click.argument("pcap_file", type=click.Path())
@click.option("--case-id", "-c", required=True, help="Unique case identifier (e.g. PCAP-2026-001).")
@click.option("--source-url", "-u", default=None, help="Origin dataset URL (e.g., Malware-Traffic-Analysis.net).")
@click.option("--pub-date", "-d", default=None, help="Dataset publication date (YYYY-MM-DD).")
@click.option("--notes", "-n", default=None, help="Initial case notes / hypothesis.")
@click.option("--output-dir", "-o", default=None, type=click.Path(), help="Directory to save case-metadata.json.")
def intake_cmd(
    pcap_file: str,
    case_id: str,
    source_url: Optional[str],
    pub_date: Optional[str],
    notes: Optional[str],
    output_dir: Optional[str],
) -> None:
    """Validate and ingest a packet capture into an investigation case."""
    try:
        metadata = intake_capture(
            pcap_path=pcap_file,
            case_id=case_id,
            source_url=source_url,
            publication_date=pub_date,
            analyst_notes=notes,
            output_dir=output_dir,
        )
        click.echo("✓ Case intake successful.")
        click.echo(f"  Case ID:       {metadata.case_id}")
        click.echo(f"  File:          {metadata.pcap_filename} ({metadata.file_size_bytes} bytes)")
        click.echo(f"  Format:        {metadata.magic_type}")
        click.echo(f"  SHA-256:       {metadata.sha256}")
        click.echo(f"  Analysis Time: {metadata.analysis_start_time}")
        if output_dir:
            click.echo(f"  Metadata saved: {Path(output_dir) / 'case-metadata.json'}")
    except (FileNotFoundError, IntakeValidationError, PermissionError) as e:
        click.secho(f"✗ Intake error: {e}", fg="red", err=True)
        sys.exit(1)


@main.command(name="extract")
@click.argument("pcap_file", type=click.Path())
@click.option("--case-id", "-c", required=True, help="Unique case identifier.")
@click.option("--output-dir", "-o", default=None, type=click.Path(), help="Directory to save metadata.json.")
@click.option("--prefer-tshark/--force-scapy", default=True, help="Attempt TShark CLI dissection if available.")
def extract_cmd(
    pcap_file: str,
    case_id: str,
    output_dir: Optional[str],
    prefer_tshark: bool,
) -> None:
    """Extract connection flows, DNS, HTTP, and TLS metadata from capture."""
    try:
        data = extract_metadata(
            pcap_path=pcap_file,
            case_id=case_id,
            output_dir=output_dir,
            prefer_tshark=prefer_tshark,
        )
        click.echo("✓ Network metadata extraction complete.")
        click.echo(f"  Source Engine: {data.extraction_source}")
        click.echo(f"  Connections:   {len(data.connections)}")
        click.echo(f"  DNS Queries:   {len(data.dns_queries)}")
        click.echo(f"  HTTP Requests: {len(data.http_requests)}")
        click.echo(f"  TLS Handshakes:{len(data.tls_handshakes)}")
        if output_dir:
            click.echo(f"  Results saved: {Path(output_dir) / 'metadata.json'}")
    except Exception as e:
        click.secho(f"✗ Extraction error: {e}", fg="red", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
