"""Command-Line Interface for NetTrace."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

from pcap_analyzer.detection import analyze_suspicious_behavior
from pcap_analyzer.extraction import extract_metadata
from pcap_analyzer.intake import IntakeValidationError, intake_capture
from pcap_analyzer.ioc_extractor import (
    export_iocs_to_csv,
    export_iocs_to_json,
    extract_iocs,
)


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


@main.command(name="ioc")
@click.argument("pcap_file", type=click.Path())
@click.option("--case-id", "-c", required=True, help="Unique case identifier.")
@click.option("--output-dir", "-o", default="cases/output", type=click.Path(), help="Directory to save IOC outputs.")
def ioc_cmd(pcap_file: str, case_id: str, output_dir: str) -> None:
    """Extract, defang, and export candidate indicators of compromise (IOCs)."""
    try:
        out_path = Path(output_dir)
        case_meta = intake_capture(pcap_path=pcap_file, case_id=case_id, output_dir=out_path)
        net_meta = extract_metadata(pcap_path=pcap_file, case_id=case_id, output_dir=out_path)
        ioc_report = extract_iocs(net_meta, case_meta)

        json_file = out_path / "iocs.json"
        csv_file = out_path / "iocs.csv"
        export_iocs_to_json(ioc_report, json_file)
        export_iocs_to_csv(ioc_report, csv_file)

        click.echo("✓ Structured IOC extraction complete.")
        click.echo(f"  IP Candidates:     {len(ioc_report.indicators.ips)}")
        click.echo(f"  Domain Candidates: {len(ioc_report.indicators.domains)}")
        click.echo(f"  URLs Identified:   {len(ioc_report.indicators.urls)}")
        click.echo(f"  JSON Export:       {json_file}")
        click.echo(f"  CSV Export:        {csv_file}")
    except Exception as e:
        click.secho(f"✗ IOC extraction error: {e}", fg="red", err=True)
        sys.exit(1)


@main.command(name="detect")
@click.argument("pcap_file", type=click.Path())
@click.option("--case-id", "-c", required=True, help="Unique case identifier.")
@click.option("--rules-file", "-r", default="configs/suricata/custom.rules", type=click.Path(), help="Path to rules file.")
@click.option("--output-dir", "-o", default="cases/output", type=click.Path(), help="Directory to save findings.")
def detect_cmd(pcap_file: str, case_id: str, rules_file: str, output_dir: str) -> None:
    """Analyze suspicious network behaviors and run intrusion detection rules."""
    try:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        net_meta = extract_metadata(pcap_path=pcap_file, case_id=case_id, output_dir=out_path)
        rf = Path(rules_file) if Path(rules_file).exists() else None

        report = analyze_suspicious_behavior(net_meta, rules_file=rf, output_dir=out_path)
        findings_path = out_path / "findings.json"
        with open(findings_path, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))

        click.echo("✓ Network detection analysis complete.")
        click.echo(f"  Total Findings:      {len(report.findings)}")
        click.echo(f"  Suricata Alerts:     {report.suricata_alerts_count}")
        click.echo(f"  Behavior Anomalies:  {report.behavioral_anomalies_count}")
        click.echo(f"  Findings saved:      {findings_path}")
    except Exception as e:
        click.secho(f"✗ Detection analysis error: {e}", fg="red", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
