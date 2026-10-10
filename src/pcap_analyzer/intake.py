"""PCAP Case Intake and Integrity Verification Module.

Handles file validation, magic byte verification, cryptographic hashing (SHA-256),
and metadata registration without mutating the original packet capture.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


# Well-known packet capture magic bytes
PCAP_MAGIC_BYTES = {
    b"\xd4\xc3\xb2\xa1": "pcap (microsecond, identical byte order)",
    b"\xa1\xb2\xc3\xd4": "pcap (microsecond, swapped byte order)",
    b"\x4d\x3c\xb2\xa1": "pcap (nanosecond, identical byte order)",
    b"\xa1\xb2\x3c\x4d": "pcap (nanosecond, swapped byte order)",
    b"\x0a\x0d\x0d\x0a": "pcapng (PCAP Next Generation)",
}


class IntakeValidationError(Exception):
    """Raised when capture validation fails."""
    pass


class CaseMetadata(BaseModel):
    """Schema representing intake metadata for an investigated capture."""
    case_id: str = Field(..., description="Unique case identifier (e.g. PCAP-2026-001)")
    pcap_filename: str = Field(..., description="Original capture basename")
    pcap_path: str = Field(..., description="Absolute path to the preserved capture")
    dataset_source_url: Optional[str] = Field(None, description="Public source origin URL")
    publication_date: Optional[str] = Field(None, description="Dataset publication date")
    file_size_bytes: int = Field(..., description="Exact file size in bytes")
    sha256: str = Field(..., description="Calculated SHA-256 hash")
    magic_type: str = Field(..., description="Detected capture format")
    analysis_start_time: str = Field(..., description="UTC ISO-8601 analysis start timestamp")
    analyst_notes: Optional[str] = Field(None, description="Analyst scope and initial notes")
    file_preserved: bool = Field(True, description="Confirmation that original file remains unchanged")


def calculate_sha256(file_path: Path, chunk_size: int = 65536) -> str:
    """Calculate the SHA-256 hash of a file deterministically in chunks.

    Args:
        file_path: Path to target file.
        chunk_size: Read buffer size in bytes.

    Returns:
        Hexadecimal string of SHA-256 digest.
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def validate_pcap_magic(file_path: Path) -> str:
    """Verify that file header matches PCAP or PCAPNG magic numbers.

    Args:
        file_path: Path to file.

    Returns:
        Human-readable capture type description.

    Raises:
        IntakeValidationError: If file is too small or does not match valid PCAP signatures.
    """
    with open(file_path, "rb") as f:
        header = f.read(4)

    if len(header) < 4:
        raise IntakeValidationError(f"File {file_path.name} is too small to be a valid packet capture.")

    for magic, desc in PCAP_MAGIC_BYTES.items():
        if header.startswith(magic):
            return desc

    raise IntakeValidationError(
        f"File {file_path.name} lacks valid PCAP/PCAPNG magic header bytes (received: {header.hex()})."
    )


def intake_capture(
    pcap_path: str | Path,
    case_id: str,
    source_url: Optional[str] = None,
    publication_date: Optional[str] = None,
    analyst_notes: Optional[str] = None,
    output_dir: Optional[str | Path] = None,
) -> CaseMetadata:
    """Execute complete intake verification workflow for a PCAP file.

    Args:
        pcap_path: Target capture file path.
        case_id: Unique case identifier.
        source_url: Optional source URL (e.g. malware-traffic-analysis.net).
        publication_date: Optional release date of dataset.
        analyst_notes: Investigative notes or context.
        output_dir: Optional directory to store case-metadata.json.

    Returns:
        CaseMetadata model instance.

    Raises:
        FileNotFoundError: If input file does not exist.
        PermissionError: If file cannot be read.
        IntakeValidationError: If file fails capture format validation.
    """
    target = Path(pcap_path).resolve()

    if not target.exists():
        raise FileNotFoundError(f"Input capture file does not exist: {target}")

    if not target.is_file():
        raise IntakeValidationError(f"Path is not a regular file: {target}")

    if not os.access(target, os.R_OK):
        raise PermissionError(f"Capture file is not readable (check permissions): {target}")

    file_size = target.stat().st_size
    if file_size == 0:
        raise IntakeValidationError(f"Capture file is empty (0 bytes): {target}")

    # Validate binary format
    magic_type = validate_pcap_magic(target)

    # Compute SHA-256 hash
    sha256_hash = calculate_sha256(target)

    # Build metadata record
    now_utc = datetime.now(timezone.utc).isoformat()
    metadata = CaseMetadata(
        case_id=case_id,
        pcap_filename=target.name,
        pcap_path=str(target),
        dataset_source_url=source_url,
        publication_date=publication_date,
        file_size_bytes=file_size,
        sha256=sha256_hash,
        magic_type=magic_type,
        analysis_start_time=now_utc,
        analyst_notes=analyst_notes,
        file_preserved=True,
    )

    # Optionally persist metadata
    if output_dir:
        out_path = Path(output_dir).resolve()
        out_path.mkdir(parents=True, exist_ok=True)
        meta_file = out_path / "case-metadata.json"
        with open(meta_file, "w", encoding="utf-8") as f:
            f.write(metadata.model_dump_json(indent=2))

    return metadata
