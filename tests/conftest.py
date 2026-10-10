"""Pytest fixtures for NetTrace test suite."""

from __future__ import annotations

import struct
from pathlib import Path
import pytest


@pytest.fixture
def valid_pcap_file(tmp_path: Path) -> Path:
    """Generate a minimal valid libpcap file header."""
    file_path = tmp_path / "sample_valid.pcap"
    # Standard libpcap global header (24 bytes)
    # magic_number (0xa1b2c3d4), major (2), minor (4), thiszone (0), sigfigs (0), snaplen (65535), network (1 = Ethernet)
    global_header = struct.pack("=IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    file_path.write_bytes(global_header)
    return file_path


@pytest.fixture
def valid_pcapng_file(tmp_path: Path) -> Path:
    """Generate a minimal valid pcapng Section Header Block."""
    file_path = tmp_path / "sample_valid.pcapng"
    # Section Header Block (28 bytes):
    # Block Type: 0x0A0D0D0A (4 bytes)
    # Block Total Length: 28 (4 bytes)
    # Byte-Order Magic: 0x1A2B3C4D (4 bytes)
    # Major Version: 1 (2 bytes)
    # Minor Version: 0 (2 bytes)
    # Section Length: -1 (8 bytes)
    # Block Total Length: 28 (4 bytes)
    shb = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    file_path.write_bytes(shb)
    return file_path


@pytest.fixture
def invalid_text_file(tmp_path: Path) -> Path:
    """Generate a plain text file pretending to be a pcap."""
    file_path = tmp_path / "fake_capture.pcap"
    file_path.write_text("This is plain text, not a network packet capture.")
    return file_path


@pytest.fixture
def empty_file(tmp_path: Path) -> Path:
    """Generate an empty file."""
    file_path = tmp_path / "empty.pcap"
    file_path.touch()
    return file_path
