"""Unit tests for Feature B: Network Metadata Extraction."""

import struct
from pathlib import Path
import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import wrpcap

from pcap_analyzer.extraction import extract_metadata, extract_metadata_scapy


def build_raw_tls_client_hello(sni_hostname: str) -> bytes:
    """Construct a clean, valid RFC 5246 TLS ClientHello with SNI extension."""
    sni_bytes = sni_hostname.encode("ascii")
    # Server Name extension data:
    # Server Name list length (2 bytes), Name Type (0 = host_name), Name length (2 bytes), Hostname bytes
    sn_list = struct.pack("!HBH", len(sni_bytes) + 3, 0, len(sni_bytes)) + sni_bytes
    # Extension header: type 0x0000 (2 bytes), length (2 bytes)
    ext_sni = struct.pack("!HH", 0x0000, len(sn_list)) + sn_list
    # Extensions block
    ext_block = struct.pack("!H", len(ext_sni)) + ext_sni

    # ClientHello payload:
    # client_version: TLS 1.2 (0x0303)
    # random: 32 bytes
    # session_id: 0 bytes
    # cipher_suites: 2 suites (0x002f, 0x0035) -> 4 bytes
    # compression_methods: 1 byte (0x00) -> 1 byte
    client_version = b"\x03\x03"
    random_bytes = b"\x00" * 32
    session_id = b"\x00"
    cipher_suites = b"\x00\x02\x00\x2f"
    compression_methods = b"\x01\x00"

    client_hello_body = (
        client_version
        + random_bytes
        + session_id
        + cipher_suites
        + compression_methods
        + ext_block
    )

    # Handshake header: type 0x01 (ClientHello), length (3 bytes)
    handshake_hdr = struct.pack("!B", 0x01) + struct.pack("!I", len(client_hello_body))[1:]
    handshake_msg = handshake_hdr + client_hello_body

    # TLS Record Layer: ContentType 0x16 (Handshake), Version 0x0301 (TLS 1.0 record framing), Length (2 bytes)
    # Format '!BBBH' = 5 bytes total
    record_hdr = struct.pack("!BBBH", 22, 3, 1, len(handshake_msg))
    return record_hdr + handshake_msg


@pytest.fixture
def traffic_pcap_file(tmp_path: Path) -> Path:
    """Generate a synthetic PCAP containing DNS, HTTP, and TLS packets."""
    pcap_file = tmp_path / "traffic_sample.pcap"

    # Packet 1: DNS Query for evil-domain.com
    dns_query = (
        IP(src="192.168.1.100", dst="8.8.8.8")
        / UDP(sport=54321, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="evil-domain.com", qtype="A"))
    )

    # Packet 2: DNS Response resolving to 198.51.100.25
    dns_resp = (
        IP(src="8.8.8.8", dst="192.168.1.100")
        / UDP(sport=53, dport=54321)
        / DNS(
            qr=1,
            aa=1,
            qd=DNSQR(qname="evil-domain.com", qtype="A"),
            an=DNSRR(rrname="evil-domain.com", rdata="198.51.100.25"),
        )
    )

    # Packet 3: HTTP GET request to malicious payload URI
    http_payload = (
        b"GET /payload.exe HTTP/1.1\r\n"
        b"Host: evil-domain.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"\r\n"
    )
    http_pkt = (
        IP(src="192.168.1.100", dst="198.51.100.25")
        / TCP(sport=49152, dport=80, flags="PA")
        / http_payload
    )

    # Packet 4: TLS Client Hello with SNI beacon-c2.net
    tls_payload = build_raw_tls_client_hello("beacon-c2.net")
    tls_pkt = (
        IP(src="192.168.1.100", dst="203.0.113.15")
        / TCP(sport=49153, dport=443, flags="PA")
        / tls_payload
    )

    wrpcap(str(pcap_file), [dns_query, dns_resp, http_pkt, tls_pkt])
    return pcap_file


def test_metadata_extraction_scapy(traffic_pcap_file: Path):
    """Test extraction of connections, DNS, HTTP, and TLS using Scapy."""
    metadata = extract_metadata_scapy(traffic_pcap_file, case_id="CASE-TRAFFIC-001")

    assert metadata.case_id == "CASE-TRAFFIC-001"
    assert metadata.pcap_filename == "traffic_sample.pcap"
    assert metadata.extraction_source == "pure_python_scapy"

    # Validate connections
    assert len(metadata.connections) >= 3

    # Validate DNS records
    assert len(metadata.dns_queries) == 2
    query_rec = metadata.dns_queries[0]
    assert query_rec.query_name == "evil-domain.com"
    assert query_rec.query_type == "A"

    resp_rec = metadata.dns_queries[1]
    assert resp_rec.query_name == "evil-domain.com"
    assert "198.51.100.25" in resp_rec.answers

    # Validate HTTP records
    assert len(metadata.http_requests) == 1
    http_rec = metadata.http_requests[0]
    assert http_rec.method == "GET"
    assert http_rec.uri == "/payload.exe"
    assert http_rec.host == "evil-domain.com"
    assert "Mozilla" in (http_rec.user_agent or "")

    # Validate TLS SNI
    assert len(metadata.tls_handshakes) == 1
    tls_rec = metadata.tls_handshakes[0]
    assert tls_rec.server_name == "beacon-c2.net"


def test_metadata_extraction_save(traffic_pcap_file: Path, tmp_path: Path):
    """Test full extraction workflow and JSON persistence."""
    out_dir = tmp_path / "metadata_out"
    metadata = extract_metadata(
        pcap_path=traffic_pcap_file,
        case_id="CASE-SAVE-001",
        output_dir=out_dir,
        prefer_tshark=False,
    )
    assert (out_dir / "metadata.json").exists()
    assert len(metadata.connections) > 0


def test_metadata_extraction_nonexistent(tmp_path: Path):
    """Test error handling when PCAP does not exist."""
    missing = tmp_path / "nonexistent.pcap"
    with pytest.raises(FileNotFoundError):
        extract_metadata(pcap_path=missing, case_id="CASE-ERR")

from click.testing import CliRunner
from pcap_analyzer.cli import main


def test_cli_extract_cmd_success(traffic_pcap_file: Path, tmp_path: Path):
    """Test CLI extract command execution."""
    runner = CliRunner()
    out_dir = tmp_path / "cli_extract_out"
    result = runner.invoke(main, [
        "extract",
        str(traffic_pcap_file),
        "-c", "PCAP-CLI-EXT-001",
        "-o", str(out_dir),
        "--force-scapy",
    ])
    assert result.exit_code == 0
    assert "metadata extraction complete" in result.output.lower()
    assert (out_dir / "metadata.json").exists()
