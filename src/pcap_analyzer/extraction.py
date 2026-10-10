"""Network Metadata Extraction Module.

Extracts connection flows (5-tuples, byte/packet counts, duration),
DNS query/response activity, HTTP methods and URIs, and TLS handshake
metadata (SNI, cipher suites, server names).

Supports TShark command-line extraction with robust pure-Python/Scapy
offline fallback when external binaries are not installed.
"""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# Scapy imports for offline packet dissection
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader


class ConnectionRecord(BaseModel):
    """Network connection 5-tuple flow summary."""
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    start_time: str
    end_time: str
    packet_count: int
    byte_count: int


class DNSRecord(BaseModel):
    """DNS transaction event."""
    timestamp: str
    src_ip: str
    dst_ip: str
    query_name: str
    query_type: str
    response_code: Optional[str] = None
    answers: List[str] = Field(default_factory=list)


class HTTPRecord(BaseModel):
    """HTTP transaction event."""
    timestamp: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    method: str
    host: str
    uri: str
    user_agent: Optional[str] = None
    status_code: Optional[int] = None


class TLSRecord(BaseModel):
    """TLS handshake metadata."""
    timestamp: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    server_name: Optional[str] = None
    version: Optional[str] = None
    cipher_suite: Optional[str] = None


class ExtractedMetadata(BaseModel):
    """Aggregate network metadata extracted from a capture."""
    case_id: str
    pcap_filename: str
    extraction_source: str
    extracted_at: str
    connections: List[ConnectionRecord] = Field(default_factory=list)
    dns_queries: List[DNSRecord] = Field(default_factory=list)
    http_requests: List[HTTPRecord] = Field(default_factory=list)
    tls_handshakes: List[TLSRecord] = Field(default_factory=list)
    encryption_notes: str = Field(
        default="Passive inspection only. Full application payloads for encrypted HTTPS/TLS sessions are not recovered."
    )


def _ts_to_iso(ts: float) -> str:
    """Format a UNIX float timestamp to UTC ISO-8601."""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def _parse_tls_sni(payload: bytes) -> Optional[str]:
    """Parse SNI (Server Name Indication) directly from raw TLS ClientHello payload.

    RFC 5246 / RFC 8446 compliant binary parser without external dependencies.
    """
    if len(payload) < 43:
        return None

    # TLS Record Header (5 bytes): Content Type (1 byte = 0x16), Version (2 bytes), Length (2 bytes)
    content_type, rec_ver_maj, rec_ver_min, rec_len = struct.unpack("!BBBH", payload[:5])
    if content_type != 0x16:
        return None

    handshake_type = payload[5]
    if handshake_type != 0x01:  # ClientHello
        return None

    # Handshake header is 4 bytes (offset 5 to 9)
    offset = 9
    if offset + 34 > len(payload):
        return None

    # Skip Client Version (2 bytes) + Random (32 bytes)
    offset += 34

    # Session ID
    if offset >= len(payload):
        return None
    session_id_len = payload[offset]
    offset += 1 + session_id_len

    # Cipher Suites
    if offset + 2 > len(payload):
        return None
    cipher_len = struct.unpack("!H", payload[offset:offset+2])[0]
    offset += 2 + cipher_len

    # Compression Methods
    if offset >= len(payload):
        return None
    comp_len = payload[offset]
    offset += 1 + comp_len

    # Extensions Length
    if offset + 2 > len(payload):
        return None
    ext_total_len = struct.unpack("!H", payload[offset:offset+2])[0]
    offset += 2
    ext_end = min(offset + ext_total_len, len(payload))

    # Loop through extensions
    while offset + 4 <= ext_end:
        ext_type, ext_len = struct.unpack("!HH", payload[offset:offset+4])
        offset += 4
        if ext_type == 0x0000:  # server_name extension
            if offset + 2 <= len(payload):
                sn_list_len = struct.unpack("!H", payload[offset:offset+2])[0]
                sn_offset = offset + 2
                while sn_offset + 3 <= offset + 2 + sn_list_len and sn_offset + 3 <= len(payload):
                    name_type = payload[sn_offset]
                    name_len = struct.unpack("!H", payload[sn_offset+1:sn_offset+3])[0]
                    sn_offset += 3
                    if name_type == 0:  # host_name
                        sni_bytes = payload[sn_offset:sn_offset+name_len]
                        return sni_bytes.decode("ascii", errors="ignore")
                    sn_offset += name_len
        offset += ext_len

    return None


def extract_metadata_scapy(pcap_path: Path, case_id: str) -> ExtractedMetadata:
    """Extract flows, DNS, HTTP, and TLS metadata using Scapy in pure offline mode."""
    flows: Dict[str, Dict[str, Any]] = {}
    dns_records: List[DNSRecord] = []
    http_records: List[HTTPRecord] = []
    tls_records: List[TLSRecord] = []

    dns_types = {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
        15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"
    }

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            pkt_time = float(pkt.time)
            iso_time = _ts_to_iso(pkt_time)
            pkt_len = len(pkt)

            src_ip, dst_ip = "", ""
            proto_name = ""
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
            else:
                continue

            src_port, dst_port = 0, 0
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                proto_name = "TCP"
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                proto_name = "UDP"
            else:
                proto_name = f"IP_PROTO_{pkt[IP].proto if IP in pkt else pkt[IPv6].nh}"

            flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto_name}"
            rev_key = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}/{proto_name}"
            canonical_key = flow_key if flow_key < rev_key else rev_key

            if canonical_key not in flows:
                flows[canonical_key] = {
                    "flow_id": canonical_key,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": proto_name,
                    "start_time": iso_time,
                    "end_time": iso_time,
                    "packet_count": 1,
                    "byte_count": pkt_len,
                }
            else:
                f_entry = flows[canonical_key]
                f_entry["end_time"] = iso_time
                f_entry["packet_count"] += 1
                f_entry["byte_count"] += pkt_len

            # DNS Inspection
            if pkt.haslayer(DNS):
                dns_layer = pkt[DNS]
                qd = dns_layer.qd
                if dns_layer.qr == 0 and qd:  # Query
                    qname_raw = qd[0].qname if isinstance(qd, list) else qd.qname
                    qtype_code = qd[0].qtype if isinstance(qd, list) else qd.qtype
                    qname = qname_raw.decode(errors="ignore").rstrip(".")
                    qtype = dns_types.get(qtype_code, str(qtype_code))
                    dns_records.append(DNSRecord(
                        timestamp=iso_time,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        query_name=qname,
                        query_type=qtype,
                    ))
                elif dns_layer.qr == 1 and qd:  # Response
                    qname_raw = qd[0].qname if isinstance(qd, list) else qd.qname
                    qtype_code = qd[0].qtype if isinstance(qd, list) else qd.qtype
                    qname = qname_raw.decode(errors="ignore").rstrip(".")
                    qtype = dns_types.get(qtype_code, str(qtype_code))
                    answers = []
                    if dns_layer.an:
                        an_list = dns_layer.an if isinstance(dns_layer.an, list) else [dns_layer.an]
                        for rr in an_list:
                            if hasattr(rr, "rdata"):
                                rdata = rr.rdata
                                if isinstance(rdata, bytes):
                                    answers.append(rdata.decode(errors="ignore"))
                                else:
                                    answers.append(str(rdata))
                    dns_records.append(DNSRecord(
                        timestamp=iso_time,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        query_name=qname,
                        query_type=qtype,
                        response_code=str(dns_layer.rcode),
                        answers=answers,
                    ))

            # HTTP Inspection
            if TCP in pkt and (dst_port in (80, 8080, 8000) or src_port in (80, 8080, 8000)):
                payload = bytes(pkt[TCP].payload)
                if payload:
                    for verb in (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS ", b"DELETE "):
                        if payload.startswith(verb):
                            try:
                                lines = payload.split(b"\r\n")
                                req_line = lines[0].decode(errors="ignore")
                                parts = req_line.split(" ")
                                method = parts[0]
                                uri = parts[1] if len(parts) > 1 else "/"
                                host = ""
                                user_agent = None
                                for line in lines[1:]:
                                    line_str = line.decode(errors="ignore")
                                    if line_str.lower().startswith("host:"):
                                        host = line_str.split(":", 1)[1].strip()
                                    elif line_str.lower().startswith("user-agent:"):
                                        user_agent = line_str.split(":", 1)[1].strip()
                                http_records.append(HTTPRecord(
                                    timestamp=iso_time,
                                    src_ip=src_ip,
                                    src_port=src_port,
                                    dst_ip=dst_ip,
                                    dst_port=dst_port,
                                    method=method,
                                    host=host or dst_ip,
                                    uri=uri,
                                    user_agent=user_agent,
                                ))
                            except Exception:
                                pass
                            break

            # TLS Inspection (SNI Extraction)
            if TCP in pkt and (dst_port == 443 or src_port == 443 or dst_port in (8443, 4433)):
                payload = bytes(pkt[TCP].payload)
                if payload:
                    sni = _parse_tls_sni(payload)
                    if sni:
                        tls_records.append(TLSRecord(
                            timestamp=iso_time,
                            src_ip=src_ip,
                            src_port=src_port,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            server_name=sni,
                        ))

    return ExtractedMetadata(
        case_id=case_id,
        pcap_filename=pcap_path.name,
        extraction_source="pure_python_scapy",
        extracted_at=datetime.now(timezone.utc).isoformat(),
        connections=[ConnectionRecord(**data) for data in flows.values()],
        dns_queries=dns_records,
        http_requests=http_records,
        tls_handshakes=tls_records,
    )


def extract_metadata_tshark(pcap_path: Path, case_id: str) -> ExtractedMetadata:
    """Extract metadata using TShark CLI, falling back to Scapy on failure."""
    tshark_bin = shutil.which("tshark")
    if not tshark_bin:
        return extract_metadata_scapy(pcap_path, case_id)

    try:
        cmd = [
            tshark_bin,
            "-r", str(pcap_path),
            "-T", "json",
            "-e", "frame.time_epoch",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "tcp.srcport", "-e", "tcp.dstport",
            "-e", "udp.srcport", "-e", "udp.dstport",
            "-e", "dns.qry.name", "-e", "dns.qry.type", "-e", "dns.a",
            "-e", "http.request.method", "-e", "http.host", "-e", "http.request.uri", "-e", "http.user_agent",
            "-e", "tls.handshake.extensions_server_name",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
        packets = json.loads(proc.stdout)
        
        dns_records: List[DNSRecord] = []
        http_records: List[HTTPRecord] = []
        tls_records: List[TLSRecord] = []
        flows: Dict[str, Dict[str, Any]] = {}

        for pkt_entry in packets:
            layers = pkt_entry.get("_source", {}).get("layers", {})
            epoch_val = layers.get("frame.time_epoch", [0])
            ts_float = float(epoch_val[0]) if isinstance(epoch_val, list) and epoch_val else 0.0
            iso_time = _ts_to_iso(ts_float)

            src_ip = (layers.get("ip.src") or [""])[0]
            dst_ip = (layers.get("ip.dst") or [""])[0]
            if not src_ip or not dst_ip:
                continue

            tcp_sport = (layers.get("tcp.srcport") or ["0"])[0]
            tcp_dport = (layers.get("tcp.dstport") or ["0"])[0]
            udp_sport = (layers.get("udp.srcport") or ["0"])[0]
            udp_dport = (layers.get("udp.dstport") or ["0"])[0]

            proto = "TCP" if layers.get("tcp.srcport") else ("UDP" if layers.get("udp.srcport") else "IP")
            src_p = int(tcp_sport) if proto == "TCP" else (int(udp_sport) if proto == "UDP" else 0)
            dst_p = int(tcp_dport) if proto == "TCP" else (int(udp_dport) if proto == "UDP" else 0)

            flow_k = f"{src_ip}:{src_p}->{dst_ip}:{dst_p}/{proto}"
            if flow_k not in flows:
                flows[flow_k] = {
                    "flow_id": flow_k,
                    "src_ip": src_ip,
                    "src_port": src_p,
                    "dst_ip": dst_ip,
                    "dst_port": dst_p,
                    "protocol": proto,
                    "start_time": iso_time,
                    "end_time": iso_time,
                    "packet_count": 1,
                    "byte_count": 0,
                }
            else:
                flows[flow_k]["end_time"] = iso_time
                flows[flow_k]["packet_count"] += 1

            if "dns.qry.name" in layers:
                qname = layers["dns.qry.name"][0]
                qtype = layers.get("dns.qry.type", ["1"])[0]
                answers = layers.get("dns.a", [])
                dns_records.append(DNSRecord(
                    timestamp=iso_time,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    query_name=qname,
                    query_type=str(qtype),
                    answers=answers if isinstance(answers, list) else [answers],
                ))

            if "http.request.method" in layers:
                method = layers["http.request.method"][0]
                host = (layers.get("http.host") or [dst_ip])[0]
                uri = (layers.get("http.request.uri") or ["/"])[0]
                ua = (layers.get("http.user_agent") or [None])[0]
                http_records.append(HTTPRecord(
                    timestamp=iso_time,
                    src_ip=src_ip,
                    src_port=src_p,
                    dst_ip=dst_ip,
                    dst_port=dst_p,
                    method=method,
                    host=host,
                    uri=uri,
                    user_agent=ua,
                ))

            if "tls.handshake.extensions_server_name" in layers:
                sni = layers["tls.handshake.extensions_server_name"][0]
                tls_records.append(TLSRecord(
                    timestamp=iso_time,
                    src_ip=src_ip,
                    src_port=src_p,
                    dst_ip=dst_ip,
                    dst_port=dst_p,
                    server_name=sni,
                ))

        return ExtractedMetadata(
            case_id=case_id,
            pcap_filename=pcap_path.name,
            extraction_source="tshark",
            extracted_at=datetime.now(timezone.utc).isoformat(),
            connections=[ConnectionRecord(**d) for d in flows.values()],
            dns_queries=dns_records,
            http_requests=http_records,
            tls_handshakes=tls_records,
        )
    except Exception:
        return extract_metadata_scapy(pcap_path, case_id)


def extract_metadata(
    pcap_path: str | Path,
    case_id: str,
    output_dir: Optional[str | Path] = None,
    prefer_tshark: bool = True,
) -> ExtractedMetadata:
    """Execute complete metadata extraction workflow and save results."""
    path = Path(pcap_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"PCAP capture not found: {path}")

    if prefer_tshark and shutil.which("tshark"):
        metadata = extract_metadata_tshark(path, case_id)
    else:
        metadata = extract_metadata_scapy(path, case_id)

    if output_dir:
        out = Path(output_dir).resolve()
        out.mkdir(parents=True, exist_ok=True)
        meta_file = out / "metadata.json"
        with open(meta_file, "w", encoding="utf-8") as f:
            f.write(metadata.model_dump_json(indent=2))

    return metadata
