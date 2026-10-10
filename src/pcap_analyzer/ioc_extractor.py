"""Structured IOC Extraction, Normalization, Defanging, and Validation Module.

Extracts candidate IPv4/IPv6 addresses, domains, URIs, and observed file hashes
from network metadata. Defangs indicators for safe transmission, discriminates
benign internal/reserved ranges from external candidates, and exports to structured
JSON and CSV formats complying with case schemas.
"""

from __future__ import annotations

import csv
import ipaddress
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field

from pcap_analyzer.extraction import ExtractedMetadata
from pcap_analyzer.intake import CaseMetadata


def is_rfc1918_or_internal(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Identify strictly internal corporate network IP ranges (RFC 1918, Loopback, Link-Local).

    Leaves documentation / lab ranges (e.g. 198.51.100.0/24, 203.0.113.0/24) or public IPs
    marked as external so threat hunting targets are accurately categorized.
    """
    if ip_obj.is_loopback or ip_obj.is_link_local:
        return True
    if ip_obj.version == 4:
        # Check standard RFC 1918 private subnets: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        rfc1918_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        return any(ip_obj in net for net in rfc1918_networks)
    return ip_obj.is_private


def defang_ip(ip: str) -> str:
    """Defang an IP address for safe text sharing (e.g., 1.1.1.1 -> 1.1.1[.]1)."""
    if ":" in ip:  # IPv6
        return ip.replace("::", "[:]:")
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}[.]{parts[3]}"
    return ip.replace(".", "[.]")


def defang_domain(domain: str) -> str:
    """Defang a domain name (e.g., malicious.com -> malicious[.]com)."""
    return re.sub(r"\.([a-zA-Z0-9_-]+)$", r"[.]\1", domain)


def defang_url(url: str) -> str:
    """Defang a URL protocol and host (e.g., http://evil.com/a -> hxxp://evil[.]com/a)."""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    parts = defanged.split("/", 3)
    if len(parts) >= 3:
        host = parts[2]
        defanged_host = host.replace(".", "[.]")
        parts[2] = defanged_host
        return "/".join(parts)
    return defanged.replace(".", "[.]")


class IPIndicator(BaseModel):
    """Normalized IP indicator."""
    value: str
    defanged: str
    ip_version: int
    is_private: bool
    sources: List[str] = Field(default_factory=list)
    relevance_notes: str = ""


class DomainIndicator(BaseModel):
    """Normalized domain indicator."""
    value: str
    defanged: str
    sources: List[str] = Field(default_factory=list)
    resolved_ips: List[str] = Field(default_factory=list)
    relevance_notes: str = ""


class URLIndicator(BaseModel):
    """Normalized URL indicator."""
    value: str
    defanged: str
    host: str
    uri: str
    method: str = "GET"
    user_agent: Optional[str] = None


class FileHashIndicator(BaseModel):
    """Extracted file hash artifact indicator."""
    hash_type: str
    value: str
    source_file: str


class ExtractedIOCs(BaseModel):
    """Collection of candidate indicators."""
    ips: List[IPIndicator] = Field(default_factory=list)
    domains: List[DomainIndicator] = Field(default_factory=list)
    urls: List[URLIndicator] = Field(default_factory=list)
    file_hashes: List[FileHashIndicator] = Field(default_factory=list)


class CaseIOCReport(BaseModel):
    """Top-level investigation IOC report matching case-report.schema.json."""
    case_id: str
    source_file: str
    sha256: str
    indicators: ExtractedIOCs
    analysis_status: str = "completed"


def extract_iocs(metadata: ExtractedMetadata, case_meta: CaseMetadata) -> CaseIOCReport:
    """Extract, normalize, deduplicate, and defang IOCs from network metadata."""
    ip_map: Dict[str, Dict[str, Any]] = {}
    domain_map: Dict[str, Dict[str, Any]] = {}
    url_map: Dict[str, Dict[str, Any]] = {}
    hash_list: List[FileHashIndicator] = []

    # 1. Connections
    for conn in metadata.connections:
        for ip_addr, role in ((conn.src_ip, "flow_src"), (conn.dst_ip, "flow_dst")):
            if not ip_addr:
                continue
            if ip_addr not in ip_map:
                try:
                    obj = ipaddress.ip_address(ip_addr)
                    is_priv = is_rfc1918_or_internal(obj)
                    ip_ver = obj.version
                except ValueError:
                    continue

                ip_map[ip_addr] = {
                    "value": ip_addr,
                    "defanged": defang_ip(ip_addr),
                    "ip_version": ip_ver,
                    "is_private": is_priv,
                    "sources": {role},
                    "relevance_notes": "Internal host endpoint" if is_priv else "External remote endpoint",
                }
            else:
                ip_map[ip_addr]["sources"].add(role)

    # 2. DNS
    for dns_rec in metadata.dns_queries:
        dname = dns_rec.query_name.lower()
        if dname and not dname.endswith(".local") and not dname.endswith(".arpa"):
            if dname not in domain_map:
                domain_map[dname] = {
                    "value": dname,
                    "defanged": defang_domain(dname),
                    "sources": {"dns_query"},
                    "resolved_ips": set(dns_rec.answers),
                    "relevance_notes": "Queried domain candidate",
                }
            else:
                domain_map[dname]["sources"].add("dns_query")
                domain_map[dname]["resolved_ips"].update(dns_rec.answers)

        for ans in dns_rec.answers:
            try:
                obj = ipaddress.ip_address(ans)
                is_priv = is_rfc1918_or_internal(obj)
                if ans not in ip_map:
                    ip_map[ans] = {
                        "value": ans,
                        "defanged": defang_ip(ans),
                        "ip_version": obj.version,
                        "is_private": is_priv,
                        "sources": {"dns_resolution"},
                        "relevance_notes": f"DNS resolution target for {dname}",
                    }
                else:
                    ip_map[ans]["sources"].add("dns_resolution")
            except ValueError:
                pass

    # 3. TLS Handshakes
    for tls_rec in metadata.tls_handshakes:
        if tls_rec.server_name:
            sname = tls_rec.server_name.lower()
            if sname not in domain_map:
                domain_map[sname] = {
                    "value": sname,
                    "defanged": defang_domain(sname),
                    "sources": {"tls_sni"},
                    "resolved_ips": set(),
                    "relevance_notes": f"Observed TLS SNI connection to {tls_rec.dst_ip}:{tls_rec.dst_port}",
                }
            else:
                domain_map[sname]["sources"].add("tls_sni")

    # 4. HTTP
    for http_rec in metadata.http_requests:
        host = http_rec.host.lower()
        if host and not host.endswith(".local"):
            if host not in domain_map:
                domain_map[host] = {
                    "value": host,
                    "defanged": defang_domain(host),
                    "sources": {"http_host"},
                    "resolved_ips": set(),
                    "relevance_notes": "Observed cleartext HTTP host header",
                }
            else:
                domain_map[host]["sources"].add("http_host")

        url_str = f"http://{http_rec.host}{http_rec.uri}"
        if url_str not in url_map:
            url_map[url_str] = {
                "value": url_str,
                "defanged": defang_url(url_str),
                "host": http_rec.host,
                "uri": http_rec.uri,
                "method": http_rec.method,
                "user_agent": http_rec.user_agent,
            }

    ip_indicators = [
        IPIndicator(
            value=d["value"],
            defanged=d["defanged"],
            ip_version=d["ip_version"],
            is_private=d["is_private"],
            sources=sorted(list(d["sources"])),
            relevance_notes=d["relevance_notes"],
        )
        for d in ip_map.values()
    ]

    domain_indicators = [
        DomainIndicator(
            value=d["value"],
            defanged=d["defanged"],
            sources=sorted(list(d["sources"])),
            resolved_ips=sorted(list(d["resolved_ips"])),
            relevance_notes=d["relevance_notes"],
        )
        for d in domain_map.values()
    ]

    url_indicators = [URLIndicator(**d) for d in url_map.values()]

    return CaseIOCReport(
        case_id=case_meta.case_id,
        source_file=case_meta.pcap_filename,
        sha256=case_meta.sha256,
        indicators=ExtractedIOCs(
            ips=ip_indicators,
            domains=domain_indicators,
            urls=url_indicators,
            file_hashes=hash_list,
        ),
        analysis_status="completed",
    )


def export_iocs_to_json(report: CaseIOCReport, output_file: Path) -> None:
    """Save IOC report to structured JSON conforming to schema."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report.model_dump_json(indent=2))


def export_iocs_to_csv(report: CaseIOCReport, output_file: Path) -> None:
    """Export normalized indicators to CSV table for ingestion into SIEM/threat platforms."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Indicator_Type", "Value", "Defanged", "Sources", "Relevance_Notes"])

        for ip in report.indicators.ips:
            writer.writerow(["IP", ip.value, ip.defanged, ";".join(ip.sources), ip.relevance_notes])

        for dom in report.indicators.domains:
            writer.writerow(["Domain", dom.value, dom.defanged, ";".join(dom.sources), dom.relevance_notes])

        for url in report.indicators.urls:
            writer.writerow(["URL", url.value, url.defanged, f"Method:{url.method}", f"User-Agent:{url.user_agent or 'N/A'}"])

        for h in report.indicators.file_hashes:
            writer.writerow(["FileHash", h.value, h.value, h.hash_type, h.source_file])
