# NetTrace Investigative Methodology & Chain of Custody

This document establishes the operational workflow and forensic standards implemented in `NetTrace` for analyzing suspicious packet captures (PCAPs).

---

## 1. Forensic Integrity & Defensive Safety

When investigating suspect network captures, defensive analysts operate under strict protocols:
- **Offline Dissection**: Never replay packets, connect to resolved external IPs, or query remote hostnames via live recursive DNS resolvers. All parsing and extraction occurs within an isolated, offline environment.
- **Evidence Immutability**: The target capture is inspected in binary read-only mode (`rb`). SHA-256 hashes are calculated upon intake and recorded in provenance metadata.
- **Defanging Standards**: All candidate indicators (IP addresses, domain names, URLs) are defanged (`1.1.1[.]1`, `evil-c2[.]net`, `hxxp://...`) before being displayed or written to reports to prevent inadvertent connection attempts.

---

## 2. Multi-Stage Investigation Workflow

```
   ┌────────────────────────────────────────────────────────┐
   │ 1. INTAKE & INTEGRITY                                  │
   │    • Magic byte validation (libpcap, pcapng)           │
   │    • SHA-256 calculation & provenance recording        │
   └───────────────────────────┬────────────────────────────┘
                               │
                               ▼
   ┌────────────────────────────────────────────────────────┐
   │ 2. PROTOCOL EXTRACTION                                 │
   │    • 5-tuple canonical flow tracking                   │
   │    • DNS transaction extraction (Queries & Answers)    │
   │    • Cleartext HTTP request header dissection          │
   │    • TLS ClientHello SNI extraction                    │
   └───────────────────────────┬────────────────────────────┘
                               │
                               ▼
   ┌────────────────────────────────────────────────────────┐
   │ 3. STRUCTURED IOC PIPELINE                             │
   │    • RFC 1918 internal vs external endpoint scoping    │
   │    • Extraction of IPs, domains, URLs, hashes          │
   │    • JSON Schema and CSV table generation              │
   └───────────────────────────┬────────────────────────────┘
                               │
                               ▼
   ┌────────────────────────────────────────────────────────┐
   │ 4. DETECTION & BEHAVIORAL ANALYSIS                     │
   │    • Suricata signature evaluation (`custom.rules`)    │
   │    • Beaconing periodicity (inter-arrival variance)    │
   │    • Outbound non-standard high port egress checks     │
   └───────────────────────────┬────────────────────────────┘
                               │
                               ▼
   ┌────────────────────────────────────────────────────────┐
   │ 5. TIMELINE & REPORTING                                │
   │    • ISO-8601 UTC chronological normalization          │
   │    • MITRE ATT&CK Enterprise matrix alignment          │
   │    • Evidence-backed malware family assessment         │
   │    • Executive & technical incident report (.md)       │
   └────────────────────────────────────────────────────────┘
```

---

## 3. Tool Contribution Matrix

Rather than forcing every tool into every investigation, each tool contributes specific high-fidelity data:

| Technology | Specific Contribution |
|---|---|
| **Wireshark / TShark** | Interactive deep packet inspection and command-line protocol dissection |
| **Zeek** | High-level transaction logs (connections, DNS, HTTP, SSL) |
| **Suricata** | Offline signature detection against `eve.json` alerts |
| **Python Core Pipeline** | Standardized ingestion, schema validation, statistical beaconing detection, timeline correlation, and markdown generation |

---

## 4. What This Demonstrates to a SOC Hiring Manager

1. **Forensic Chain of Custody**: Proves that you understand evidence preservation, cryptographic hashing, and immutability standards.
2. **Defensive Discretion**: Distinguishes between internal corporate endpoints and external infrastructure. Does not mistake CDN IPs for C2 nodes without corroborating evidence.
3. **Realistic Attribution**: Refuses to guess a malware family without sufficient evidence; clearly articulates what endpoint logs (Sysmon, EDR, memory) are required to confirm hypotheses.
4. **Repeatable Automation**: Replaces ad-hoc, error-prone manual bash one-liners with a typed, tested, and modular Python toolkit.
