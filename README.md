# NetTrace: Network Threat Hunting & Malware Traffic Investigation

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **Portfolio Title**: Network Threat Hunting and Malware Traffic Investigation Using Wireshark, Zeek, and Suricata  
> **Target Roles**: SOC Analyst, Network Security Analyst, Incident Response Specialist, Junior Threat Hunter.

---

## 1. Project Purpose & Investigative Philosophy

`NetTrace` provides a repeatable, evidence-grounded workflow for investigating suspicious network traffic using packet captures (PCAPs). 

In modern Security Operations Center (SOC) environments, analyzing suspicious traffic is not just about isolating an arbitrary IP address. It requires answering operational questions with demonstrable forensic integrity:
- **What was the likely initial infection vector?**
- **Which internal endpoints and remote hosts were involved?**
- **Did the compromised host communicate with suspected Command and Control (C2) infrastructure?**
- **What indicators of compromise (IOCs) can be reliably extracted?**
- **Which hypotheses are confirmed by network evidence, and what requires additional endpoint telemetry?**

### Defensive Safety Principles
- **Strictly Offline Analysis**: No live payloads or suspicious connections are executed or resolved against active infrastructure.
- **Evidence Immutability**: Source captures are hashed, validated via binary header inspection, and treated as immutable forensic artifacts.
- **Explainable Attribution**: Clear distinction between *Confirmed*, *Probable*, *Possible*, and *Inconclusive* malware attributions.
- **Indicator Defanging**: All candidate IPs, domains, and URLs are defanged (`1.1.1[.]1`, `evil[.]com`, `hxxp://...`) to prevent accidental execution or automated preview resolution when sharing forensic findings.
- **Normalized UTC Timelines**: All timestamps across disparate network layers (DNS, flows, HTTP, TLS, IDS alerts) are normalized to ISO-8601 UTC to eliminate timezone ambiguity during incident correlation.
- **Encrypted Traffic Realism**: HTTPS/TLS encryption prevents passive packet captures from revealing application payloads; extraction is transparently constrained to handshake metadata (SNI, endpoints, ciphers).

---

## 2. Architecture & Pipeline

```
          Public PCAP Dataset (e.g. Malware-Traffic-Analysis.net)
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │  Case Intake & Integrity  │
                    │   • Header / Magic Check  │
                    │   • SHA-256 Verification  │
                    │   • Provenance Metadata   │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │     Metadata Extraction   │
                    │   • L4 5-Tuple Flows      │
                    │   • DNS Queries & Records │
                    │   • HTTP Methods & URIs   │
                    │   • TLS Handshakes & SNI  │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │  Structured IOC Pipeline  │
                    │   • Candidate Extraction  │
                    │   • Defanging & Typing    │
                    │   • Internal/External L3  │
                    │   • JSON / CSV Exports    │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │   Detection & Analysis    │
                    │   • Suricata Offline IDS  │
                    │   • Custom Rule Signatures│
                    │   • Beaconing & Anomalies │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │    Timeline Correlation   │
                    │   • Unified UTC Events    │
                    │   • DNS -> Flow -> L7/TLS │
                    │   • CSV & Markdown Tables │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │   SOC Incident Reporting  │
                    │   • ATT&CK Mapping        │
                    │   • Malware Assessment    │
                    │   • Containment Playbook  │
                    │   • Markdown Report (.md) │
                    └───────────────────────────┘
```

---

## 3. Technology Stack

| Technology | Purpose |
|---|---|
| **Python 3.10+** | Forensic data pipeline, ingestion, schema validation, timeline correlation, and reporting |
| **Wireshark / TShark** | Interactive deep packet inspection and command-line protocol dissection |
| **Zeek** | High-level connection, DNS, HTTP, and SSL protocol transaction logging |
| **Suricata** | Offline signature-based intrusion detection engine (`eve.json` alerting) |
| **MITRE ATT&CK** | Adversary tactic and technique mapping |
| **Pydantic** | Strict schema validation for case metadata, findings, and IOCs |

---

## 4. Getting Started

### Prerequisites
- Python 3.10 or higher
- Optional: `tshark`, `zeek`, `suricata` installed on host system

### Installation
```bash
git clone https://github.com/ayus1n9/NetTrace.git
cd NetTrace

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -e .
```

### Running Automated Tests
```bash
pytest -v --cov=pcap_analyzer
```

---

## 5. Usage Workflows

### Complete End-to-End Investigation Workflow
Generate the full SOC incident report, IOC tables, timeline, and structured findings in a single command:
```bash
nettrace report /path/to/capture.pcap \
  --case-id "PCAP-2026-001" \
  --output-dir cases/example-case/
```

This single command triggers the entire pipeline:
1. **Intake & Verification**: Records SHA-256 and validates binary capture header.
2. **Metadata Extraction**: Dissects L4 5-tuples, DNS queries, HTTP verbs/URIs, and TLS SNI hostnames.
3. **IOC Extraction**: Extracts and defangs candidate IPs, domains, and URLs.
4. **Behavioral Detection**: Evaluates Suricata rules and calculates beaconing intervals.
5. **Timeline Correlation**: Merges all events into chronological UTC sequence.
6. **Incident Report Generation**: Formats an executive and technical markdown report (`incident-report.md`) complete with MITRE ATT&CK mapping, malware family assessment, and containment actions.

---

## 6. Implementation Roadmap

- [x] **Day 1**: Case Intake, Header Validation, and Cryptographic Integrity Verification. (`v0.1.0`)
- [x] **Day 2**: Connection, DNS, HTTP, and TLS Metadata Extraction Subsystem. (`v0.2.0`)
- [x] **Day 3**: Structured IOC Parsing, Defanging, and Schema Validation. (`v0.3.0`)
- [x] **Day 4**: Suricata Offline Detection, Custom Rule Evaluation & Behavioral Analysis. (`v0.4.0`)
- [x] **Day 5**: Cross-Source Chronological Event Timeline Generation. (`v0.5.0`)
- [x] **Day 6**: MITRE ATT&CK Mapping & Incident Report Generation. (`v0.6.0`)
- [ ] **Day 7**: End-to-End Case Investigation & Final Release Documentation.
