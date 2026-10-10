# NetTrace: Network Threat Hunting & Malware Traffic Investigation

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **Portfolio Title**: Network Threat Hunting and Malware Traffic Investigation Using Wireshark, Zeek, and Suricata  
> **Target Roles**: SOC Analyst, Network Security Analyst, Incident Response Specialist, Junior Threat Hunter.

---

## 1. Project Purpose & Investigative Philosophy

`NetTrace` provides a rigorous, repeatable, evidence-grounded workflow for investigating suspicious network traffic using packet captures (PCAPs). 

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
                    │   Detection & Analysis    │
                    │   • Suricata Offline IDS  │
                    │   • Custom Rule Validation│
                    │   • Beaconing & Anomalies │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │      SOC Investigation    │
                    │   • Unified UTC Timeline  │
                    │   • Extracted IOC Schema  │
                    │   • MITRE ATT&CK Mapping  │
                    │   • Incident Report (.md) │
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
- Optional: `tshark`, `zeek`, `suricata` installed on the host system

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

### Running Unit Tests
```bash
pytest -v
```

---

## 5. Usage Example: Day 1 Case Intake

```bash
# Ingest and verify a PCAP capture
nettrace intake /path/to/capture.pcap \
  --case-id "PCAP-2026-001" \
  --source-url "https://www.malware-traffic-analysis.net/sample.html" \
  --pub-date "2026-10-10" \
  --notes "Suspected initial access loader beaconing via HTTPS." \
  --output-dir cases/example-case/
```

Generated `case-metadata.json`:
```json
{
  "case_id": "PCAP-2026-001",
  "pcap_filename": "capture.pcap",
  "pcap_path": "/path/to/capture.pcap",
  "dataset_source_url": "https://www.malware-traffic-analysis.net/sample.html",
  "publication_date": "2026-10-10",
  "file_size_bytes": 1048576,
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "magic_type": "pcap (microsecond, identical byte order)",
  "analysis_start_time": "2026-10-10T06:00:00+00:00",
  "analyst_notes": "Suspected initial access loader beaconing via HTTPS.",
  "file_preserved": true
}
```

---

## 6. Implementation Roadmap

- [x] **Day 1**: Case Intake, Header Validation, and Cryptographic Integrity Verification.
- [ ] **Day 2**: Connection, DNS, HTTP, and TLS Metadata Extraction Subsystem.
- [ ] **Day 3**: Structured IOC Parsing, Defanging, and Schema Validation.
- [ ] **Day 4**: Suricata Offline Analysis & Custom Detection Rules.
- [ ] **Day 5**: Cross-Source Chronological Event Timeline Generation.
- [ ] **Day 6**: MITRE ATT&CK Mapping & Incident Report Generation.
- [ ] **Day 7**: End-to-End Case Investigation & Final Release Documentation.
