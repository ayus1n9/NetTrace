# NetTrace Technical Limitations & Defensive Caveats

Forensic integrity requires transparently communicating analytical boundaries. This document outlines the technical limitations of passive network packet analysis and the constraints of this toolkit.

---

## 1. Encrypted Traffic (HTTPS / TLS)

Modern malware traffic heavily utilizes TLS 1.2 and TLS 1.3 encryption.
- **What is Observable**: L4 endpoints (IP, port), connection timing/duration, packet size metrics, unencrypted TLS ClientHello metadata (Server Name Indication / SNI, cipher suites), and unencrypted certificate exchanges (in TLS 1.2 or cleartext handshakes).
- **What is NOT Observable**: Full HTTP URIs, request headers, POST bodies, downloaded binary payloads, or response data transmitted inside encrypted sessions.
- **Forensic Principle**: Never claim to have inspected or extracted payload contents from an encrypted session unless session keys (e.g. `SSLKEYLOGFILE`) were provided.

---

## 2. Lack of Endpoint Telemetry

Network traffic alone captures wire activity, but cannot independently verify host execution:
- **Ingress Tool Transfer (`T1105`)**: Observing an HTTP `.exe` download in network packets confirms transit across the wire, but does not prove the file was saved to disk or executed.
- **Required Host Telemetry**: Endpoint detection (EDR / Sysmon Event ID 11 for file creation, Event ID 1 for process creation, Event ID 7 for image load) is necessary to confirm infection.

---

## 3. Dynamic Cloud Infrastructure & False Indicators

- **Shared CDNs / Cloud Services**: Legitimate services and malware often share major cloud IP space (Cloudflare, AWS CloudFront, Azure, Google Cloud). Blocking an IP address without domain context can cause operational outages.
- **Dynamic DNS**: High-turnover domains frequently rotate IP mappings. Threat indicators must be tagged with observation timestamps.

---

## 4. Environment & Binary Dependencies

- If system binaries (`tshark`, `suricata`, `zeek`) are not installed on the host, `NetTrace` automatically degrades to its built-in pure-Python Scapy dissection engine and fallback rule evaluator. While functional offline, full protocol breadth (such as specialized industrial or proprietary protocol dissection) requires external tool suites.
