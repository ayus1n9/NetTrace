# Forensic Investigation & Network Incident Report

**Case Identifier**: `PCAP-2026-MAL-001`  
**Target PCAP**: `demo_investigation.pcap`  
**Capture SHA-256**: `070cf0f6e9a95094007826f2e0effbf3e0d652f28df534d71dfbc8eb5fb5ae38`  
**Analysis Timestamp**: `2026-10-10T06:31:31.877617+00:00`  
**Dataset Source**: Offline Capture Artifact  
**Status**: `Completed`  

---

## 1. Executive Summary

A network traffic investigation was performed on packet capture `demo_investigation.pcap` to reconstruct adversary activity, identify compromised host endpoints, extract indicators of compromise (IOCs), and evaluate threats to the enterprise environment.

The investigation identified **2 internal host(s)** (`10.0.0.1, 10.0.0.45`) interacting with external infrastructure across **5 connection flow(s)**. Suspicious activity was detected including **0 signature alert(s)** and **5 behavioral anomaly finding(s)**.

- **Malware Family Assessment**: **Probable** (`Multi-Stage Loader / C2 Agent`)
- **Assessed Impact**: Potential host compromise with staged executable delivery and subsequent Command-and-Control (C2) communication attempts.
- **Immediate Action**: Host isolation and endpoint memory/process triage recommended.

---

## 2. Case Scope & Forensic Provenance

- **Forensic Capture**: `demo_investigation.pcap`
- **Original File Size**: `880` bytes
- **SHA-256 Digest**: `070cf0f6e9a95094007826f2e0effbf3e0d652f28df534d71dfbc8eb5fb5ae38`
- **Format Verification**: `pcap (microsecond, identical byte order)` (Validated via binary magic header inspection)
- **Evidence Immutability**: Confirmed. Source capture was preserved read-only throughout all extraction stages.

---

## 3. Investigation Methodology

Analysis followed a structured, repeatable SOC defensive methodology:
1. **Intake & Verification**: Capture format verification, checksum verification, and provenance documentation.
2. **Metadata Dissection**: 5-tuple flow aggregation, DNS resolution mapping, cleartext HTTP inspection, and TLS ClientHello SNI parsing.
3. **Detection Engine Evaluation**: Offline Suricata signature evaluation (`custom.rules`) and mathematical beaconing interval analysis.
4. **Adversary Technique Mapping**: Aligning network evidence to the MITRE ATT&CK matrix.
5. **Report & Containment Formulation**: Evidence-grounded remediation recommendations.

---

## 4. Affected Hosts & Network Endpoints

### Internal Affected Endpoints
| IP Address | Role / Observation | Defanged |
|---|---|---|
| `10.0.0.1` | Suspected compromised internal client | `10[.]0[.]0[.]1` |
| `10.0.0.45` | Suspected compromised internal client | `10[.]0[.]0[.]45` |

### External Infrastructure Interacted With
| IP / Endpoint | Association | Status |
|---|---|---|
| `198.51.100.44` | Remote communication endpoint | External Candidate |
| `203.0.113.88` | Remote communication endpoint | External Candidate |

---

## 5. Key Observations & Findings

Total Findings: **5**

### [FIND-001] GET request for binary file '/update_agent.exe' to host 'update-portal-cdn.xyz'
- **Evidence Source**: `HTTP Log / Rule SID 1000001`
- **Timestamp (UTC)**: `2026-10-10T06:31:31.873157+00:00`
- **Source**: `10.0.0.45:49200` ➔ **Destination**: `198.51.100.44:80`
- **Why Suspicious**: Adversaries frequently deliver second-stage implants, drop-executables, or tools via direct unencrypted HTTP requests.
- **Alternative Benign Explanation**: Legitimate legacy software update or internal administrative installer fetch over HTTP.
- **Confidence Level**: `High`
- **Recommended Follow-up**: Investigate endpoint process creation logs (Sysmon EID 1) around timestamp; acquire downloaded file if available to compute hash.

### [FIND-002] DNS query for 'update-portal-cdn.xyz' resolving to []
- **Evidence Source**: `DNS Log / Rule SID 1000002`
- **Timestamp (UTC)**: `2026-10-10T06:31:31.872486+00:00`
- **Source**: `10.0.0.45` ➔ **Destination**: `10.0.0.1:53`
- **Why Suspicious**: High-abuse TLDs and dynamic DNS domains are commonly registered by threat actors for short-lived C2 infrastructure.
- **Alternative Benign Explanation**: Benign web navigation to a legitimate business website utilizing non-standard TLDs.
- **Confidence Level**: `Medium`
- **Recommended Follow-up**: Check passive DNS history for domain; query endpoint proxy/web browsing logs for referer URL.

### [FIND-003] DNS query for 'update-portal-cdn.xyz' resolving to ['198.51.100.44']
- **Evidence Source**: `DNS Log / Rule SID 1000002`
- **Timestamp (UTC)**: `2026-10-10T06:31:31.872839+00:00`
- **Source**: `10.0.0.1` ➔ **Destination**: `10.0.0.45:53`
- **Why Suspicious**: High-abuse TLDs and dynamic DNS domains are commonly registered by threat actors for short-lived C2 infrastructure.
- **Alternative Benign Explanation**: Benign web navigation to a legitimate business website utilizing non-standard TLDs.
- **Confidence Level**: `Medium`
- **Recommended Follow-up**: Check passive DNS history for domain; query endpoint proxy/web browsing logs for referer URL.

### [FIND-004] TLS ClientHello SNI header requesting server name 'beacon-c2.net'
- **Evidence Source**: `TLS Handshake / Rule SID 1000004`
- **Timestamp (UTC)**: `2026-10-10T06:31:31.873784+00:00`
- **Source**: `10.0.0.45:49201` ➔ **Destination**: `203.0.113.88:443`
- **Why Suspicious**: Observed TLS SNI matches suspected command-and-control server naming patterns.
- **Alternative Benign Explanation**: Coincidental naming in internal testing or legitimate telemetry service.
- **Confidence Level**: `High`
- **Recommended Follow-up**: Inspect active network connections and memory artifacts of the source host for injected beacon threads.

### [FIND-005] TLS ClientHello SNI header requesting server name 'beacon-c2.net'
- **Evidence Source**: `TLS Handshake / Rule SID 1000004`
- **Timestamp (UTC)**: `2026-10-10T06:31:31.873954+00:00`
- **Source**: `10.0.0.45:49202` ➔ **Destination**: `203.0.113.88:443`
- **Why Suspicious**: Observed TLS SNI matches suspected command-and-control server naming patterns.
- **Alternative Benign Explanation**: Coincidental naming in internal testing or legitimate telemetry service.
- **Confidence Level**: `High`
- **Recommended Follow-up**: Inspect active network connections and memory artifacts of the source host for injected beacon threads.

---

## 6. Chronological Investigation Timeline

| Timestamp (UTC) | Event | Source | Destination | Summary | Interpretation |
|---|---|---|---|---|---|
| `2026-10-10T06:31:31.872486+00:00` | **DNS Query** | `10.0.0.45` | `10.0.0.1:53` | Lookup for 'update-portal-cdn.xyz' (Type A) | Host initiated domain name lookup for 'update-portal-cdn.xyz'. |
| `2026-10-10T06:31:31.872486+00:00` | **Outbound Connection** | `10.0.0.45:53210` | `10.0.0.1:53` | L4 UDP connection (2 packets, 171 bytes) | Host established network transport session to 10.0.0.1:53. |
| `2026-10-10T06:31:31.872486+00:00` | **Detection Alert** | `10.0.0.45` | `10.0.0.1:53` | DNS query for 'update-portal-cdn.xyz' resolving to [] | Matched detection rule 1000002: High-abuse TLDs and dynamic DNS domains are commonly registered by threat actors... |
| `2026-10-10T06:31:31.872839+00:00` | **DNS Response** | `10.0.0.45` | `10.0.0.1` | Resolved 'update-portal-cdn.xyz' (A) -> 198.51.100.44 | Host resolved domain 'update-portal-cdn.xyz' prior to potential connection. |
| `2026-10-10T06:31:31.872839+00:00` | **Detection Alert** | `10.0.0.1` | `10.0.0.45:53` | DNS query for 'update-portal-cdn.xyz' resolving to ['198.51.100.44'] | Matched detection rule 1000002: High-abuse TLDs and dynamic DNS domains are commonly registered by threat actors... |
| `2026-10-10T06:31:31.873157+00:00` | **Outbound Connection** | `10.0.0.45:49200` | `198.51.100.44:80` | L4 TCP connection (1 packets, 174 bytes) | Host established network transport session to 198.51.100.44:80. |
| `2026-10-10T06:31:31.873157+00:00` | **HTTP Request** | `10.0.0.45:49200` | `198.51.100.44:80` | GET /update_agent.exe (Host: update-portal-cdn.xyz) | Application-layer cleartext request to 'update-portal-cdn.xyz/update_agent.exe'. |
| `2026-10-10T06:31:31.873157+00:00` | **Detection Alert** | `10.0.0.45:49200` | `198.51.100.44:80` | GET request for binary file '/update_agent.exe' to host 'update-portal-cdn.xyz' | Matched detection rule 1000001: Adversaries frequently deliver second-stage implants, drop-executables, or tools... |
| `2026-10-10T06:31:31.873371+00:00` | **DNS Query** | `10.0.0.45` | `10.0.0.1:53` | Lookup for 'c2-beacon-service.net' (Type A) | Host initiated domain name lookup for 'c2-beacon-service.net'. |
| `2026-10-10T06:31:31.873371+00:00` | **Outbound Connection** | `10.0.0.45:53211` | `10.0.0.1:53` | L4 UDP connection (2 packets, 171 bytes) | Host established network transport session to 10.0.0.1:53. |
| `2026-10-10T06:31:31.873563+00:00` | **DNS Response** | `10.0.0.45` | `10.0.0.1` | Resolved 'c2-beacon-service.net' (A) -> 203.0.113.88 | Host resolved domain 'c2-beacon-service.net' prior to potential connection. |
| `2026-10-10T06:31:31.873784+00:00` | **Outbound Connection** | `10.0.0.45:49201` | `203.0.113.88:443` | L4 TCP connection (1 packets, 114 bytes) | Host established network transport session to 203.0.113.88:443. |
| `2026-10-10T06:31:31.873784+00:00` | **TLS Handshake** | `10.0.0.45:49201` | `203.0.113.88:443` | ClientHello to SNI: beacon-c2.net | Host initiated TLS encrypted tunnel negotiating server name 'beacon-c2.net'. |
| `2026-10-10T06:31:31.873784+00:00` | **Detection Alert** | `10.0.0.45:49201` | `203.0.113.88:443` | TLS ClientHello SNI header requesting server name 'beacon-c2.net' | Matched detection rule 1000004: Observed TLS SNI matches suspected command-and-control server naming patterns.... |
| `2026-10-10T06:31:31.873954+00:00` | **Outbound Connection** | `10.0.0.45:49202` | `203.0.113.88:443` | L4 TCP connection (1 packets, 114 bytes) | Host established network transport session to 203.0.113.88:443. |
| `2026-10-10T06:31:31.873954+00:00` | **TLS Handshake** | `10.0.0.45:49202` | `203.0.113.88:443` | ClientHello to SNI: beacon-c2.net | Host initiated TLS encrypted tunnel negotiating server name 'beacon-c2.net'. |
| `2026-10-10T06:31:31.873954+00:00` | **Detection Alert** | `10.0.0.45:49202` | `203.0.113.88:443` | TLS ClientHello SNI header requesting server name 'beacon-c2.net' | Matched detection rule 1000004: Observed TLS SNI matches suspected command-and-control server naming patterns.... |

---

## 7. Extracted Indicators of Compromise (IOCs)

### Candidate IP Addresses
| IP Address | Defanged | Scope | Observed Sources |
|---|---|---|---|
| `10.0.0.45` | `10.0.0[.]45` | Internal | flow_src |
| `10.0.0.1` | `10.0.0[.]1` | Internal | flow_dst |
| `198.51.100.44` | `198.51.100[.]44` | External | dns_resolution, flow_dst |
| `203.0.113.88` | `203.0.113[.]88` | External | dns_resolution, flow_dst |

### Candidate Domains & Hostnames
| Domain | Defanged | Sources | Resolved IPs |
|---|---|---|---|
| `update-portal-cdn.xyz` | `update-portal-cdn[.]xyz` | dns_query, http_host | `198.51.100.44` |
| `c2-beacon-service.net` | `c2-beacon-service[.]net` | dns_query | `203.0.113.88` |
| `beacon-c2.net` | `beacon-c2[.]net` | tls_sni | `None` |

### Candidate URLs
| URL | Defanged | Method | Host / Path |
|---|---|---|---|
| `http://update-portal-cdn.xyz/update_agent.exe` | `hxxp://update-portal-cdn[.]xyz/update_agent.exe` | `GET` | `update-portal-cdn.xyz/update_agent.exe` |

---

## 8. Malware-Family Assessment

- **Confidence Tier**: **Probable**
- **Suspected Classification**: `Multi-Stage Loader / C2 Agent`
- **Forensic Rationale**: Traffic patterns demonstrate a staged delivery sequence: initial HTTP payload transfer followed by structured TLS C2 beaconing. Multiple corroborating network indicators observed.
- **Alternative Benign Hypotheses**: Automated security assessment scanner, penetration testing beacon (e.g. Cobalt Strike, Mythic, Sliver), or custom internal automated updater.
- **Required Endpoint Telemetry**: Need endpoint file sample hash, binary static analysis / sandbox detonation, and process execution telemetry to achieve Confirmed attribution.

---

## 9. MITRE ATT&CK Technique Mapping

| Tactic | Technique ID | Technique Name | Status | Supporting Evidence | Endpoint Verification Required |
|---|---|---|---|---|---|
| **Command and Control** | `T1071.004` | Application Layer Protocol: DNS | `Confirmed` | Observed 4 DNS transactions querying external domains. | Verify process DNS client cache and resolving application identity via endpoint socket logs. |
| **Command and Control / Execution** | `T1105` | Ingress Tool Transfer | `Confirmed` | Cleartext HTTP GET request observed requesting a Windows PE binary (.exe) payload. | Examine Sysmon Event ID 11 (FileCreate) and Sysmon Event ID 1 (Process Create) to confirm file write to disk and execution. |
| **Command and Control** | `T1071.001` | Application Layer Protocol: Web Protocols | `Confirmed` | Host engaged in HTTP web communications to external infrastructure. | Review parent process tree (e.g. powershell.exe, cmd.exe, or browser) that spawned the outbound connection. |
| **Command and Control** | `T1573.002` | Encrypted Channel: Asymmetric Cryptography (TLS) | `Probable` | Observed TLS ClientHello handshakes to external destination endpoints. | Inspect host memory for injected DLLs or living-off-the-land binaries maintaining persistent HTTPS sockets. |

---

## 10. Confidence, Caveats & Limitations

1. **Passive Capture Scope**: Passive network traffic alone cannot confirm process execution on endpoints. Observed file transfers must be corroborated with host file creation events.
2. **TLS Encryption Boundary**: Full application payloads for HTTPS/TLS traffic are encrypted. Analysis is limited to L4/L5 handshake metadata (SNI, endpoints, certificate subjects).
3. **Dynamic Infrastructure**: IP indicators may belong to shared hosting or CDNs. Blocks should be implemented with contextual scrutiny.

---

## 11. Recommended Containment & Remediation Actions

1. **Immediate Host Containment**: Isolate internal host(s) from the enterprise network via EDR isolation or VLAN quarantine.
2. **Network Blocklist Deployment**: Block external candidate IPs and domains at the perimeter firewall and DNS sinkhole.
3. **Endpoint Triage (EDR / Forensic Collection)**:
   - Collect Sysmon logs (EID 1, 3, 11) and PowerShell script block logs (EID 4104).
   - Inspect memory of active processes communicating with flagged external endpoints.
   - Scan local directories for dropped executables matching extracted URL paths.
4. **Threat Intelligence Correlation**: Submit extracted file hashes to enterprise threat intelligence repositories to cross-reference known threat actor campaigns.
