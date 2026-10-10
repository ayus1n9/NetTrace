# NetTrace Detection Rules Reference

This document provides detailed documentation for custom Suricata detection rules, behavioral heuristics, and validation methodology.

---

## 1. Custom Suricata Signatures

### Rule 1: Windows Executable Download via Plaintext HTTP
- **SID**: `1000001`
- **Rule Purpose**: Detects cleartext download requests for Windows executable binaries (`.exe`).
- **Required Protocol / Traffic Conditions**: Established TCP flow to external server, HTTP `GET` request, URI ending in `.exe`.
- **Expected Alert**: `NETTRACE SUSPICIOUS Windows Executable Download (.exe)`
- **Known Limitations**: Does not inspect encrypted HTTPS downloads; does not verify if file response actually returned an MZ/PE header.
- **Benign Traffic That Might Trigger It**: Legitimate software updates over unencrypted HTTP (legacy systems or internal mirror repositories).
- **Recommended Follow-up**: Check endpoint process logs (Sysmon Event ID 1 / EDR) for process creation from downloaded path; verify file hash via threat intelligence.

### Rule 2: Query to Potentially Malicious Dynamic DNS or TLD
- **SID**: `1000002`
- **Rule Purpose**: Identifies DNS lookups targeting high-abuse top-level domains commonly used by initial access loaders.
- **Required Protocol / Traffic Conditions**: UDP/TCP port 53 DNS query containing `.xyz`.
- **Expected Alert**: `NETTRACE SUSPICIOUS Query to Potentially Malicious Dynamic DNS or TLD`
- **Known Limitations**: Many legitimate domains use `.xyz` or alternative TLDs; signature alone cannot prove malicious intent.
- **Benign Traffic That Might Trigger It**: Legitimate web navigation to commercial `.xyz` web properties.
- **Recommended Follow-up**: Correlate with resolved IP address, passive DNS history, and host browsing context.

### Rule 3: Plaintext HTTP on Non-Standard Port
- **SID**: `1000003`
- **Rule Purpose**: Flags unencrypted HTTP commands transmitted over non-standard destination ports (outside 80, 443, 8080).
- **Required Protocol / Traffic Conditions**: TCP flow where destination port is not 80/443/8080, payload begins with `GET `.
- **Expected Alert**: `NETTRACE ANOMALY Plaintext HTTP on Non-Standard Port`
- **Known Limitations**: Developer microservices or internal admin portals may bind HTTP to ephemeral ports.
- **Benign Traffic That Might Trigger It**: Local development servers, alternate proxy gateways.
- **Recommended Follow-up**: Identify remote destination ownership and inspecting process on the source host.

### Rule 4: Suspicious TLS SNI Matching C2 Pattern
- **SID**: `1000004`
- **Rule Purpose**: Identifies TLS ClientHello handshakes where the Server Name Indication contains suspected adversary infrastructure tokens.
- **Required Protocol / Traffic Conditions**: TLS port 443 handshake, `tls.sni` string match.
- **Expected Alert**: `NETTRACE SUSPICIOUS TLS SNI Matching Known C2 Beacon Pattern`
- **Known Limitations**: Adversaries leveraging domain fronting or CDNs may blend into legitimate infrastructure.
- **Recommended Follow-up**: Inspect host socket connection history, TLS JA3/JA4 fingerprints, and certificate issuer details.

---

## 2. Behavioral Heuristics Engine

In addition to signature-based alerts, `NetTrace` includes algorithmic behavioral heuristics:
1. **Beaconing Analysis**: Calculates coefficient of variation ($CV = \sigma / \mu$) across connection intervals. Small variances ($CV < 0.25$) indicate automated, machine-driven beaconing rather than human interactive browsing.
2. **Unusual Port Detection**: Flags outbound egress to uncommon administrative or high ports.
3. **High-Frequency Resolution**: Identifies multiple rapid DNS lookups within short temporal windows.
