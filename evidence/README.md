# Evidence & Captures Notice

In adherence to strict defensive security practices:
1. **Never commit live malware samples or raw malicious PCAP/PCAPNG files to source control.**
2. Test fixtures in this repository synthesize synthetic, non-malicious packet headers (`tests/conftest.py`) to validate dissection and integrity workflows offline.
3. For real case investigations, place downloaded `.pcap` captures in this directory locally (which is excluded via `.gitignore`), record the provenance URL and SHA-256 hash in `cases/<case-name>/case-metadata.json`, and run NetTrace against the local file path.
