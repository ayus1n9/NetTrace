"""Tests for TShark and Suricata execution paths using mocking."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from tests.test_extraction import traffic_pcap_file

from pcap_analyzer.detection import run_suricata_offline
from pcap_analyzer.extraction import extract_metadata_tshark


def test_tshark_json_parsing_mocked(traffic_pcap_file: Path):
    """Test TShark execution and JSON output parser via mock."""
    mock_tshark_output = json.dumps([
        {
            "_source": {
                "layers": {
                    "frame.time_epoch": ["1700000000.0"],
                    "ip.src": ["192.168.1.50"],
                    "ip.dst": ["93.184.216.34"],
                    "tcp.srcport": ["50000"],
                    "tcp.dstport": ["80"],
                    "http.request.method": ["GET"],
                    "http.host": ["example.com"],
                    "http.request.uri": ["/index.html"],
                    "http.user_agent": ["curl/7.88.1"],
                }
            }
        },
        {
            "_source": {
                "layers": {
                    "frame.time_epoch": ["1700000001.0"],
                    "ip.src": ["192.168.1.50"],
                    "ip.dst": ["1.1.1.1"],
                    "udp.srcport": ["53000"],
                    "udp.dstport": ["53"],
                    "dns.flags.response": ["0"],
                    "dns.qry.name": ["test-mock.xyz"],
                    "dns.qry.type": ["1"],
                    "dns.a": ["198.51.100.10"],
                }
            }
        },
        {
            "_source": {
                "layers": {
                    "frame.time_epoch": ["1700000002.0"],
                    "ip.src": ["192.168.1.50"],
                    "ip.dst": ["104.244.42.1"],
                    "tcp.srcport": ["51000"],
                    "tcp.dstport": ["443"],
                    "tls.handshake.extensions_server_name": ["mock-sni.net"],
                }
            }
        }
    ])

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = mock_tshark_output

    with patch("shutil.which", return_value="/usr/bin/tshark"), \
         patch("subprocess.run", return_value=mock_proc):
        metadata = extract_metadata_tshark(traffic_pcap_file, case_id="CASE-TSHARK-MOCK")

        assert metadata.extraction_source == "tshark"
        assert len(metadata.connections) >= 3
        assert len(metadata.http_requests) == 1
        assert metadata.http_requests[0].host == "example.com"
        assert len(metadata.dns_queries) == 1
        assert metadata.dns_queries[0].query_name == "test-mock.xyz"
        assert len(metadata.tls_handshakes) == 1
        assert metadata.tls_handshakes[0].server_name == "mock-sni.net"


def test_suricata_execution_successful_mocked(traffic_pcap_file: Path, tmp_path: Path):
    """Test successful Suricata execution and eve.json alert extraction via mock."""
    rules_file = tmp_path / "mock.rules"
    rules_file.touch()

    # Pre-create eve.json in output directory to simulate Suricata output
    eve_file = tmp_path / "eve.json"
    eve_alert = {
        "event_type": "alert",
        "timestamp": "2026-10-10T12:00:00+00:00",
        "src_ip": "10.0.0.45",
        "src_port": 49200,
        "dest_ip": "198.51.100.44",
        "dest_port": 80,
        "alert": {
            "signature": "NETTRACE SUSPICIOUS Windows Executable Download (.exe)",
            "signature_id": 1000001,
            "category": "bad-unknown",
            "severity": 1,
        }
    }

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stderr = ""

    def fake_subprocess_run(cmd, **kwargs):
        # Write eve.json when subprocess runs
        eve_file.write_text(json.dumps(eve_alert) + "\n", encoding="utf-8")
        return mock_proc

    with patch("shutil.which", return_value="/usr/bin/suricata"), \
         patch("subprocess.run", side_effect=fake_subprocess_run):
        alerts, result = run_suricata_offline(traffic_pcap_file, rules_file, tmp_path)

        assert result.attempted is True
        assert result.success is True
        assert result.alerts_found == 1
        assert len(alerts) == 1
        assert alerts[0]["alert"]["signature_id"] == 1000001
