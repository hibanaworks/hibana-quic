"""Parse actual Rust writer output with Python JSON; fixtures are not interop evidence."""
from decimal import Decimal
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BoundedTraceSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Intentionally fail if the required Rust toolchain is absent: a skip
        # would not constitute serializer verification.
        with tempfile.TemporaryDirectory(prefix="hibana-trace-fixture-") as directory:
            binary = Path(directory) / "fixture"
            subprocess.run(["rustc", "--edition=2024", "-Dwarnings",
                            str(ROOT / "tests/support/trace_fixture.rs"),
                            "-o", str(binary)], check=True)
            cls.wire = subprocess.check_output([str(binary)])
        cls.records = []
        for record in cls.wire.split(b"\x1e")[1:]:
            if not record.endswith(b"\n"):
                raise AssertionError("JSON-SEQ record lacks line feed")
            cls.records.append(json.loads(record, parse_float=Decimal))

    def test_sequence_framing_and_header(self):
        self.assertTrue(self.wire.startswith(b"\x1e{"))
        self.assertEqual(len(self.records), 37)
        header = self.records[0]
        self.assertEqual(header["file_schema"], "urn:ietf:params:qlog:file:sequential")
        self.assertEqual(header["serialization_format"], "application/qlog+json-seq")
        self.assertEqual(header["trace"]["event_schemas"], ["urn:ietf:params:qlog:events:quic-13"])
        self.assertEqual(header["trace"]["vantage_point"], {"type": "client"})
        self.assertEqual(header["trace"]["common_fields"], {
            "time_format": "relative_to_epoch",
            "reference_time": {"clock_type": "monotonic", "epoch": "unknown"},
        })
        self.assertNotIn("events", header["trace"])

    def test_each_event_matches_supported_shapes(self):
        for event in self.records[1:]:
            self.assertEqual(set(event), {"time", "name", "data"})
            self.assertIsInstance(event["time"], Decimal)
            self.assertIsInstance(event["data"], dict)
        self.assertEqual({event["name"] for event in self.records[1:]}, {
            "quic:packet_sent", "quic:packet_received", "quic:udp_datagrams_sent",
            "quic:udp_datagrams_received", "quic:packet_dropped", "quic:packet_lost",
            "quic:key_updated",
        })
        for event in self.records[1:]:
            data = event["data"]
            if event["name"] in {"quic:packet_sent", "quic:packet_received"}:
                self.assertIn("header", data)
                self.assertLessEqual(set(data), {"header", "datagram_id"})
                self.assertLessEqual(set(data["header"]), {"packet_type", "packet_number", "key_phase"})
            elif "udp_datagrams_" in event["name"]:
                self.assertEqual(set(data), {"count", "raw", "datagram_ids", "ecn"})
                self.assertEqual(data["count"], 1)
                self.assertEqual(len(data["raw"]), 1)
                self.assertEqual(set(data["raw"][0]), {"length"})
                self.assertEqual(len(data["ecn"]), 1)
                self.assertEqual(len(data["datagram_ids"]), 1)
            elif event["name"] == "quic:key_updated":
                self.assertEqual(set(data), {"key_type", "key_phase", "trigger"})

    def test_exact_large_integers_and_timestamp_units(self):
        received = self.records[2]
        self.assertEqual(received["data"]["header"]["packet_number"], str(2**62 - 1))
        self.assertEqual(received["data"]["header"]["key_phase"], str(2**64 - 1))
        self.assertEqual(received["time"], Decimal("0.001"))
        self.assertEqual(self.records[-1]["time"], Decimal("18446744073709551.615"))
        times = [event["time"] for event in self.records[1:]]
        self.assertEqual(times, sorted(times))

    def test_enum_spellings_and_absent_private_data(self):
        events = self.records[1:]
        packet_types = {e["data"]["header"]["packet_type"] for e in events if "header" in e["data"]}
        self.assertEqual(packet_types, {"initial", "handshake", "0RTT", "1RTT", "retry",
                                       "version_negotiation", "stateless_reset", "unknown"})
        drop_reasons = {e["data"]["trigger"] for e in events if e["name"] == "quic:packet_dropped"}
        self.assertEqual(drop_reasons, {"internal_error", "rejected", "unsupported", "invalid",
                                      "duplicate", "connection_unknown", "decryption_failure",
                                      "key_unavailable", "general"})
        ecn = {e["data"]["ecn"][0] for e in events if "ecn" in e["data"]}
        self.assertEqual(ecn, {"Not-ECT", "ECT(0)", "ECT(1)", "CE"})
        for forbidden in [b'"old"', b'"new"', b'"scid"', b'"dcid"', b'"token"',
                          b'"ip_v4"', b'"ip_v6"', b'"frames"']:
            self.assertNotIn(forbidden, self.wire)
        for event in events:
            if event["name"] == "quic:packet_dropped":
                self.assertNotIn("packet_number", event["data"]["header"])


if __name__ == "__main__":
    unittest.main()
