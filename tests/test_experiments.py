import json
import tempfile
import unittest
from pathlib import Path

from packetscope.cli import main
from packetscope.experiments import compare_controlled_change
from packetscope.models import Limits, Packet


class ExperimentComparisonTests(unittest.TestCase):
    def test_controlled_change_reports_bounded_correlated_range(self):
        baseline = [Packet(10, b"\xaa\x01\x10"), Packet(11, b"\xaa\x02\x10")]
        changed = [Packet(20, b"\xaa\x01\x20"), Packet(21, b"\xaa\x02\x20")]
        report = compare_controlled_change(baseline, changed)
        self.assertEqual(report["coordinate_system"], "application_payload")
        self.assertEqual(report["pairing"]["paired_messages"], 2)
        self.assertEqual(report["correlated_ranges"][0]["offset"], 2)
        self.assertEqual(report["correlated_ranges"][0]["width"], 1)
        self.assertEqual(report["correlated_ranges"][0]["change_rate"], 1.0)
        self.assertEqual(report["hypotheses"][0]["status"], "hypothesis")
        self.assertTrue(any("causation" in limitation for limitation in report["limitations"]))

    def test_unavailable_application_payload_is_not_paired_as_raw_bytes(self):
        baseline = [Packet(0, b"raw", link_type=999), Packet(1, b"\x01\x02")]
        changed = [Packet(2, b"other", link_type=999), Packet(3, b"\x01\x03")]
        report = compare_controlled_change(baseline, changed, limits=Limits(max_response_bytes=2048))
        self.assertEqual(report["baseline"]["unavailable_payloads"], 1)
        self.assertEqual(report["changed"]["unavailable_payloads"], 1)
        self.assertEqual(report["pairing"]["paired_messages"], 1)
        self.assertEqual(report["correlated_ranges"][0]["offset"], 1)

    def test_cli_compare_is_deterministic_and_supports_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.bin"
            changed = root / "changed.bin"
            output = root / "report.json"
            baseline.write_bytes(b"\x01\x02\x03")
            changed.write_bytes(b"\x01\x09\x03")
            self.assertEqual(main([
                "compare", str(baseline), str(changed), "--baseline-format", "bin",
                "--changed-format", "bin", "--output", str(output), "--pretty",
            ]), 0)
            report = json.loads(output.read_text())
            self.assertEqual(report["correlated_ranges"][0]["offset"], 1)
            self.assertEqual(report["baseline"]["format"], "bin")


if __name__ == "__main__":
    unittest.main()
