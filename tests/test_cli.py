import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packetscope.cli import main
from packetscope.errors import InputLimitError
from packetscope.models import Limits
from packetscope.evaluation import evaluate_result


class CliTests(unittest.TestCase):
    def test_evaluation_counts_matches_and_unmatched_hypotheses(self):
        report = evaluate_result({"hypotheses": [{"id": "magic", "field_type": "magic_bytes", "absolute_offset": 0, "width_bits": 16, "status": "hypothesis"}, {"id": "noise", "field_type": "message_type", "absolute_offset": 3, "width_bits": 8, "status": "hypothesis"}]}, [{"field_type": "magic_bytes", "absolute_offset": 0, "width_bits": 16}])
        self.assertEqual(report["matched_count"], 1)
        self.assertEqual(report["false_positive_count"], 1)
        self.assertEqual(report["automatic_confirmed_count"], 0)

    def test_file_size_is_checked_before_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "too-large.bin"
            path.write_bytes(b"1234")
            with patch("packetscope.cli.Limits", return_value=Limits(max_input_bytes=3)):
                with self.assertRaises(InputLimitError):
                    main(["analyze", str(path), "--format", "bin"])


if __name__ == "__main__":
    unittest.main()
