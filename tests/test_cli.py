import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packetscope.cli import main
from packetscope.errors import InputLimitError
from packetscope.models import Limits


class CliTests(unittest.TestCase):
    def test_file_size_is_checked_before_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "too-large.bin"
            path.write_bytes(b"1234")
            with patch("packetscope.cli.Limits", return_value=Limits(max_input_bytes=3)):
                with self.assertRaises(InputLimitError):
                    main(["analyze", str(path), "--format", "bin"])


if __name__ == "__main__":
    unittest.main()
