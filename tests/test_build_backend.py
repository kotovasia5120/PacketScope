import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from packetscope.build_backend import build_wheel


class BuildBackendTests(unittest.TestCase):
    def test_wheel_bytes_are_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first"
            second = Path(directory) / "second"
            first.mkdir()
            second.mkdir()
            first_path = first / build_wheel(first)
            second_path = second / build_wheel(second)
            self.assertEqual(
                hashlib.sha256(first_path.read_bytes()).digest(),
                hashlib.sha256(second_path.read_bytes()).digest(),
            )
            with zipfile.ZipFile(first_path) as wheel:
                metadata = wheel.read("packetscope-0.1.0.dist-info/METADATA").decode("utf-8")
                self.assertIn("Requires-Python: ==3.12.7", metadata)


if __name__ == "__main__":
    unittest.main()
