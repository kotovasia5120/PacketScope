"""Small dependency-free PEP 517 backend for PacketScope.

PacketScope deliberately has no build-time or runtime third-party
dependencies.  This backend produces the pure-Python wheel needed by offline
builds instead of referring to an unavailable external backend.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import sys
import zipfile


NAME = "packetscope"
VERSION = "0.1.0"
DIST_INFO = f"{NAME}-{VERSION}.dist-info"
ROOT = Path(__file__).resolve().parent.parent


def _metadata() -> dict[str, str]:
    return {
        "METADATA": "\n".join(
            [
                "Metadata-Version: 2.1",
                f"Name: {NAME}",
                f"Version: {VERSION}",
                "Summary: A local, explainable binary protocol reverse-engineering workbench.",
                "Requires-Python: >=3.12,<3.13",
                "License: MIT",
                "Author: PacketScope contributors",
                "",
            ]
        ),
        "WHEEL": "Wheel-Version: 1.0\nGenerator: packetscope.build_backend\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        "entry_points.txt": "[console_scripts]\npacketscope = packetscope.cli:main\n",
    }


def _write_metadata(directory: str | os.PathLike[str]) -> Path:
    target = Path(directory) / DIST_INFO
    target.mkdir(parents=True, exist_ok=True)
    for name, content in _metadata().items():
        (target / name).write_text(content, encoding="utf-8")
    return target


def get_requires_for_build_wheel(config_settings=None) -> list[str]:
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None) -> str:
    _write_metadata(metadata_directory)
    return DIST_INFO


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None) -> str:
    filename = f"{NAME}-{VERSION}-py3-none-any.whl"
    destination = Path(wheel_directory) / filename
    records: list[str] = []
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
        files = sorted(
            path
            for path in (ROOT / NAME).rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        )
        for path in files:
            archive_name = path.relative_to(ROOT).as_posix()
            data = path.read_bytes()
            wheel.writestr(archive_name, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            records.append(f"{archive_name},sha256={digest},{len(data)}")
        metadata = _metadata()
        for metadata_name, content in metadata.items():
            archive_name = f"{DIST_INFO}/{metadata_name}"
            data = content.encode("utf-8")
            wheel.writestr(archive_name, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            records.append(f"{archive_name},sha256={digest},{len(data)}")
        records.append(f"{DIST_INFO}/RECORD,,")
        wheel.writestr(f"{DIST_INFO}/RECORD", "\n".join(records) + "\n")
    return filename


def _check() -> None:
    if tuple(sys.version_info[:2]) != (3, 12):
        raise SystemExit(f"PacketScope requires Python 3.12.x; found {sys.version.split()[0]}")
    if sys.version_info[:3] != (3, 12, 7):
        raise SystemExit(f"PacketScope reproducible image requires Python 3.12.7; found {sys.version.split()[0]}")


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        _check()
    else:
        raise SystemExit("usage: python -m packetscope.build_backend --check")
