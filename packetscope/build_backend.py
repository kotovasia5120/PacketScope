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
import time
import zipfile


NAME = "packetscope"
VERSION = "0.2.0"
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
                "Requires-Python: ==3.12.7",
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
    source_date_epoch = max(int(os.environ.get("SOURCE_DATE_EPOCH", "315532800")), 315532800)
    source_date = time.gmtime(source_date_epoch)
    timestamp = (source_date.tm_year, source_date.tm_mon, source_date.tm_mday, source_date.tm_hour, source_date.tm_min, source_date.tm_sec)

    def write_entry(wheel: zipfile.ZipFile, archive_name: str, data: bytes) -> None:
        info = zipfile.ZipInfo(archive_name, date_time=timestamp)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.create_system = 3
        info.external_attr = 0o644 << 16
        wheel.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=False) as wheel:
        files = sorted(
            path
            for path in (ROOT / NAME).rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        )
        for path in files:
            archive_name = path.relative_to(ROOT).as_posix()
            data = path.read_bytes()
            write_entry(wheel, archive_name, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            records.append(f"{archive_name},sha256={digest},{len(data)}")
        metadata = _metadata()
        for metadata_name, content in metadata.items():
            archive_name = f"{DIST_INFO}/{metadata_name}"
            data = content.encode("utf-8")
            write_entry(wheel, archive_name, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            records.append(f"{archive_name},sha256={digest},{len(data)}")
        records.append(f"{DIST_INFO}/RECORD,,")
        write_entry(wheel, f"{DIST_INFO}/RECORD", ("\n".join(records) + "\n").encode("utf-8"))
    return filename


def _check() -> None:
    if tuple(sys.version_info[:2]) != (3, 12):
        raise SystemExit(f"PacketScope requires Python 3.12.x; found {sys.version.split()[0]}")
    if sys.version_info[:3] != (3, 12, 7):
        raise SystemExit(f"PacketScope reproducible image requires Python 3.12.7; found {sys.version.split()[0]}")
    lock = ROOT / "requirements.lock"
    if not lock.is_file():
        raise SystemExit("requirements.lock is missing")
    undeclared = [
        line.strip()
        for line in lock.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if undeclared:
        raise SystemExit(f"unexpected unlocked dependencies: {undeclared!r}")


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        _check()
    else:
        raise SystemExit("usage: python -m packetscope.build_backend --check")
