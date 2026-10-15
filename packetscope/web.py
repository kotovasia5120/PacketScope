from __future__ import annotations

import json
import mimetypes
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from packetscope.analysis import analyze_packets
from packetscope.errors import PacketScopeError
from packetscope.export import dumps_result
from packetscope.importers import import_bytes
from packetscope.models import Limits


STATIC_DIR = Path(__file__).with_name("static")


class PacketScopeHandler(BaseHTTPRequestHandler):
    server_version = "PacketScope/0.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/api/health":
            self._json(HTTPStatus.OK, {"status": "ok", "local_only": True})
            return
        if self.path == "/" or self.path == "/index.html":
            self._static("index.html")
            return
        if self.path.startswith("/static/"):
            self._static(unquote(self.path.removeprefix("/static/")))
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/api/analyze":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        length_header = self.headers.get("Content-Length")
        try:
            content_length = int(length_header or "-1")
        except ValueError:
            content_length = -1
        limit = self.server.limits.max_input_bytes  # type: ignore[attr-defined]
        if content_length < 0:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length is required"})
            return
        if content_length > limit:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "upload exceeds size limit"})
            return
        body = self.rfile.read(content_length)
        if len(body) != content_length:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "request body is shorter than Content-Length"})
            return
        try:
            name, format_name, payload = _multipart_file(self.headers.get("Content-Type", ""), body)
            imported = import_bytes(name, payload, format_name, self.server.limits)  # type: ignore[attr-defined]
            result = analyze_packets(imported.packets, limits=self.server.limits)  # type: ignore[attr-defined]
            result["source"] = {
                "name": name,
                "format": imported.format,
                "packet_count": len(imported.packets),
                "byte_count": len(payload),
            }
            result["warnings"] = imported.warnings
            self._json(HTTPStatus.OK, result)
        except PacketScopeError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except (ValueError, UnicodeDecodeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

    def log_message(self, _format: str, *_args: object) -> None:
        # Captures can contain secrets; the local server intentionally stays quiet.
        return

    def _static(self, relative: str) -> None:
        candidate = (STATIC_DIR / relative).resolve()
        try:
            candidate.relative_to(STATIC_DIR.resolve())
        except ValueError:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not candidate.is_file():
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        content = candidate.read_bytes()
        if len(content) > self.server.limits.max_response_bytes:  # type: ignore[attr-defined]
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "response exceeds configured limit"})
            return
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _json(self, status: HTTPStatus, value: dict) -> None:
        payload = dumps_result(value).encode("utf-8")
        if len(payload) > self.server.limits.max_response_bytes:  # type: ignore[attr-defined]
            payload = b"{}"
            status = HTTPStatus.INTERNAL_SERVER_ERROR
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class PacketScopeServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], limits: Limits | None = None):
        super().__init__(address, PacketScopeHandler)
        self.limits = limits or Limits()


def serve(host: str = "127.0.0.1", port: int = 8765, limits: Limits | None = None) -> None:
    server = PacketScopeServer((host, port), limits)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def _multipart_file(content_type: str, body: bytes) -> tuple[str, str, bytes]:
    if not content_type.lower().startswith("multipart/form-data"):
        raise ValueError("Content-Type must be multipart/form-data")
    message = BytesParser(policy=policy.default).parsebytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
    )
    if not message.is_multipart():
        raise ValueError("invalid multipart body")
    requested_format = "auto"
    file_part = None
    for part in message.iter_parts():
        disposition = part.get_content_disposition()
        field_name = part.get_param("name", header="content-disposition")
        if disposition == "form-data" and field_name == "format":
            requested_format = (part.get_content() or "auto").strip().lower()
        if disposition == "form-data" and field_name in {"file", "packet"}:
            file_part = part
    if file_part is not None:
        filename = file_part.get_filename() or "upload.bin"
        return filename[:200], requested_format, file_part.get_payload(decode=True) or b""
    raise ValueError("multipart field 'file' is required")
