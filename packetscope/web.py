from __future__ import annotations

import json
import hashlib
import mimetypes
import socket
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from packetscope.analysis import analyze_packets
from packetscope.errors import PacketScopeError
from packetscope.export import dumps_result
from packetscope.importers import import_bytes
from packetscope.models import Limits
from packetscope.demo import demo_capture, demo_corpus
from packetscope.evaluation import evaluate_result
from packetscope.flows import normalize_direction
from packetscope.jobs import AnalysisManager


STATIC_DIR = Path(__file__).with_name("static")


class PacketScopeHandler(BaseHTTPRequestHandler):
    server_version = "PacketScope/0.1"

    def setup(self) -> None:
        super().setup()
        # A client that advertises a body and then stops must not pin a server
        # thread forever.  This is deliberately short for the local UI; a
        # large upload still arrives in one bounded request body.
        self.connection.settimeout(10.0)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if self.path == "/api/health":
            self._json(HTTPStatus.OK, {"status": "ok", "local_only": True})
            return
        if parsed.path == "/api/demo/download":
            profile = query.get("profile", ["crc16-be"])[0]
            format_name = query.get("format", ["pcap"])[0]
            try:
                payload = demo_capture(profile, format_name=format_name, limits=self.server.limits)
            except (ValueError, TypeError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "unknown demo profile or format"})
                return
            self._binary(HTTPStatus.OK, payload,
                         "application/vnd.tcpdump.pcap" if format_name == "pcap" else "application/x-pcapng")
            return
        if parsed.path == "/api/demo":
            profile = query.get("profile", ["crc16-be"])[0]
            direction = query.get("direction", ["both"])[0]
            flow_id = query.get("flow_id", [None])[0] or None
            try:
                direction = normalize_direction(direction)
                demo = demo_corpus(profile, limits=self.server.limits)  # type: ignore[attr-defined]
                result = analyze_packets(demo["packets"], limits=self.server.limits,
                                         selected_direction=direction, flow_id=flow_id)
            except (ValueError, TypeError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid demo selection"})
                return
            self.server.demo_truth[profile] = demo["ground_truth"]  # type: ignore[attr-defined]
            result["demo"] = {"profile": profile, "metadata": demo["metadata"], "evaluation_available": True}
            self._json(HTTPStatus.OK, result)
            return
        if self.path.startswith("/api/jobs/"):
            job_id = self.path.removeprefix("/api/jobs/").split("/", 1)[0]
            status = self.server.analysis_manager.get(job_id)  # type: ignore[attr-defined]
            self._json(HTTPStatus.OK if status else HTTPStatus.NOT_FOUND, status or {"error": "job not found"})
            return
        if self.path == "/" or self.path == "/index.html":
            self._static("index.html")
            return
        if self.path.startswith("/static/"):
            self._static(unquote(self.path.removeprefix("/static/")))
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/api/demo/evaluate":
            self._evaluate_demo()
            return
        if self.path == "/api/jobs":
            self._submit_job()
            return
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
        body = self._read_body(content_length)
        if body is None:
            return
        if len(body) != content_length:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "request body is shorter than Content-Length"})
            return
        try:
            name, format_name, payload, analyze_raw, selected_direction, flow_id = _multipart_file(self.headers.get("Content-Type", ""), body)
            imported = import_bytes(name, payload, format_name, self.server.limits)  # type: ignore[attr-defined]
            result = analyze_packets(imported.packets, limits=self.server.limits, analyze_raw=analyze_raw,
                                     selected_direction=selected_direction, flow_id=flow_id,
                                     input_sha256=hashlib.sha256(payload).hexdigest())  # type: ignore[attr-defined]
            result["source"] = {
                "name": name,
                "format": imported.format,
                "packet_count": len(imported.packets),
                "byte_count": len(payload),
            }
            result["warnings"] = _merge_warnings(result.get("warnings", []), imported.warnings)
            self._json(HTTPStatus.OK, result)
        except PacketScopeError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except (ValueError, UnicodeDecodeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

    def do_DELETE(self) -> None:  # noqa: N802
        if self.path.startswith("/api/jobs/"):
            job_id = self.path.removeprefix("/api/jobs/").split("/", 1)[0]
            cancelled, current_status = self.server.analysis_manager.cancel_with_status(job_id)  # type: ignore[attr-defined]
            if current_status is None:
                self._json(HTTPStatus.NOT_FOUND, {"job_id": job_id, "cancelled": False})
            elif cancelled:
                self._json(HTTPStatus.OK, {"job_id": job_id, "cancelled": True, "status": current_status})
            else:
                # The job is known but has already reached a terminal state;
                # distinguish that from an unknown job instead of reporting
                # a misleading 404.
                self._json(HTTPStatus.CONFLICT, {"job_id": job_id, "cancelled": False, "status": current_status})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def _submit_job(self) -> None:
        length_header = self.headers.get("Content-Length")
        try:
            content_length = int(length_header or "-1")
        except ValueError:
            content_length = -1
        if content_length < 0:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length is required"})
            return
        if content_length > self.server.limits.max_input_bytes:  # type: ignore[attr-defined]
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "upload exceeds size limit"})
            return
        try:
            body = self._read_body(content_length)
            if body is None:
                return
            if len(body) != content_length:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "request body is shorter than Content-Length"})
                return
            name, format_name, payload, analyze_raw, selected_direction, flow_id = _multipart_file(self.headers.get("Content-Type", ""), body)
            job = self.server.analysis_manager.submit(
                name, format_name, payload, analyze_raw,
                selected_direction=selected_direction, flow_id=flow_id,
            )  # type: ignore[attr-defined]
            self._json(HTTPStatus.ACCEPTED, {"job_id": job.job_id, "status": job.status, "progress": job.progress})
        except (ValueError, RuntimeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST if isinstance(exc, ValueError) else HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})

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

    def _read_body(self, length: int) -> bytes | None:
        try:
            return self.rfile.read(length)
        except (TimeoutError, socket.timeout):
            self._json(HTTPStatus.REQUEST_TIMEOUT, {"error": "request body read timed out"})
            return None

    def _evaluate_demo(self) -> None:
        """Evaluate a previously returned demo result without exposing truth data.

        Evaluation is deliberately a post-analysis operation.  The request
        contains only the profile name and the caller's result; the matching
        ground truth stays in the server-side demo registry.  Every client
        failure is converted to a response so malformed requests cannot tear
        down the HTTP connection.
        """
        length_header = self.headers.get("Content-Length")
        try:
            length = int(length_header or "-1")
        except ValueError:
            length = -1
        limit = self.server.limits.max_input_bytes  # type: ignore[attr-defined]
        if length < 0:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length is required"})
            return
        if length > limit:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "evaluation request exceeds size limit"})
            return
        if not self.headers.get("Content-Type", "").lower().split(";", 1)[0].strip() == "application/json":
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "Content-Type must be application/json"})
            return
        body = self._read_body(length)
        if body is None:
            return
        if len(body) != length:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "request body is shorter than Content-Length"})
            return
        try:
            value = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "evaluation request must be valid JSON"})
            return
        if not isinstance(value, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "evaluation request must be a JSON object"})
            return
        profile = value.get("profile")
        result = value.get("result")
        if not isinstance(profile, str) or not profile:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "evaluation profile is required"})
            return
        if profile not in {"crc16-be", "crc32-le"}:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "unknown evaluation profile"})
            return
        if not isinstance(result, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "evaluation result is required"})
            return
        hypotheses = result.get("hypotheses", [])
        if not isinstance(hypotheses, list) or len(hypotheses) > self.server.limits.max_hypotheses:  # type: ignore[attr-defined]
            self._json(HTTPStatus.BAD_REQUEST, {"error": "evaluation hypotheses exceed the configured limit"})
            return
        truth = self.server.demo_truth.get(profile)  # type: ignore[attr-defined]
        if truth is None:
            self._json(HTTPStatus.CONFLICT, {"error": "demo evaluation is not available"})
            return
        try:
            self._json(HTTPStatus.OK, evaluate_result(result, truth))
        except (TypeError, ValueError, KeyError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "evaluation result has an invalid shape"})
        except Exception:
            # Do not expose exception text, tracebacks, or packet-derived data.
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "evaluation failed"})

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

    def _binary(self, status: HTTPStatus, payload: bytes, content_type: str) -> None:
        if len(payload) > self.server.limits.max_response_bytes:  # type: ignore[attr-defined]
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "response exceeds configured limit"})
            return
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class PacketScopeServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], limits: Limits | None = None):
        super().__init__(address, PacketScopeHandler)
        self.limits = limits or Limits()
        self.demo_truth: dict[str, list[dict]] = {}
        self.analysis_manager = AnalysisManager(self.limits)

    def server_close(self) -> None:
        self.analysis_manager.close()
        super().server_close()


def serve(host: str = "127.0.0.1", port: int = 8765, limits: Limits | None = None) -> None:
    server = PacketScopeServer((host, port), limits)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def _multipart_file(content_type: str, body: bytes) -> tuple[str, str, bytes, bool, str, str | None]:
    if not content_type.lower().startswith("multipart/form-data"):
        raise ValueError("Content-Type must be multipart/form-data")
    message = BytesParser(policy=policy.default).parsebytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
    )
    if not message.is_multipart():
        raise ValueError("invalid multipart body")
    requested_format = "auto"
    analyze_raw = False
    selected_direction = "both"
    flow_id: str | None = None
    file_part = None
    field_count = 0
    for part in message.iter_parts():
        field_count += 1
        if field_count > 32:
            raise ValueError("multipart form has too many fields")
        disposition = part.get_content_disposition()
        field_name = part.get_param("name", header="content-disposition")
        if disposition == "form-data" and field_name == "format":
            requested_format = (part.get_content() or "auto").strip().lower()
        if disposition == "form-data" and field_name == "raw":
            analyze_raw = (part.get_content() or "").strip().lower() in {"1", "true", "yes", "on"}
        if disposition == "form-data" and field_name == "direction":
            selected_direction = normalize_direction((part.get_content() or "both").strip())
        if disposition == "form-data" and field_name == "flow_id":
            candidate = (part.get_content() or "").strip()
            if len(candidate) > 200:
                raise ValueError("flow_id exceeds length limit")
            flow_id = candidate or None
        if disposition == "form-data" and field_name in {"file", "packet"}:
            file_part = part
    if file_part is not None:
        filename = file_part.get_filename() or "upload.bin"
        return filename[:200], requested_format, file_part.get_payload(decode=True) or b"", analyze_raw, selected_direction, flow_id
    raise ValueError("multipart field 'file' is required")


def _merge_warnings(analyzer: list, importer: list[str]) -> list[dict[str, str]]:
    merged = []
    for warning in analyzer:
        if isinstance(warning, dict):
            merged.append({"source": str(warning.get("source", "analyzer")), "message": str(warning.get("message", ""))})
        else:
            merged.append({"source": "analyzer", "message": str(warning)})
    merged.extend({"source": "importer", "message": str(warning)} for warning in importer)
    return sorted(merged, key=lambda item: (item["source"], item["message"]))
