from __future__ import annotations

import hashlib
import json
import mimetypes
import socket
import struct
import threading
import time
import uuid
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from packetscope import __version__
from packetscope.analysis import analyze_packets
from packetscope.config import DeploymentConfig, deployment_from_env, format_bytes
from packetscope.errors import FormatError, InputLimitError, PacketScopeError
from packetscope.export import dumps_result
from packetscope.importers import import_bytes
from packetscope.interop import export_kaitai, export_wireshark_lua
from packetscope.models import Limits
from packetscope.demo import demo_capture, demo_corpus
from packetscope.evaluation import evaluate_result
from packetscope.flows import flows_as_dict, group_flows, normalize_direction
from packetscope.jobs import AnalysisManager
from packetscope.reassembly import reconstruct_tcp_streams
from packetscope.schema import loads_schema, validate_capture_against_schema


STATIC_DIR = Path(__file__).with_name("static")


class PacketScopeHandler(BaseHTTPRequestHandler):
    server_version = f"PacketScope/{__version__}"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        # A client that advertises a body and then stops must not pin a server
        # thread forever. The deadline is also enforced between bounded reads
        # so a slow trickle cannot keep a request alive indefinitely.
        self.connection.settimeout(self.server.limits.max_request_seconds)
        self.close_connection = True

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if self.path == "/api/health":
            config = self.server.deployment  # type: ignore[attr-defined]
            self._json(HTTPStatus.OK, {
                "status": "ok",
                "deployment_mode": config.mode,
                "local_only": config.local_only,
                "upload_limit_bytes": self.server.limits.max_input_bytes,  # type: ignore[attr-defined]
                "privacy_notice": config.privacy_notice,
            })
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
            evaluation_id = uuid.uuid4().hex
            self.server.demo_records[evaluation_id] = {  # type: ignore[attr-defined]
                "profile": profile,
                "result": json.loads(dumps_result(result)),
            }
            while len(self.server.demo_records) > 8:  # type: ignore[attr-defined]
                del self.server.demo_records[next(iter(self.server.demo_records))]  # type: ignore[attr-defined]
            result["demo"] = {
                "profile": profile,
                "metadata": demo["metadata"],
                "evaluation_available": True,
                "evaluation_id": evaluation_id,
                "evaluation_mode": "server_recomputed_reference",
            }
            self._json(HTTPStatus.OK, result)
            return
        if parsed.path.startswith("/api/jobs/") and parsed.path.endswith("/report"):
            job_id = parsed.path.removeprefix("/api/jobs/").removesuffix("/report").strip("/")
            status = self.server.analysis_manager.get(job_id)  # type: ignore[attr-defined]
            if status is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "job not found"})
            elif status.get("status") != "COMPLETE" or not isinstance(status.get("result"), dict):
                self._json(HTTPStatus.CONFLICT, {"error": "experiment report is not complete"})
            else:
                self._report_download(job_id, status["result"])
            return
        if parsed.path.startswith("/api/jobs/"):
            job_id = parsed.path.removeprefix("/api/jobs/").split("/", 1)[0]
            status = self.server.analysis_manager.get(job_id)  # type: ignore[attr-defined]
            self._json(HTTPStatus.OK if status else HTTPStatus.NOT_FOUND, status or {"error": "job not found"})
            return
        if parsed.path == "/" or parsed.path == "/index.html":
            self._static("index.html")
            return
        if parsed.path.startswith("/static/"):
            self._static(unquote(parsed.path.removeprefix("/static/")))
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/api/demo/evaluate":
            self._evaluate_demo()
            return
        if self.path == "/api/jobs":
            self._submit_job()
            return
        if self.path == "/api/experiments/prepare":
            self._prepare_experiment()
            return
        if self.path == "/api/experiments":
            self._submit_experiment()
            return
        if self.path == "/api/reconstruct":
            self._reconstruct_streams()
            return
        if self.path == "/api/schema/validate":
            self._validate_schema_capture()
            return
        if self.path == "/api/schema/export/kaitai":
            self._export_schema("kaitai")
            return
        if self.path == "/api/schema/export/wireshark":
            self._export_schema("wireshark")
            return
        if self.path != "/api/analyze":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        content_length = self._content_length()
        limit = self.server.limits.max_input_bytes  # type: ignore[attr-defined]
        if content_length is None:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length is required"})
            return
        if content_length < 0:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length is invalid"})
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
            self._json(HTTPStatus.BAD_REQUEST, {"error": _safe_capture_error(exc)})
        except (ValueError, UnicodeDecodeError, struct.error, IndexError, OverflowError, RecursionError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": _safe_capture_error(exc)})
        except MemoryError:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "capture exceeds available processing budget"})
        except Exception:
            # Malformed/adversarial input must not terminate the request thread
            # or expose exception text that could contain capture data.
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid capture"})

    def do_DELETE(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path.startswith("/api/jobs/"):
            job_id = path.removeprefix("/api/jobs/").split("/", 1)[0]
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
        content_length = self._content_length()
        if content_length is None:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length is required"})
            return
        if content_length < 0:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length is invalid"})
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
        except (ValueError, PacketScopeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": _safe_capture_error(exc)})
        except RuntimeError as exc:
            message = str(exc).lower()
            if "payload" in message or "retention" in message:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "upload exceeds the retained-job payload budget"})
            else:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "analysis service is busy"})
        except (struct.error, IndexError, OverflowError, RecursionError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid capture"})
        except MemoryError:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "capture exceeds available processing budget"})
        except Exception:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid capture"})

    def _prepare_experiment(self) -> None:
        parsed = self._read_experiment_request()
        if parsed is None:
            return
        baseline, changed = parsed["baseline"], parsed["changed"]
        try:
            if len(baseline["payload"]) + len(changed["payload"]) > self.server.limits.max_job_payload_bytes:  # type: ignore[attr-defined]
                raise InputLimitError("experiment payload exceeds retention limit")
            baseline_imported = import_bytes(
                baseline["name"], baseline["payload"], baseline["format"], self.server.limits  # type: ignore[attr-defined]
            )
            changed_imported = import_bytes(
                changed["name"], changed["payload"], changed["format"], self.server.limits  # type: ignore[attr-defined]
            )
            self._json(HTTPStatus.OK, {
                "baseline": _experiment_source(
                    baseline, baseline_imported, len(baseline["payload"]),
                    flows_as_dict(group_flows(baseline_imported.packets, limits=self.server.limits)),  # type: ignore[attr-defined]
                ),
                "changed": _experiment_source(
                    changed, changed_imported, len(changed["payload"]),
                    flows_as_dict(group_flows(changed_imported.packets, limits=self.server.limits)),  # type: ignore[attr-defined]
                ),
            })
        except PacketScopeError as exc:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE if isinstance(exc, InputLimitError) else HTTPStatus.BAD_REQUEST,
                       {"error": _safe_capture_error(exc)})
        except (ValueError, UnicodeDecodeError, struct.error, IndexError, OverflowError, RecursionError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid experiment capture"})
        except MemoryError:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "capture exceeds available processing budget"})
        except Exception:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid experiment capture"})

    def _submit_experiment(self) -> None:
        parsed = self._read_experiment_request()
        if parsed is None:
            return
        baseline, changed = parsed["baseline"], parsed["changed"]
        try:
            job = self.server.analysis_manager.submit_controlled_experiment(  # type: ignore[attr-defined]
                baseline["name"], baseline["format"], baseline["payload"],
                changed["name"], changed["format"], changed["payload"], parsed["raw"],
                baseline_direction=baseline["direction"],
                changed_direction=changed["direction"],
                baseline_flow_id=baseline["flow_id"],
                changed_flow_id=changed["flow_id"],
                change_label=parsed["change_label"],
            )
            self._json(HTTPStatus.ACCEPTED, {
                "job_id": job.job_id,
                "operation": "controlled_experiment",
                "status": job.status,
                "progress": job.progress,
                "report_url": f"/api/jobs/{job.job_id}/report",
            })
        except (ValueError, PacketScopeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": _safe_capture_error(exc)})
        except RuntimeError as exc:
            message = str(exc).lower()
            if "payload" in message or "retention" in message:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "experiment exceeds the retained-job payload budget"})
            else:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "analysis service is busy"})
        except MemoryError:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "capture exceeds available processing budget"})
        except Exception:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid experiment capture"})

    def _read_experiment_request(self) -> dict | None:
        content_length = self._content_length()
        if content_length is None:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length is required"})
            return None
        if content_length < 0:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length is invalid"})
            return None
        if content_length > self.server.limits.max_input_bytes:  # type: ignore[attr-defined]
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "upload exceeds size limit"})
            return None
        body = self._read_body(content_length)
        if body is None:
            return None
        if len(body) != content_length:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "request body is shorter than Content-Length"})
            return None
        try:
            return _multipart_experiment(self.headers.get("Content-Type", ""), body)
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": _safe_capture_error(exc)})
            return None

    def _report_download(self, job_id: str, result: dict) -> None:
        payload = dumps_result(result).encode("utf-8")
        if len(payload) > self.server.limits.max_response_bytes:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "report exceeds configured response limit"})
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="packetscope-experiment-{job_id}.json"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _reconstruct_streams(self) -> None:
        content_length = self._content_length()
        if content_length is None:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length is required"})
            return
        if content_length < 0:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length is invalid"})
            return
        if content_length > self.server.limits.max_input_bytes:  # type: ignore[attr-defined]
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "upload exceeds size limit"})
            return
        body = self._read_body(content_length)
        if body is None:
            return
        if len(body) != content_length:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "request body is shorter than Content-Length"})
            return
        try:
            name, format_name, payload, _raw, _direction, _flow_id = _multipart_file(self.headers.get("Content-Type", ""), body)
            imported = import_bytes(name, payload, format_name, self.server.limits)  # type: ignore[attr-defined]
            report = reconstruct_tcp_streams(imported.packets, limits=self.server.limits)  # type: ignore[attr-defined]
            report["source"] = {"name": name, "format": imported.format, "packet_count": len(imported.packets), "byte_count": len(payload), "raw_sha256": hashlib.sha256(payload).hexdigest()}
            report["warnings"] = _merge_warnings([], imported.warnings)
            self._json(HTTPStatus.OK, report)
        except PacketScopeError as exc:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE if isinstance(exc, InputLimitError) else HTTPStatus.BAD_REQUEST, {"error": _safe_capture_error(exc)})
        except (ValueError, UnicodeDecodeError, struct.error, IndexError, OverflowError, RecursionError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid capture"})
        except MemoryError:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "capture exceeds available processing budget"})
        except Exception:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "stream reconstruction failed"})

    def _validate_schema_capture(self) -> None:
        content_length = self._content_length()
        if content_length is None:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length is required"})
            return
        if content_length < 0:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length is invalid"})
            return
        if content_length > self.server.limits.max_input_bytes:  # type: ignore[attr-defined]
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "validation request exceeds size limit"})
            return
        body = self._read_body(content_length)
        if body is None:
            return
        if len(body) != content_length:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "request body is shorter than Content-Length"})
            return
        try:
            name, format_name, payload, schema = _multipart_schema_validation(self.headers.get("Content-Type", ""), body)
            imported = import_bytes(name, payload, format_name, self.server.limits)  # type: ignore[attr-defined]
            report = validate_capture_against_schema(schema, imported.packets, max_packets=self.server.limits.max_packets)  # type: ignore[attr-defined]
            report["source"] = {"name": name, "format": imported.format, "packet_count": len(imported.packets), "byte_count": len(payload)}
            report["warnings"] = _merge_warnings([], imported.warnings)
            self._json(HTTPStatus.OK, report)
        except PacketScopeError as exc:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE if isinstance(exc, InputLimitError) else HTTPStatus.BAD_REQUEST, {"error": _safe_capture_error(exc)})
        except (ValueError, UnicodeDecodeError, struct.error, IndexError, OverflowError, RecursionError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid schema or capture"})
        except MemoryError:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "validation exceeds available processing budget"})
        except Exception:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "schema validation failed"})

    def _export_schema(self, format_name: str) -> None:
        length = self._content_length()
        if length is None:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length is required"})
            return
        if length < 0 or length > self.server.limits.max_input_bytes:  # type: ignore[attr-defined]
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "schema export request exceeds size limit"})
            return
        body = self._read_body(length)
        if body is None:
            return
        try:
            value = json.loads(body)
            schema = loads_schema(json.dumps(value.get("schema") if isinstance(value, dict) else None))
            report = export_kaitai(schema) if format_name == "kaitai" else export_wireshark_lua(schema)
            self._json(HTTPStatus.OK, report)
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid protocol schema"})
        except MemoryError:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "schema export exceeds processing budget"})
        except Exception:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "schema export failed"})

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
        if candidate.name == "index.html" and candidate.parent == STATIC_DIR:
            content = _render_index(content, self.server.deployment, self.server.limits)  # type: ignore[attr-defined]
        if len(content) > self.server.limits.max_response_bytes:  # type: ignore[attr-defined]
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "response exceeds configured limit"})
            return
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _content_length(self) -> int | None:
        values = self.headers.get_all("Content-Length", [])
        if not values:
            return None
        if len(values) != 1:
            return -1
        raw = values[0].strip()
        if not raw.isascii() or not raw.isdigit():
            return -1
        try:
            return int(raw)
        except ValueError:
            return -1

    def _read_body(self, length: int) -> bytes | None:
        if length == 0:
            return b""
        deadline = time.monotonic() + self.server.limits.max_request_seconds  # type: ignore[attr-defined]
        chunks: list[bytes] = []
        remaining = length
        while remaining:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                self._json(HTTPStatus.REQUEST_TIMEOUT, {"error": "request body read timed out"})
                return None
            self.connection.settimeout(timeout)
            try:
                chunk = self.rfile.read(min(64 * 1024, remaining))
            except (TimeoutError, socket.timeout):
                self._json(HTTPStatus.REQUEST_TIMEOUT, {"error": "request body read timed out"})
                return None
            except OSError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "request body could not be read"})
                return None
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _evaluate_demo(self) -> None:
        """Evaluate a previously returned demo result without exposing truth data.

        Evaluation is deliberately a post-analysis operation.  The request
        contains only the profile name and the caller's result; the matching
        ground truth stays in the server-side demo registry.  Every client
        failure is converted to a response so malformed requests cannot tear
        down the HTTP connection.
        """
        length = self._content_length()
        limit = self.server.limits.max_input_bytes  # type: ignore[attr-defined]
        if length is None:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length is required"})
            return
        if length < 0:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Content-Length is invalid"})
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
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "evaluation request must be valid JSON"})
            return
        except MemoryError:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "evaluation request exceeds processing budget"})
            return
        if not isinstance(value, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "evaluation request must be a JSON object"})
            return
        profile = value.get("profile")
        result = value.get("result")
        evaluation_id = value.get("evaluation_id")
        if not isinstance(profile, str) or not profile:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "evaluation profile is required"})
            return
        if profile not in {"crc16-be", "crc32-le"}:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "unknown evaluation profile"})
            return
        if not (isinstance(evaluation_id, str) and evaluation_id):
            if not isinstance(result, dict):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "evaluation result is required for untrusted comparison"})
                return
            untrusted_hypotheses = result.get("hypotheses", [])
            if not isinstance(untrusted_hypotheses, list) or len(untrusted_hypotheses) > self.server.limits.max_hypotheses:  # type: ignore[attr-defined]
                self._json(HTTPStatus.BAD_REQUEST, {"error": "evaluation hypotheses exceed the configured limit"})
                return
        truth = self.server.demo_truth.get(profile)  # type: ignore[attr-defined]
        if truth is None:
            self._json(HTTPStatus.CONFLICT, {"error": "demo evaluation is not available"})
            return
        trusted = False
        if isinstance(evaluation_id, str) and evaluation_id:
            record = self.server.demo_records.get(evaluation_id)  # type: ignore[attr-defined]
            if record is None:
                self._json(HTTPStatus.CONFLICT, {"error": "evaluation identity is unknown or expired"})
                return
            if record.get("profile") != profile:
                self._json(HTTPStatus.CONFLICT, {"error": "evaluation identity does not match the selected profile"})
                return
            result = record.get("result")
            trusted = True
        if not isinstance(result, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "evaluation result is required for untrusted comparison"})
            return
        hypotheses = result.get("hypotheses", [])
        if not isinstance(hypotheses, list) or len(hypotheses) > self.server.limits.max_hypotheses:  # type: ignore[attr-defined]
            self._json(HTTPStatus.BAD_REQUEST, {"error": "evaluation hypotheses exceed the configured limit"})
            return
        try:
            evaluation = evaluate_result(result, truth)
            evaluation["evaluation_mode"] = "server_recomputed_reference" if trusted else "client_submitted_untrusted"
            evaluation["trusted"] = trusted
            self._json(HTTPStatus.OK, evaluation)
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
    daemon_threads = True
    request_queue_size = 16

    def __init__(
        self,
        address: tuple[str, int],
        limits: Limits | None = None,
        *,
        deployment_mode: str | None = None,
        max_concurrent_requests: int = 8,
    ):
        if max_concurrent_requests <= 0:
            raise ValueError("max_concurrent_requests must be positive")
        self.limits = limits or Limits()
        self.deployment = DeploymentConfig(deployment_mode) if deployment_mode is not None else deployment_from_env()
        self.deployment_mode = self.deployment.mode
        self.max_concurrent_requests = max_concurrent_requests
        self._request_slots = threading.BoundedSemaphore(max_concurrent_requests)
        super().__init__(address, PacketScopeHandler)
        self.demo_truth: dict[str, list[dict]] = {}
        self.demo_records: dict[str, dict] = {}
        self.analysis_manager = AnalysisManager(self.limits)

    def process_request(self, request, client_address) -> None:
        if not self._request_slots.acquire(blocking=False):
            _reject_busy_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()

    def server_close(self) -> None:
        self.analysis_manager.close()
        super().server_close()


def serve(
    host: str = "127.0.0.1",
    port: int = 8765,
    limits: Limits | None = None,
    *,
    deployment_mode: str | None = None,
) -> None:
    server = PacketScopeServer((host, port), limits, deployment_mode=deployment_mode)
    try:
        server.serve_forever()
    finally:
        server.server_close()



def _safe_capture_error(exc: Exception) -> str:
    """Return a bounded client error without echoing capture-derived text."""
    if isinstance(exc, InputLimitError):
        return "input exceeds a configured safety limit"
    if isinstance(exc, FormatError):
        return "invalid capture format"
    if isinstance(exc, ValueError):
        message = str(exc)
        return message if len(message) <= 120 else "invalid capture request"
    return "invalid capture"


def _reject_busy_request(request) -> None:
    payload = b'{"error":"server concurrency limit reached"}'
    response = (
        b"HTTP/1.1 503 Service Unavailable\r\n"
        b"Content-Type: application/json; charset=utf-8\r\n"
        b"Cache-Control: no-store\r\n"
        b"Retry-After: 1\r\n"
        b"Connection: close\r\n"
        + f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
        + payload
    )
    try:
        request.settimeout(1.0)
        request.sendall(response)
    except OSError:
        pass
    finally:
        request.close()


def _render_index(content: bytes, config: DeploymentConfig, limits: Limits) -> bytes:
    replacements = {
        "PacketScope — local protocol workbench": config.ui_title,
        'data-deployment-mode="local"': f'data-deployment-mode="{config.mode}"',
        "LOCAL / PRIVATE / EVIDENCE FIRST": config.ui_eyebrow,
        "Local/private · no cloud · no telemetry": config.ui_badge,
        "64 MiB upload limit": f"{format_bytes(limits.max_input_bytes)} upload limit",
        "Analyze locally": config.ui_analyze_label,
        "Ready for a local file.": config.ui_ready_status,
        "Captures are processed by this local server and are not sent to a hosted service.": config.privacy_notice,
    }
    rendered = content.decode("utf-8")
    for source, replacement in replacements.items():
        rendered = rendered.replace(source, replacement)
    return rendered.encode("utf-8")

def _multipart_file(content_type: str, body: bytes) -> tuple[str, str, bytes, bool, str, str | None]:
    if any(character in content_type for character in "\r\n") or len(content_type) > 1024:
        raise ValueError("invalid multipart content type")
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
        if field_name is not None and len(field_name) > 64:
            raise ValueError("multipart field name exceeds length limit")
        if disposition == "form-data" and field_name in {"file", "packet"}:
            if file_part is not None:
                raise ValueError("multipart form must contain one file")
            file_part = part
    if file_part is not None:
        filename = file_part.get_filename() or "upload.bin"
        payload = file_part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            raise ValueError("multipart file payload is invalid")
        return filename[:200], requested_format, payload, analyze_raw, selected_direction, flow_id
    raise ValueError("multipart field 'file' is required")


def _multipart_schema_validation(content_type: str, body: bytes) -> tuple[str, str, bytes, dict]:
    if any(character in content_type for character in "\r\n") or len(content_type) > 1024:
        raise ValueError("invalid multipart content type")
    if not content_type.lower().startswith("multipart/form-data"):
        raise ValueError("Content-Type must be multipart/form-data")
    message = BytesParser(policy=policy.default).parsebytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
    )
    if not message.is_multipart():
        raise ValueError("invalid multipart body")
    file_part = None
    schema_value = None
    format_name = "auto"
    field_count = 0
    for part in message.iter_parts():
        field_count += 1
        if field_count > 8:
            raise ValueError("schema validation form has too many fields")
        field_name = part.get_param("name", header="content-disposition")
        if field_name is not None and len(field_name) > 64:
            raise ValueError("multipart field name exceeds length limit")
        if field_name == "file":
            if file_part is not None:
                raise ValueError("schema validation requires one file")
            file_part = part
        elif field_name == "format":
            format_name = (part.get_content() or "auto").strip().lower()
            if format_name not in {
                "auto", "bin", "hex", "pcap", "pcapng", "jsonl",
                "uart", "uart-lines", "can", "can-lines",
            }:
                raise ValueError("schema validation format is invalid")
        elif field_name == "schema":
            schema_value = part.get_content()
    if file_part is None or schema_value is None:
        raise ValueError("schema validation requires file and schema fields")
    payload = file_part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        raise ValueError("multipart file payload is invalid")
    return _safe_upload_name(file_part.get_filename() or "upload.bin"), format_name, payload, loads_schema(schema_value)


def _multipart_experiment(content_type: str, body: bytes) -> dict:
    """Parse two bounded capture parts without accepting client-side results."""
    if any(character in content_type for character in "\r\n") or len(content_type) > 1024:
        raise ValueError("invalid multipart content type")
    if not content_type.lower().startswith("multipart/form-data"):
        raise ValueError("Content-Type must be multipart/form-data")
    message = BytesParser(policy=policy.default).parsebytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
    )
    if not message.is_multipart():
        raise ValueError("invalid multipart body")
    captures: dict[str, dict] = {}
    values = {
        "baseline_format": "auto",
        "changed_format": "auto",
        "baseline_direction": "both",
        "changed_direction": "both",
        "baseline_flow_id": None,
        "changed_flow_id": None,
        "raw": False,
        "change_label": "controlled change",
    }
    formats = {
        "auto", "bin", "hex", "pcap", "pcapng", "jsonl",
        "uart", "uart-lines", "can", "can-lines",
    }
    field_count = 0
    for part in message.iter_parts():
        field_count += 1
        if field_count > 32:
            raise ValueError("multipart form has too many fields")
        disposition = part.get_content_disposition()
        field_name = part.get_param("name", header="content-disposition")
        if field_name is not None and len(field_name) > 64:
            raise ValueError("multipart field name exceeds length limit")
        if disposition != "form-data" or not field_name:
            continue
        if field_name in {"baseline", "changed"}:
            if field_name in captures:
                raise ValueError(f"multipart form must contain one {field_name} file")
            payload = part.get_payload(decode=True)
            if not isinstance(payload, bytes):
                raise ValueError("multipart file payload is invalid")
            captures[field_name] = {
                "name": _safe_upload_name(part.get_filename() or f"{field_name}.bin"),
                "payload": payload,
            }
            continue
        if field_name in values:
            if field_name.endswith("_format"):
                value = (part.get_content() or "auto").strip().lower()
                if value not in formats:
                    raise ValueError("experiment format is invalid")
                values[field_name] = value
            elif field_name.endswith("_direction"):
                values[field_name] = normalize_direction((part.get_content() or "both").strip())
            elif field_name.endswith("_flow_id"):
                value = (part.get_content() or "").strip()
                if len(value) > 200:
                    raise ValueError("experiment flow_id exceeds length limit")
                values[field_name] = value or None
            elif field_name == "raw":
                values[field_name] = (part.get_content() or "").strip().lower() in {"1", "true", "yes", "on"}
            elif field_name == "change_label":
                value = " ".join((part.get_content() or "").split())
                if len(value) > 120:
                    raise ValueError("change label exceeds length limit")
                values[field_name] = value or "controlled change"
    if set(captures) != {"baseline", "changed"}:
        raise ValueError("multipart fields 'baseline' and 'changed' are required")
    captures["baseline"].update({
        "format": values["baseline_format"],
        "direction": values["baseline_direction"],
        "flow_id": values["baseline_flow_id"],
    })
    captures["changed"].update({
        "format": values["changed_format"],
        "direction": values["changed_direction"],
        "flow_id": values["changed_flow_id"],
    })
    return {
        "baseline": captures["baseline"],
        "changed": captures["changed"],
        "raw": values["raw"],
        "change_label": values["change_label"],
    }


def _safe_upload_name(value: str) -> str:
    """Keep provenance names bounded and path-free."""
    name = Path(value.replace("\\", "/")).name
    cleaned = "".join(character if character.isprintable() and character not in '\"\r\n' else "_" for character in name)
    return cleaned[:200] or "upload.bin"


def _experiment_source(source: dict, imported, byte_count: int, flows: list[dict]) -> dict:
    return {
        "name": source["name"],
        "requested_format": source["format"],
        "format": imported.format,
        "packet_count": len(imported.packets),
        "byte_count": byte_count,
        "raw_sha256": hashlib.sha256(source["payload"]).hexdigest(),
        "flows": [
            {
                "flow_id": item["flow_id"],
                "protocol": item["protocol"],
                "endpoint_a": item["endpoint_a"],
                "endpoint_b": item["endpoint_b"],
                "packet_count": item["packet_count"],
                "direction_counts": item["direction_counts"],
                "limitations": item["limitations"],
            }
            for item in flows
        ],
        "warnings": list(imported.warnings),
    }


def _merge_warnings(analyzer: list, importer: list[str]) -> list[dict[str, str]]:
    merged = []
    for warning in analyzer:
        if isinstance(warning, dict):
            merged.append({"source": str(warning.get("source", "analyzer")), "message": str(warning.get("message", ""))})
        else:
            merged.append({"source": "analyzer", "message": str(warning)})
    merged.extend({"source": "importer", "message": str(warning)} for warning in importer)
    return sorted(merged, key=lambda item: (item["source"], item["message"]))
