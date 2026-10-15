import json
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from unittest import mock

from packetscope.models import Limits
from packetscope.importers.base import import_bytes
from packetscope.jobs import AnalysisManager
from packetscope.web import PacketScopeServer


def multipart(payload: bytes, filename: str = "sample.bin", raw: bool = False) -> tuple[bytes, str]:
    boundary = "----PacketScope" + uuid.uuid4().hex
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + payload
    if raw:
        body += f"\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"raw\"\r\n\r\ntrue".encode()
    body += f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


class WebIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.server = PacketScopeServer(("127.0.0.1", 0), Limits(max_input_bytes=512))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, path: str, method: str = "GET", body: bytes | None = None, content_type: str | None = None):
        request = urllib.request.Request(self.base + path, data=body, method=method)
        if content_type:
            request.add_header("Content-Type", content_type)
        return urllib.request.urlopen(request, timeout=2)

    def test_health_and_ui(self):
        with self.request("/api/health") as response:
            self.assertEqual(response.status, 200)
            self.assertTrue(json.load(response)["local_only"])
        with self.request("/") as response:
            self.assertEqual(response.status, 200)
            self.assertIn(b"PacketScope", response.read())

    def test_demo_evaluation_returns_metrics_for_both_profiles(self):
        self.server.limits = Limits(max_input_bytes=2 * 1024 * 1024)
        for profile in ("crc16-be", "crc32-le"):
            with self.request(f"/api/demo?profile={profile}") as response:
                result = json.load(response)
            body = json.dumps({"profile": profile, "result": result}).encode()
            with self.request("/api/demo/evaluate", "POST", body, "application/json") as response:
                evaluation = json.load(response)
            self.assertIn("precision", evaluation)
            self.assertIn("recall", evaluation)
            self.assertIn("f1", evaluation)
            self.assertGreater(evaluation["matched_count"], 0)
        with self.request("/api/health") as response:
            self.assertEqual(response.status, 200)

    def test_demo_evaluation_rejects_client_errors_and_recovers(self):
        cases = [
            (b"{", "application/json", 400),
            (json.dumps({"profile": "crc16-be"}).encode(), "application/json", 400),
            (json.dumps({"profile": "not-a-demo", "result": {}}).encode(), "application/json", 400),
            (json.dumps({"profile": "crc16-be", "result": []}).encode(), "application/json", 400),
            (b"{}", "text/plain", 415),
        ]
        for body, content_type, expected_status in cases:
            with self.assertRaises(urllib.error.HTTPError) as context:
                self.request("/api/demo/evaluate", "POST", body, content_type)
            self.assertEqual(context.exception.code, expected_status)

        self.server.limits = Limits(max_input_bytes=8)
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request("/api/demo/evaluate", "POST", b"{}" * 8, "application/json")
        self.assertEqual(context.exception.code, 413)

        self.server.limits = Limits(max_input_bytes=512)
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request(
                "/api/demo/evaluate", "POST",
                json.dumps({"profile": "crc16-be", "result": {}}).encode(), "application/json"
            )
        self.assertEqual(context.exception.code, 409)
        sock = socket.create_connection(("127.0.0.1", self.server.server_port), timeout=2)
        request = (
            "POST /api/demo/evaluate HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.server.server_port}\r\n"
            "Content-Length: 10\r\n"
            "Content-Type: application/json\r\n\r\n"
            "{}"
        ).encode()
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)
        response = sock.recv(4096)
        sock.close()
        self.assertIn(b"400", response.split(b"\r\n", 1)[0])
        with self.request("/api/health") as response:
            self.assertEqual(response.status, 200)

    def test_demo_evaluation_hides_unexpected_failures(self):
        self.server.limits = Limits(max_input_bytes=2 * 1024 * 1024)
        with self.request("/api/demo") as response:
            result = json.load(response)
        body = json.dumps({"profile": "crc16-be", "result": result}).encode()
        with mock.patch("packetscope.web.evaluate_result", side_effect=RuntimeError("secret payload")):
            with self.assertRaises(urllib.error.HTTPError) as context:
                self.request("/api/demo/evaluate", "POST", body, "application/json")
        self.assertEqual(context.exception.code, 500)
        self.assertNotIn(b"secret payload", context.exception.read())
        with self.request("/api/health") as response:
            self.assertEqual(response.status, 200)

    def test_upload_returns_analysis_json(self):
        body, content_type = multipart(bytes([0xAA, 1, 2, 3]))
        with self.request("/api/analyze", "POST", body, content_type) as response:
            result = json.load(response)
        self.assertEqual(result["source"]["byte_count"], 4)
        self.assertEqual(result["source"]["format"], "bin")
        self.assertEqual(result["packets"][0]["payload"], "aa010203")

    def test_raw_analysis_option_is_exposed(self):
        body, content_type = multipart(b"raw-bytes", raw=True)
        with self.request("/api/analyze", "POST", body, content_type) as response:
            result = json.load(response)
        self.assertEqual(result["analysis"]["scope"], "raw_packet")

    def test_upload_limit_returns_413_and_server_survives(self):
        body, content_type = multipart(b"x" * 600)
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request("/api/analyze", "POST", body, content_type)
        self.assertEqual(context.exception.code, 413)
        with self.request("/api/health") as response:
            self.assertEqual(response.status, 200)

    def test_short_body_is_rejected_and_server_survives(self):
        sock = socket.create_connection(("127.0.0.1", self.server.server_port), timeout=2)
        request = (
            "POST /api/analyze HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.server.server_port}\r\n"
            "Content-Length: 10\r\n"
            "Content-Type: application/octet-stream\r\n\r\n"
            "abc"
        ).encode()
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)
        response = sock.recv(4096)
        sock.close()
        self.assertIn(b"400", response.split(b"\r\n", 1)[0])
        with self.request("/api/health") as health:
            self.assertEqual(health.status, 200)

    def test_response_limit_is_applied(self):
        self.server.limits = Limits(max_input_bytes=512, max_response_bytes=10)
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request("/api/health")
        self.assertEqual(context.exception.code, 500)

    def test_multipart_field_count_is_bounded(self):
        self.server.limits = Limits(max_input_bytes=4096)
        boundary = "----PacketScopeFields"
        parts = [f"--{boundary}\r\nContent-Disposition: form-data; name=field{i}\r\n\r\nvalue\r\n" for i in range(33)]
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=file; filename=x.bin\r\n\r\nx\r\n")
        body = ("".join(parts) + f"--{boundary}--\r\n").encode()
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request("/api/analyze", "POST", body, f"multipart/form-data; boundary={boundary}")
        self.assertEqual(context.exception.code, 400)

    def test_job_reads_are_repeatable_and_terminal_delete_is_conflict(self):
        body, content_type = multipart(b"job")
        with self.request("/api/jobs", "POST", body, content_type) as response:
            queued = json.load(response)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with self.request(f"/api/jobs/{queued['job_id']}") as response:
                status = json.load(response)
            if status["status"] in {"COMPLETE", "FAILED", "CANCELLED"}:
                break
            time.sleep(0.01)
        self.assertEqual(status["status"], "COMPLETE")
        with self.request(f"/api/jobs/{queued['job_id']}") as response:
            repeated = json.load(response)
        self.assertEqual(repeated, status)
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request(f"/api/jobs/{queued['job_id']}", "DELETE")
        self.assertEqual(context.exception.code, 409)

    def test_job_delete_cancels_analysis_and_unknown_is_not_found(self):
        started = threading.Event()

        def analyzer(packets, *, cancel, **kwargs):
            started.set()
            while not cancel():
                time.sleep(0.002)
            return {"status": "CANCELLED", "warnings": []}

        self.server.analysis_manager.close()
        self.server.analysis_manager = AnalysisManager(
            self.server.limits,
            importer=import_bytes,
            analyzer=analyzer,
        )
        body, content_type = multipart(b"job")
        with self.request("/api/jobs", "POST", body, content_type) as response:
            queued = json.load(response)
        self.assertTrue(started.wait(1))
        with self.request(f"/api/jobs/{queued['job_id']}", "DELETE") as response:
            cancelled = json.load(response)
        self.assertEqual(cancelled["cancelled"], True)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with self.request(f"/api/jobs/{queued['job_id']}") as response:
                status = json.load(response)
            if status["status"] == "CANCELLED":
                break
            time.sleep(0.01)
        self.assertEqual(status["status"], "CANCELLED")
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request("/api/jobs/does-not-exist", "DELETE")
        self.assertEqual(context.exception.code, 404)

    def test_job_queue_overflow_returns_service_unavailable(self):
        started = threading.Event()
        release = threading.Event()

        def analyzer(packets, **kwargs):
            started.set()
            release.wait(1)
            return {"warnings": []}

        self.server.analysis_manager.close()
        self.server.analysis_manager = AnalysisManager(
            self.server.limits,
            max_queue=1,
            importer=import_bytes,
            analyzer=analyzer,
        )
        body, content_type = multipart(b"job")
        try:
            with self.request("/api/jobs", "POST", body, content_type) as response:
                self.assertEqual(response.status, 202)
            self.assertTrue(started.wait(1))
            with self.request("/api/jobs", "POST", body, content_type) as response:
                self.assertEqual(response.status, 202)
            with self.assertRaises(urllib.error.HTTPError) as context:
                self.request("/api/jobs", "POST", body, content_type)
            self.assertEqual(context.exception.code, 503)
        finally:
            release.set()


if __name__ == "__main__":
    unittest.main()
