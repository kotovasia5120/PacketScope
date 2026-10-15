import json
import socket
import threading
import unittest
import urllib.error
import urllib.request
import uuid

from packetscope.models import Limits
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


if __name__ == "__main__":
    unittest.main()
