import json
import threading
import unittest
import urllib.error
import urllib.request
import uuid

from packetscope.models import Limits
from packetscope.web import PacketScopeServer


def multipart(payload: bytes, filename: str = "sample.bin") -> tuple[bytes, str]:
    boundary = "----PacketScope" + uuid.uuid4().hex
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()
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

    def test_upload_limit_returns_413_and_server_survives(self):
        body, content_type = multipart(b"x" * 600)
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request("/api/analyze", "POST", body, content_type)
        self.assertEqual(context.exception.code, 413)
        with self.request("/api/health") as response:
            self.assertEqual(response.status, 200)


if __name__ == "__main__":
    unittest.main()
