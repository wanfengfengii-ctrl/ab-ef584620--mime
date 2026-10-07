"""End-to-end tests for the HTTP API using a real loopback server."""

import json
import threading
import unittest
import urllib.error
import urllib.request

from mimeaudit.app import build_server
from tests.test_audit import (
    attachment_part,
    message,
    mixed,
    mixed_entity,
)


class HttpAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = build_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def _post(self, data, ctype="message/rfc822", raw_len=None):
        headers = {"Content-Type": ctype}
        if raw_len is not None:
            headers["Content-Length"] = str(raw_len)
        req = urllib.request.Request(
            f"{self.base}/api/mime/audit", data=data, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_health(self):
        with urllib.request.urlopen(f"{self.base}/health", timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read()), {"status": "ok"})

    def test_valid_nested_message_returns_manifest(self):
        a = attachment_part("a.txt", b"alpha payload")
        nested = mixed_entity("INNER", [attachment_part("n.bin", b"\x00\x01\x02\xff")])
        body = mixed("ROOT", [a, nested])
        status, payload = self._post(message(body))
        self.assertEqual(status, 200, payload)
        self.assertIn("attachments", payload)
        self.assertEqual([x["filename"] for x in payload["attachments"]], ["a.txt", "n.bin"])
        for item in payload["attachments"]:
            self.assertEqual(set(item), {"part", "filename", "media_type", "size", "sha256"})
            self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")

    def test_broken_boundary_is_rejected_without_partial_manifest(self):
        good = message(mixed("ROOT", [attachment_part("a", b"a")]))
        # Drop the closing delimiter line.
        broken = good.replace(b"--ROOT--\r\n", b"")
        status, payload = self._post(broken)
        self.assertEqual(status, 400)
        self.assertNotIn("attachments", payload)
        self.assertEqual(payload["code"], "BOUNDARY_NOT_CLOSED")

    def test_wrong_content_type_rejected(self):
        status, payload = self._post(b"x", ctype="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["code"], "UNSUPPORTED_MEDIA_TYPE")

    def test_get_on_audit_path_is_method_not_allowed(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"{self.base}/api/mime/audit", timeout=5)
        self.assertEqual(ctx.exception.code, 405)


if __name__ == "__main__":
    unittest.main(verbosity=2)
