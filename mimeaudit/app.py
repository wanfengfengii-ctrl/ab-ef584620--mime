"""HTTP front-end for the strict MIME audit API.

* ``POST /api/mime/audit`` -- consumes exactly ``message/rfc822`` (<= 4 MiB,
  CRLF throughout) and returns the attachment manifest as JSON, or a stable
  error object; no partial manifest is ever emitted.
* ``GET  /health``       -- liveness probe for Docker / Compose.

The server only depends on the Python standard library.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .errors import MimeAuditError
from .parser import MAX_MESSAGE_BYTES, audit_message

AUDIT_PATH = "/api/mime/audit"
HEALTH_PATH = "/health"


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "MimeAudit/1.0"

    # Quiet the default stderr logging; structured JSON belongs to the API.
    def log_message(self, fmt, *args):  # noqa: D401, N802
        return

    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path.split("?", 1)[0] == HEALTH_PATH:
            self._send_json(200, {"status": "ok"})
        elif self.path.split("?", 1)[0] == AUDIT_PATH:
            self._send_json(405, {"code": "METHOD_NOT_ALLOWED", "message": "use POST", "part": None})
        else:
            self._send_json(404, {"code": "NOT_FOUND", "message": "unknown path", "part": None})

    def do_POST(self):  # noqa: N802
        if self.path.split("?", 1)[0] != AUDIT_PATH:
            self._send_json(404, {"code": "NOT_FOUND", "message": "unknown path", "part": None})
            return

        ctype = self.headers.get("Content-Type", "")
        if ctype.split(";", 1)[0].strip().lower() != "message/rfc822":
            self._send_json(
                415,
                {"code": "UNSUPPORTED_MEDIA_TYPE", "message": "Content-Type must be message/rfc822", "part": None},
            )
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"code": "BAD_CONTENT_LENGTH", "message": "Content-Length is not an integer", "part": None})
            return
        if length <= 0:
            self._send_json(400, {"code": "EMPTY_BODY", "message": "request body is empty", "part": None})
            return

        # Read at most one octet past the limit so oversized uploads are
        # rejected without trusting an attacker-controlled Content-Length.
        raw = self._read_limited(length)
        if raw is None:
            self._send_json(413, {"code": "MESSAGE_TOO_LARGE", "message": f"message exceeds {MAX_MESSAGE_BYTES} bytes", "part": None})
            return

        try:
            result = audit_message(raw)
        except MimeAuditError as exc:
            self._send_json(400, exc.to_dict())
        else:
            self._send_json(200, result)

    def _read_limited(self, declared: int):
        remaining = min(declared, MAX_MESSAGE_BYTES + 1)
        chunks = []
        received = 0
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
            remaining -= len(chunk)
            if received > MAX_MESSAGE_BYTES:
                return None
        return b"".join(chunks)


def build_server(host: str = "0.0.0.0", port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), AuditHandler)
