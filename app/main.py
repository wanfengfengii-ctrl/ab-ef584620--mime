"""HTTP front end for the MIME auditor (Python standard library only).

Endpoints:
  POST /api/mime/audit   audit a message/rfc822 body (max 4 MiB)
  GET  /healthz          liveness/readiness probe
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .errors import MimeAuditError
from .parser import MAX_MESSAGE_SIZE, audit_message

HOST = "0.0.0.0"
PORT = 8080
AUDIT_PATH = "/api/mime/audit"
HEALTH_PATH = "/healthz"
# Oversized bodies up to this many bytes past the limit are drained so the
# connection stays usable; anything larger gets Connection: close.
_DISCARD_SLOP = 1024 * 1024


class _Server(ThreadingHTTPServer):
    daemon_threads = True


class _Handler(BaseHTTPRequestHandler):
    server_version = "MimeAudit/1.0"
    protocol_version = "HTTP/1.1"

    # -- helpers ------------------------------------------------------
    def _send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status, code, message, part=None):
        self._send_json(
            status,
            {"error": {"code": code, "part": part, "message": message}},
        )

    def _discard(self, length):
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)

    # -- routing ------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == HEALTH_PATH:
            self._send_json(200, {"status": "ok"})
        else:
            self._send_error(404, "NOT_FOUND", "unknown endpoint")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != AUDIT_PATH:
            self._send_error(404, "NOT_FOUND", "unknown endpoint")
            return

        content_type = self.headers.get("Content-Type")
        media = content_type.split(";", 1)[0].strip().lower() if content_type else ""
        if media != "message/rfc822":
            self._send_error(
                415,
                "INVALID_REQUEST_CONTENT_TYPE",
                "Content-Type must be message/rfc822",
            )
            return

        transfer_encoding = self.headers.get("Transfer-Encoding", "identity")
        if transfer_encoding.strip().lower() != "identity":
            self._send_error(
                400,
                "UNSUPPORTED_REQUEST_TRANSFER_ENCODING",
                "chunked requests are not supported; send a Content-Length",
            )
            return

        raw_length = self.headers.get("Content-Length")
        if raw_length is None or not raw_length.isdigit():
            self._send_error(
                400,
                "MISSING_CONTENT_LENGTH",
                "a numeric Content-Length header is required",
            )
            return
        length = int(raw_length)
        if length > MAX_MESSAGE_SIZE:
            if length <= MAX_MESSAGE_SIZE + _DISCARD_SLOP:
                self._discard(length)
            else:
                self.close_connection = True
            self._send_error(
                413,
                "MESSAGE_TOO_LARGE",
                "message exceeds the %d byte limit" % MAX_MESSAGE_SIZE,
            )
            return

        body = self.rfile.read(length)
        if len(body) != length:
            self._send_error(
                400,
                "TRUNCATED_BODY",
                "fewer bytes received than declared by Content-Length",
            )
            return

        try:
            result = audit_message(body)
        except MimeAuditError as exc:
            self._send_json(exc.status, exc.to_dict())
            return
        except Exception:  # pragma: no cover - defensive
            self.log_error("unexpected auditor failure", exc_info=True)
            self._send_error(500, "INTERNAL_ERROR", "unexpected auditor failure")
            return
        self._send_json(200, result)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main():
    server = _Server((HOST, PORT), _Handler)
    print("mime-audit listening on %s:%d" % (HOST, PORT), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
