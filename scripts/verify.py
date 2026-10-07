#!/usr/bin/env python3
"""One-shot verification service (``docker compose run verify``).

Phases:

1. Run the full unit test suite inside the built image.
2. Wait for the deployed ``api`` service's health endpoint.
3. Submit a *valid* four-level nested message; the returned manifest must
   match the independently decoded bytes (size + lowercase SHA-256).
4. Submit a *broken-boundary* message; it must be rejected with a stable
   error code, a locatable part ordinal and no partial manifest.

Exits 0 only when every phase succeeds.
"""

import base64
import hashlib
import json
import os
import sys
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_audit import (  # noqa: E402
    attachment_part,
    leaf_with,
    message,
    mixed,
    mixed_entity,
)

BASE_URL = os.environ.get("MIME_AUDIT_BASE_URL", "http://api:8080").rstrip("/")
CRLF = "\r\n"


def phase_unit_tests() -> bool:
    print("== phase 1: unit tests ==", flush=True)
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return result.wasSuccessful()


def _request(method, path, data=None, ctype=None, timeout=5):
    headers = {}
    if ctype:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(BASE_URL + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def phase_health() -> bool:
    print(f"== phase 2: waiting for {BASE_URL}/health ==", flush=True)
    for _ in range(30):
        try:
            status, payload = _request("GET", "/health")
            if status == 200 and payload.get("status") == "ok":
                print("health ok", flush=True)
                return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(1)
    print("health check timed out", flush=True)
    return False


def _qp_encode(payload: bytes) -> str:
    """Canonical quoted-printable encoding with CRLF line breaks (<=76)."""
    out = bytearray()
    line = bytearray()

    def flush(soft=False):
        if soft:
            line.append(ord("="))
        out.extend(line)
        out.extend(b"\r\n")
        line.clear()

    i = 0
    while i < len(payload):
        c = payload[i]
        if c == 0x0D and i + 1 < len(payload) and payload[i + 1] == 0x0A:
            flush()
            i += 2
            continue
        if c in (0x09, 0x20) or (0x21 <= c <= 0x7E and c != 0x3D):
            token = bytes([c])
        else:
            token = b"=" + f"{c:02X}".encode("ascii")
        if len(line) + len(token) > 76:
            flush(soft=True)
        line.extend(token)
        i += 1
    if line or not out:
        flush()
    return out.decode("ascii").rstrip("\r\n")


def build_legal_message():
    payloads = {
        "a.txt": (b"research archive evidence A\n" * 3, "text/plain", "base64"),
        "n.bin": (bytes(range(256)) * 4, "application/octet-stream", "base64"),
        "quote.txt": (
            b"caf=\xe9 quoted printable\r\nsecond line",
            "text/plain",
            "quoted-printable",
        ),
        "€-report.txt": (b"\xe2\x82\xac euro attachment", "text/plain", "base64"),
    }

    def leaf(fname, payload, media, cte):
        if cte == "base64":
            body = base64.encodebytes(payload).replace(b"\n", b"\r\n").rstrip(b"\r\n").decode()
        else:
            body = _qp_encode(payload)
        if fname == "€-report.txt":
            disp = "Content-Disposition: attachment; filename*=UTF-8''%E2%82%AC-report.txt"
        else:
            disp = f"Content-Disposition: attachment; filename={fname}"
        return leaf_with(
            [f"Content-Type: {media}", f"Content-Transfer-Encoding: {cte}", disp],
            body,
        )

    a = leaf("a.txt", *payloads["a.txt"])
    n = leaf("n.bin", *payloads["n.bin"])
    q = leaf("quote.txt", *payloads["quote.txt"])
    u = leaf("€-report.txt", *payloads["€-report.txt"])

    # root > B1 > B2 > [leaf, B3 > leaf]  (four multipart levels deep)
    l3 = mixed_entity("B3", [u])
    l2 = mixed_entity("B2", [n, l3])
    l1 = mixed_entity("B1", [q, l2])
    root_body = mixed("ROOT", [a, l1])
    return message(root_body), payloads


def phase_valid_message() -> bool:
    print("== phase 3: valid nested message ==", flush=True)
    msg, payloads = build_legal_message()
    status, payload = _request("POST", "/api/mime/audit", msg, "message/rfc822")
    if status != 200:
        print(f"FAIL expected 200 got {status}: {payload}", flush=True)
        return False
    atts = payload.get("attachments")
    if not isinstance(atts, list) or len(atts) != 4:
        print(f"FAIL expected 4 attachments, got: {atts}", flush=True)
        return False

    # Independently recompute expected size / digest from the decoded bytes.
    expected = {}
    for fname, (data, _media, _cte) in payloads.items():
        expected[fname] = (len(data), hashlib.sha256(data).hexdigest())

    seen = set()
    for item in atts:
        fname = item["filename"]
        if fname not in expected:
            print(f"FAIL unexpected filename {fname!r}", flush=True)
            return False
        size, digest = expected[fname]
        if item["size"] != size or item["sha256"] != digest:
            print(
                f"FAIL manifest mismatch for {fname!r}: "
                f"got ({item['size']}, {item['sha256']}) expected ({size}, {digest})",
                flush=True,
            )
            return False
        if item["sha256"] != item["sha256"].lower():
            print("FAIL sha256 must be lowercase", flush=True)
            return False
        seen.add(fname)
    if seen != set(expected):
        print(f"FAIL attachment set mismatch: {seen}", flush=True)
        return False

    # Stability: the same input must produce byte-identical output again.
    status2, payload2 = _request("POST", "/api/mime/audit", msg, "message/rfc822")
    if status2 != 200 or payload2 != payload:
        print("FAIL manifest is not stable across requests", flush=True)
        return False

    print(f"PASS valid message manifest: {json.dumps(payload, ensure_ascii=True)}", flush=True)
    return True


def build_broken_boundary_message():
    good = message(mixed("ROOT", [attachment_part("a.txt", b"abc"), attachment_part("b.bin", b"def")]))
    # Remove the closing delimiter while leaving the parts dangling.
    return good.replace(b"--ROOT--\r\n", b"")


def phase_broken_boundary() -> bool:
    print("== phase 4: broken boundary message ==", flush=True)
    bad = build_broken_boundary_message()
    status, payload = _request("POST", "/api/mime/audit", bad, "message/rfc822")
    if status != 400:
        print(f"FAIL expected 400 got {status}: {payload}", flush=True)
        return False
    if "attachments" in payload:
        print(f"FAIL partial manifest must not be returned: {payload}", flush=True)
        return False
    code = payload.get("code")
    if not isinstance(code, str) or not code:
        print(f"FAIL missing stable error code: {payload}", flush=True)
        return False
    if code != "BOUNDARY_NOT_CLOSED":
        print(f"FAIL expected BOUNDARY_NOT_CLOSED, got {code}", flush=True)
        return False
    if not isinstance(payload.get("message"), str) or not payload["message"]:
        print(f"FAIL missing human readable message: {payload}", flush=True)
        return False
    print(f"PASS broken boundary rejected with code={code} part={payload.get('part')}", flush=True)
    return True


def main() -> int:
    phases = (
        phase_unit_tests,
        phase_health,
        phase_valid_message,
        phase_broken_boundary,
    )
    for phase in phases:
        if not phase():
            print(f"VERIFY FAILED in {phase.__name__}", flush=True)
            return 1
    print("VERIFY OK: all phases passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
