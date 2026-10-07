"""One-shot verification service.

Runs the strict-parser unit tests, then exercises the live HTTP endpoint
with a valid nested message and corrupted-boundary samples. The process
exit code is 0 only when every check passes, so `docker compose up
--exit-code-from verify verify` reports the result directly.
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

from app.errors import MimeAuditError
from app.parser import MAX_MESSAGE_SIZE, audit_message

APP_URL = os.environ.get("APP_URL", "http://127.0.0.1:8080").rstrip("/")

# ---------------------------------------------------------------------------
# Sample messages
# ---------------------------------------------------------------------------

NOTICE_QP = b"Archive notice=2E evidence attached=2E\r\nSecond line=2E"
NOTICE_RAW = b"Archive notice. evidence attached.\r\nSecond line."
PDF_BYTES = b"%PDF-1.4\n" + bytes(range(256)) * 4 + b"\n%%EOF\n"
CSV_BYTES = "name,值,note\r\nalpha,1,第一条\r\nbeta,2,第二条\r\n".encode("utf-8")
ZIP_BYTES = hashlib.sha256(b"mime-audit-seed").digest() * 40  # 1280 bytes
CSV_FILENAME = "data set 测.csv"
CSV_FILENAME_STAR = b"utf-8''data%20set%20%E6%B5%8B.csv"


def _b64(data):
    encoded = base64.b64encode(data)
    return b"\r\n".join(encoded[i:i + 76] for i in range(0, len(encoded), 76))


def build_valid_message():
    """Four levels deep, four leaves, three attachments."""
    return b"\r\n".join(
        [
            b"MIME-Version: 1.0",
            b'Content-Type: multipart/mixed; boundary="mix-1"',
            b"",
            b"preamble is ignored",
            b"--mix-1",
            b"Content-Type: text/plain; charset=utf-8",
            b"Content-Transfer-Encoding: quoted-printable",
            b"Content-Disposition: inline",
            b"",
            NOTICE_QP,
            b"--mix-1",
            b'Content-Type: multipart/related; boundary="rel-1"',
            b"",
            b"--rel-1",
            b"Content-Type: application/pdf",
            b"Content-Transfer-Encoding: base64",
            b'Content-Disposition: attachment; filename="report.pdf"',
            b"",
            _b64(PDF_BYTES),
            b"--rel-1",
            b'Content-Type: multipart/alternative; boundary="alt-1"',
            b"",
            b"--alt-1",
            b'Content-Type: text/csv; name="ignored-name.csv"',
            b"Content-Transfer-Encoding: base64",
            b"Content-Disposition: attachment; filename*=" + CSV_FILENAME_STAR,
            b"",
            _b64(CSV_BYTES),
            b"--alt-1--",
            b"--rel-1--",
            b"--mix-1",
            b"Content-Type: application/zip",
            b"Content-Transfer-Encoding: base64",
            b"Content-Disposition: attachment; filename=\"archive.zip\"; "
            b"filename*=utf-8''archive.zip",
            b"",
            _b64(ZIP_BYTES),
            b"--mix-1--",
            b"epilogue is ignored",
        ]
    )


def build_broken_boundary_message():
    """The root multipart is never closed."""
    lines = build_valid_message().split(b"\r\n")
    del lines[lines.index(b"--mix-1--")]
    return b"\r\n".join(lines)


def build_inner_broken_message():
    """The innermost multipart/alternative is never closed."""
    return build_valid_message().replace(
        b"\r\n--alt-1--\r\n", b"\r\n--alt-1\r\n"
    )


EXPECTED_ATTACHMENTS = [
    {
        "part": 3,
        "filename": "report.pdf",
        "media_type": "application/pdf",
        "size": len(PDF_BYTES),
        "sha256": hashlib.sha256(PDF_BYTES).hexdigest(),
    },
    {
        "part": 5,
        "filename": CSV_FILENAME,
        "media_type": "text/csv",
        "size": len(CSV_BYTES),
        "sha256": hashlib.sha256(CSV_BYTES).hexdigest(),
    },
    {
        "part": 6,
        "filename": "archive.zip",
        "media_type": "application/zip",
        "size": len(ZIP_BYTES),
        "sha256": hashlib.sha256(ZIP_BYTES).hexdigest(),
    },
]


# ---------------------------------------------------------------------------
# Message builders used by the unit tests
# ---------------------------------------------------------------------------

def simple_message(boundary=b"bound", ct=b"text/plain", cte=b"base64",
                   body=b"QUJD", disposition=b"attachment", filename=b"a.txt",
                   extra_cd_params=b""):
    lines = [
        b'Content-Type: multipart/mixed; boundary="' + boundary + b'"',
        b"",
        b"--" + boundary,
    ]
    if ct is not None:
        lines.append(b"Content-Type: " + ct)
    if cte is not None:
        lines.append(b"Content-Transfer-Encoding: " + cte)
    if disposition is not None:
        cd = b"Content-Disposition: " + disposition
        if filename is not None:
            cd += b'; filename="' + filename + b'"'
        cd += extra_cd_params
        lines.append(cd)
    lines += [b"", body, b"--" + boundary + b"--"]
    return b"\r\n".join(lines)


def deep_message(levels):
    """A chain of nested multiparts with a single leaf at depth `levels`."""
    bounds = [b"b%d" % i for i in range(levels)]
    lines = [b'Content-Type: multipart/mixed; boundary="' + bounds[0] + b'"', b""]
    for i in range(1, levels):
        lines.append(b"--" + bounds[i - 1])
        if i < levels - 1:
            lines.append(
                b'Content-Type: multipart/mixed; boundary="' + bounds[i] + b'"'
            )
            lines.append(b"")
        else:
            lines.append(b"Content-Type: text/plain")
            lines.append(b"Content-Transfer-Encoding: base64")
            lines.append(b"")
            lines.append(b"QUJD")
    for i in reversed(range(levels - 1)):
        lines.append(b"--" + bounds[i] + b"--")
    return b"\r\n".join(lines)


def many_leaves_message(count):
    lines = [b'Content-Type: multipart/mixed; boundary="b"', b""]
    for _ in range(count):
        lines += [
            b"--b",
            b"Content-Type: text/plain",
            b"Content-Transfer-Encoding: base64",
            b"",
            b"QUJD",
        ]
    lines.append(b"--b--")
    return b"\r\n".join(lines)


def two_attachments(cd_params_1, cd_params_2):
    def part(params):
        return [
            b"--b",
            b"Content-Type: text/plain",
            b"Content-Transfer-Encoding: base64",
            b"Content-Disposition: attachment; " + params,
            b"",
            b"QUJD",
        ]

    lines = [b'Content-Type: multipart/mixed; boundary="b"', b""]
    lines += part(cd_params_1) + part(cd_params_2) + [b"--b--"]
    return b"\r\n".join(lines)


# ---------------------------------------------------------------------------
# Unit tests for the strict parser
# ---------------------------------------------------------------------------

class ParserUnitTests(unittest.TestCase):
    def assert_error(self, data, code, part="skip"):
        with self.assertRaises(MimeAuditError) as caught:
            audit_message(data)
        self.assertEqual(caught.exception.code, code)
        if part != "skip":
            self.assertEqual(caught.exception.part, part)

    def attachments_of(self, data):
        return audit_message(data)["attachments"]

    # -- happy paths --------------------------------------------------
    def test_valid_nested_message(self):
        result = audit_message(build_valid_message())
        self.assertEqual(result["attachments"], EXPECTED_ATTACHMENTS)
        self.assertEqual(result["leaf_count"], 4)
        self.assertEqual(result["max_depth"], 4)

    def test_depth_four_accepted(self):
        self.assertEqual(audit_message(deep_message(4))["leaf_count"], 1)

    def test_64_leaves_accepted(self):
        self.assertEqual(audit_message(many_leaves_message(64))["leaf_count"], 64)

    def test_quoted_printable_decoding(self):
        attachments = self.attachments_of(
            simple_message(cte=b"quoted-printable", body=NOTICE_QP)
        )
        self.assertEqual(attachments[0]["size"], len(NOTICE_RAW))
        self.assertEqual(
            attachments[0]["sha256"], hashlib.sha256(NOTICE_RAW).hexdigest()
        )

    def test_quoted_printable_soft_break_and_escapes(self):
        attachments = self.attachments_of(
            simple_message(cte=b"quoted-printable", body=b"join=\r\ned =41=42")
        )
        self.assertEqual(attachments[0]["size"], len(b"joined AB"))

    def test_default_media_type_is_text_plain(self):
        attachments = self.attachments_of(simple_message(ct=None))
        self.assertEqual(attachments[0]["media_type"], "text/plain")

    def test_filename_star_utf8(self):
        attachments = self.attachments_of(
            simple_message(
                filename=None,
                extra_cd_params=b"; filename*=utf-8''data%20set%20%E6%B5%8B.csv",
            )
        )
        self.assertEqual(attachments[0]["filename"], CSV_FILENAME)

    def test_filename_normalised_to_nfc(self):
        attachments = self.attachments_of(
            simple_message(
                filename=None,
                extra_cd_params=b"; filename*=utf-8''%65%CC%81.txt",  # e + ´
            )
        )
        self.assertEqual(attachments[0]["filename"], "é.txt")

    def test_matching_filename_and_filename_star(self):
        attachments = self.attachments_of(
            simple_message(extra_cd_params=b"; filename*=utf-8''a.txt")
        )
        self.assertEqual(attachments[0]["filename"], "a.txt")

    def test_inline_part_with_filename_is_not_listed(self):
        result = audit_message(simple_message(disposition=b"inline"))
        self.assertEqual(result["attachments"], [])
        self.assertEqual(result["leaf_count"], 1)

    # -- message level ------------------------------------------------
    def test_message_too_large(self):
        self.assert_error(
            b"A" * (MAX_MESSAGE_SIZE + 1), "MESSAGE_TOO_LARGE", part=None
        )

    def test_empty_message(self):
        self.assert_error(b"", "EMPTY_MESSAGE", part=None)

    def test_non_crlf_line_endings(self):
        self.assert_error(
            b"Content-Type: multipart/mixed; boundary=x\n\n--x--",
            "NON_CRLF_LINE_ENDING",
            part=None,
        )

    def test_root_must_be_multipart_mixed(self):
        self.assert_error(
            b"Content-Type: text/plain\r\n\r\nQUJD",
            "ROOT_NOT_MULTIPART_MIXED",
            part=0,
        )
        self.assert_error(
            b"Content-Type: multipart/related; boundary=x\r\n\r\n--x--",
            "ROOT_NOT_MULTIPART_MIXED",
            part=0,
        )

    # -- headers --------------------------------------------------------
    def test_malformed_header(self):
        self.assert_error(
            b"Content-Type: multipart/mixed; boundary=b\r\nno colon here\r\n"
            b"\r\n--b--",
            "MALFORMED_HEADER",
            part=0,
        )

    def test_header_continuation_before_any_header(self):
        self.assert_error(
            b" folded\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b--",
            "MALFORMED_HEADER",
            part=0,
        )

    def test_duplicate_singular_header(self):
        self.assert_error(
            b"Content-Type: multipart/mixed; boundary=b\r\n"
            b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b--",
            "DUPLICATE_HEADER",
            part=0,
        )

    def test_unsupported_mime_version(self):
        self.assert_error(
            b"MIME-Version: 2.0\r\nContent-Type: multipart/mixed; boundary=b\r\n"
            b"\r\n--b--",
            "UNSUPPORTED_MIME_VERSION",
            part=0,
        )

    # -- structure ------------------------------------------------------
    def test_boundary_not_closed(self):
        self.assert_error(build_broken_boundary_message(), "BOUNDARY_NOT_CLOSED", part=0)

    def test_inner_boundary_not_closed_locates_part(self):
        self.assert_error(build_inner_broken_message(), "BOUNDARY_NOT_CLOSED", part=4)

    def test_boundary_delimiter_missing(self):
        self.assert_error(
            b'Content-Type: multipart/mixed; boundary="b"\r\n\r\nno delimiters',
            "BOUNDARY_DELIMITER_MISSING",
            part=0,
        )

    def test_empty_multipart(self):
        self.assert_error(
            b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b--',
            "EMPTY_MULTIPART",
            part=0,
        )

    def test_boundary_reused(self):
        self.assert_error(
            b"\r\n".join(
                [
                    b'Content-Type: multipart/mixed; boundary="dup"',
                    b"",
                    b"--dup",
                    b'Content-Type: multipart/mixed; boundary="dup"',
                    b"",
                    b"--dup",
                    b"Content-Type: text/plain",
                    b"Content-Transfer-Encoding: base64",
                    b"",
                    b"QUJD",
                    b"--dup--",
                    b"--dup--",
                ]
            ),
            "BOUNDARY_REUSED",
            part=1,
        )

    def test_ambiguous_boundary_line(self):
        self.assert_error(
            simple_message(cte=b"quoted-printable", body=b"--bound-x"),
            "AMBIGUOUS_BOUNDARY_LINE",
            part=0,
        )

    def test_missing_boundary_parameter(self):
        self.assert_error(
            b"Content-Type: multipart/mixed\r\n\r\n--b--",
            "MISSING_BOUNDARY",
            part=0,
        )

    def test_invalid_boundary(self):
        self.assert_error(
            b'Content-Type: multipart/mixed; boundary="' + b"x" * 71 + b'"\r\n\r\n',
            "INVALID_BOUNDARY",
            part=0,
        )
        self.assert_error(
            b'Content-Type: multipart/mixed; boundary="trailing "\r\n\r\n',
            "INVALID_BOUNDARY",
            part=0,
        )

    def test_duplicate_parameter(self):
        self.assert_error(
            b'Content-Type: multipart/mixed; boundary="a"; boundary="b"\r\n\r\n',
            "DUPLICATE_PARAMETER",
            part=0,
        )

    def test_max_depth_exceeded(self):
        self.assert_error(deep_message(5), "MAX_DEPTH_EXCEEDED", part=4)

    def test_too_many_leaves(self):
        self.assert_error(many_leaves_message(65), "TOO_MANY_LEAVES", part=65)

    def test_multipart_transfer_encoding(self):
        self.assert_error(
            b'Content-Type: multipart/mixed; boundary="b"\r\n'
            b"Content-Transfer-Encoding: base64\r\n\r\n--b--",
            "MULTIPART_TRANSFER_ENCODING",
            part=0,
        )

    # -- transfer encodings ---------------------------------------------
    def test_missing_transfer_encoding(self):
        self.assert_error(simple_message(cte=None), "MISSING_TRANSFER_ENCODING", part=1)

    def test_unsupported_transfer_encoding(self):
        self.assert_error(simple_message(cte=b"7bit"), "UNSUPPORTED_TRANSFER_ENCODING", part=1)
        self.assert_error(simple_message(cte=b"binary"), "UNSUPPORTED_TRANSFER_ENCODING", part=1)

    def test_invalid_base64(self):
        for body in (b"QUJD!", b"QUJ", b"TR==", b"QU JD", b"=AAA", b"A" * 77):
            self.assert_error(simple_message(body=body), "INVALID_BASE64", part=1)

    def test_invalid_quoted_printable(self):
        for body in (
            b"bad=GH",
            b"bad=A",
            b"trailing ",
            b"dangling=",
            b"8bit \xe9",
            b"ctrl \x01",
            b"x" * 77,
        ):
            self.assert_error(
                simple_message(cte=b"quoted-printable", body=body),
                "INVALID_QUOTED_PRINTABLE",
                part=1,
            )

    # -- filenames --------------------------------------------------------
    def test_missing_filename(self):
        self.assert_error(
            simple_message(filename=None), "MISSING_FILENAME", part=1
        )

    def test_empty_filename(self):
        self.assert_error(simple_message(filename=b""), "FILENAME_EMPTY", part=1)
        self.assert_error(simple_message(filename=b"  "), "FILENAME_EMPTY", part=1)

    def test_filename_path_components(self):
        for name in (b"../x", b"a/b", b"..", b"."):
            self.assert_error(
                simple_message(filename=name), "FILENAME_PATH_COMPONENT", part=1
            )
        self.assert_error(
            simple_message(filename=None, extra_cd_params=b"; filename*=utf-8''a%5Cb"),
            "FILENAME_PATH_COMPONENT",
            part=1,
        )

    def test_filename_mismatch(self):
        self.assert_error(
            simple_message(extra_cd_params=b"; filename*=utf-8''other.txt"),
            "FILENAME_MISMATCH",
            part=1,
        )

    def test_invalid_filename_star(self):
        for star in (
            b"; filename*=iso-8859-1''x.txt",
            b"; filename*=utf-8''%ff.txt",
            b"; filename*=utf-8''a*b.txt",
            b"; filename*=no-delimiters",
        ):
            self.assert_error(
                simple_message(filename=None, extra_cd_params=star),
                "INVALID_FILENAME_STAR",
                part=1,
            )

    def test_filename_continuation_unsupported(self):
        self.assert_error(
            simple_message(
                filename=None,
                extra_cd_params=b"; filename*0*=utf-8''a; filename*1*=b",
            ),
            "UNSUPPORTED_FILENAME_CONTINUATION",
            part=1,
        )

    def test_duplicate_filename(self):
        self.assert_error(
            two_attachments(b'filename="a.txt"', b'filename="a.txt"'),
            "DUPLICATE_FILENAME",
            part=2,
        )

    def test_duplicate_filename_after_normalisation(self):
        self.assert_error(
            two_attachments(
                b"filename*=utf-8''%C3%A9.txt",      # NFC é
                b"filename*=utf-8''e%CC%81.txt",     # NFD é
            ),
            "DUPLICATE_FILENAME",
            part=2,
        )


# ---------------------------------------------------------------------------
# Integration tests against the running HTTP service
# ---------------------------------------------------------------------------

class HttpIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deadline = time.time() + 60
        while True:
            try:
                with urllib.request.urlopen(APP_URL + "/healthz", timeout=2) as resp:
                    if resp.status == 200:
                        return
            except Exception:
                pass
            if time.time() > deadline:
                raise RuntimeError("service at %s did not become healthy" % APP_URL)
            time.sleep(1)

    def post(self, body, content_type="message/rfc822"):
        request = urllib.request.Request(
            APP_URL + "/api/mime/audit",
            data=body,
            headers={"Content-Type": content_type},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_health_endpoint(self):
        with urllib.request.urlopen(APP_URL + "/healthz", timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read()), {"status": "ok"})

    def test_valid_nested_message(self):
        status, payload = self.post(build_valid_message())
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["attachments"], EXPECTED_ATTACHMENTS)
        self.assertEqual(payload["attachment_count"], 3)
        self.assertEqual(payload["leaf_count"], 4)
        self.assertEqual(payload["max_depth"], 4)

    def test_valid_message_is_deterministic(self):
        first = self.post(build_valid_message())
        second = self.post(build_valid_message())
        self.assertEqual(first, second)

    def test_corrupted_root_boundary(self):
        status, payload = self.post(build_broken_boundary_message())
        self.assertEqual(status, 422, payload)
        self.assertEqual(payload["error"]["code"], "BOUNDARY_NOT_CLOSED")
        self.assertEqual(payload["error"]["part"], 0)
        self.assertNotIn("attachments", payload)

    def test_corrupted_inner_boundary_locates_part(self):
        status, payload = self.post(build_inner_broken_message())
        self.assertEqual(status, 422, payload)
        self.assertEqual(payload["error"]["code"], "BOUNDARY_NOT_CLOSED")
        self.assertEqual(payload["error"]["part"], 4)
        self.assertNotIn("attachments", payload)

    def test_non_crlf_message_rejected(self):
        status, payload = self.post(build_valid_message().replace(b"\r\n", b"\n"))
        self.assertEqual(status, 422, payload)
        self.assertEqual(payload["error"]["code"], "NON_CRLF_LINE_ENDING")
        self.assertNotIn("attachments", payload)

    def test_oversized_message_rejected(self):
        status, payload = self.post(b"A" * (MAX_MESSAGE_SIZE + 1))
        self.assertEqual(status, 413, payload)
        self.assertEqual(payload["error"]["code"], "MESSAGE_TOO_LARGE")

    def test_wrong_request_content_type(self):
        status, payload = self.post(build_valid_message(), content_type="text/plain")
        self.assertEqual(status, 415, payload)
        self.assertEqual(payload["error"]["code"], "INVALID_REQUEST_CONTENT_TYPE")

    def test_unknown_endpoint(self):
        try:
            with urllib.request.urlopen(APP_URL + "/nope", timeout=5) as response:
                self.fail("expected 404, got %d" % response.status)
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 404)


def main():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(ParserUnitTests))
    suite.addTests(loader.loadTestsFromTestCase(HttpIntegrationTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        "verify: %d tests, %d failures, %d errors"
        % (result.testsRun, len(result.failures), len(result.errors))
    )
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
