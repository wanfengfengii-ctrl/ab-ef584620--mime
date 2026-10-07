"""Strict-parser unit tests (stdlib unittest; ``python -m unittest -v``)."""

import base64
import hashlib
import unittest

from mimeaudit import MimeAuditError, audit_message
from mimeaudit.parser import MAX_MESSAGE_BYTES

CRLF = "\r\n"


def b64line(raw: bytes) -> str:
    # encodebytes() wraps every 76 chars using bare LF; normalise to CRLF
    # and drop the final line break (part bodies omit their body's CRLF).
    encoded = base64.encodebytes(raw).replace(b"\n", b"\r\n").rstrip(b"\r\n")
    return encoded.decode("ascii")


def attachment_part(filename, payload, media="text/plain", filename_star=None):
    cd = f"Content-Disposition: attachment; filename={filename}"
    if filename_star is not None:
        cd += f"; filename*=UTF-8''{filename_star}"
    return CRLF.join(
        [
            f"Content-Type: {media}",
            "Content-Transfer-Encoding: base64",
            cd,
            "",
            b64line(payload),
        ]
    )


def inline_part(payload=b"hello", media="text/plain", cte="base64", raw_body=None):
    if raw_body is None:
        raw_body = b64line(payload) if cte == "base64" else payload.decode("ascii")
    return CRLF.join(
        [f"Content-Type: {media}", f"Content-Transfer-Encoding: {cte}", "", raw_body]
    )


def mixed(boundary, children, prologue="", epilogue=""):
    body = prologue
    for child in children:
        body += f"--{boundary}{CRLF}" + child + CRLF
    body += f"--{boundary}--{CRLF}" + epilogue
    return body


def mixed_entity(boundary, children):
    """A nested multipart *entity*: its own headers plus the multipart body."""
    return CRLF.join(
        [
            f"Content-Type: multipart/mixed; boundary={boundary}",
            "",
            mixed(boundary, children).rstrip(CRLF),
        ]
    )


def message(root_body, boundary="ROOT"):
    # The two trailing empty strings produce the header-terminating CRLFCRLF.
    head = CRLF.join(
        ["MIME-Version: 1.0", f"Content-Type: multipart/mixed; boundary={boundary}", "", ""]
    )
    return (head + root_body).encode("utf-8")


def leaf_with(headers, body):
    return CRLF.join([*headers, "", body])


class ValidMessageTests(unittest.TestCase):
    def test_two_attachments_manifest_matches_decoded_bytes(self):
        payload_a = b"archive evidence block A"
        payload_b = bytes(range(256))
        msg = message(
            mixed(
                "ROOT",
                [
                    attachment_part("a.txt", payload_a),
                    attachment_part("b.bin", payload_b, media="application/octet-stream"),
                ],
            )
        )
        result = audit_message(msg)
        atts = result["attachments"]
        self.assertEqual(
            atts,
            [
                {
                    "part": 1,
                    "filename": "a.txt",
                    "media_type": "text/plain",
                    "size": len(payload_a),
                    "sha256": hashlib.sha256(payload_a).hexdigest(),
                },
                {
                    "part": 2,
                    "filename": "b.bin",
                    "media_type": "application/octet-stream",
                    "size": len(payload_b),
                    "sha256": hashlib.sha256(payload_b).hexdigest(),
                },
            ],
        )

    def test_nesting_depth_four_dfs_order(self):
        # root(depth1) > B1(depth2) > B2(depth3) > B3(depth4) > attachment
        node = attachment_part("deep.txt", b"deep")
        for b in ("B3", "B2", "B1"):
            node = mixed_entity(b, [node])
        msg = message(mixed("ROOT", [node]))
        atts = audit_message(msg)["attachments"]
        self.assertEqual([a["part"] for a in atts], [4])
        self.assertEqual(atts[0]["filename"], "deep.txt")
        self.assertEqual(atts[0]["size"], 4)

    def test_dfs_order_across_branches(self):
        a = attachment_part("a", b"a")
        b = attachment_part("b", b"b")
        c = attachment_part("c", b"c")
        inner = mixed_entity("IN", [b, c])
        msg = message(mixed("ROOT", [a, inner]))
        atts = audit_message(msg)["attachments"]
        self.assertEqual([x["filename"] for x in atts], ["a", "b", "c"])
        self.assertEqual([x["part"] for x in atts], [1, 3, 4])

    def test_quoted_printable_attachment(self):
        payload = b"caf=\xe9 123"
        part = leaf_with(
            [
                "Content-Type: application/octet-stream",
                "Content-Transfer-Encoding: quoted-printable",
                "Content-Disposition: attachment; filename=q.bin",
            ],
            "caf=3D=E9 123",
        )
        atts = audit_message(message(mixed("ROOT", [part])))["attachments"]
        self.assertEqual(atts[0]["size"], len(payload))
        self.assertEqual(atts[0]["sha256"], hashlib.sha256(payload).hexdigest())

    def test_quoted_printable_soft_break(self):
        # "line one\r\nline two" with a soft break inside the first segment.
        part = leaf_with(
            [
                "Content-Type: application/octet-stream",
                "Content-Transfer-Encoding: quoted-printable",
                "Content-Disposition: attachment; filename=q2.bin",
            ],
            "line o=\r\nne\r\nline two",
        )
        atts = audit_message(message(mixed("ROOT", [part])))["attachments"]
        self.assertEqual(atts[0]["size"], len(b"line one\r\nline two"))

    def test_qp_soft_break_with_trailing_space(self):
        # "...abc <space>" joined across a soft break becomes interior space.
        part = leaf_with(
            [
                "Content-Type: application/octet-stream",
                "Content-Transfer-Encoding: quoted-printable",
                "Content-Disposition: attachment; filename=q3.bin",
            ],
            "abc =\r\ndef",
        )
        atts = audit_message(message(mixed("ROOT", [part])))["attachments"]
        self.assertEqual(atts[0]["size"], len(b"abc def"))

    def test_filename_star_utf8(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename*=UTF-8''%E2%82%AC%E2%82%AC",
            ],
            "AAAA",
        )
        atts = audit_message(message(mixed("ROOT", [part])))["attachments"]
        self.assertEqual(atts[0]["filename"], "€€")

    def test_filename_and_star_agree(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename=report; filename*=UTF-8''report",
            ],
            "AAAA",
        )
        atts = audit_message(message(mixed("ROOT", [part])))["attachments"]
        self.assertEqual(atts[0]["filename"], "report")

    def test_deterministic_output(self):
        msg = message(
            mixed("ROOT", [attachment_part("x.txt", b"xyz"), attachment_part("y.txt", b"abc")])
        )
        self.assertEqual(audit_message(msg), audit_message(msg))

    def test_inline_body_allowed(self):
        msg = message(mixed("ROOT", [inline_part(b"body"), attachment_part("f", b"f")]))
        atts = audit_message(msg)["attachments"]
        self.assertEqual([a["filename"] for a in atts], ["f"])

    def test_stdlib_encoded_multiline_base64_is_accepted(self):
        import base64 as _b64

        payload = bytes((i % 251 for i in range(5000)))
        encoded = _b64.encodebytes(payload).replace(b"\n", b"\r\n").rstrip(b"\r\n")
        self.assertGreater(encoded.count(b"\r\n"), 0)  # genuinely multi-line
        part = CRLF.join(
            [
                "Content-Type: application/octet-stream",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename=blob.bin",
                "",
                encoded.decode("ascii"),
            ]
        )
        atts = audit_message(message(mixed("ROOT", [part])))["attachments"]
        self.assertEqual(atts[0]["size"], 5000)
        self.assertEqual(atts[0]["sha256"], hashlib.sha256(payload).hexdigest())

    def test_stdlib_encoded_multiline_qp_is_accepted(self):
        import quopri

        # RFC 2045 compliant payload: no raw CR/LF (those must appear only as
        # line breaks); quopri would otherwise emit a non-compliant bare CR.
        safe = bytes(v for v in range(256) if v not in (10, 13))
        payload = (safe * 13)[:3000]
        encoded = quopri.encodestring(payload).replace(b"\n", b"\r\n").rstrip(b"\r\n")
        self.assertGreater(encoded.count(b"\r\n"), 0)
        part = CRLF.join(
            [
                "Content-Type: application/octet-stream",
                "Content-Transfer-Encoding: quoted-printable",
                "Content-Disposition: attachment; filename=blob.qp",
                "",
                encoded.decode("ascii"),
            ]
        )
        atts = audit_message(message(mixed("ROOT", [part])))["attachments"]
        self.assertEqual(atts[0]["size"], 3000)
        self.assertEqual(atts[0]["sha256"], hashlib.sha256(payload).hexdigest())


class InvalidMessageTests(unittest.TestCase):
    def assert_code(self, data, code):
        with self.assertRaises(MimeAuditError) as ctx:
            audit_message(data)
        self.assertEqual(ctx.exception.code, code)
        return ctx.exception

    def test_qp_raw_cr_is_rejected(self):
        # A literal CR inside encoded data (rather than =0D) is ambiguous and
        # must be rejected before any manifest is produced.
        part = leaf_with(
            [
                "Content-Type: application/octet-stream",
                "Content-Transfer-Encoding: quoted-printable",
                "Content-Disposition: attachment; filename=x",
            ],
            "ab\rcd",
        )
        self.assert_code(message(mixed("ROOT", [part])), "BARE_EOL")

    def test_qp_hard_line_trailing_space_rejected(self):
        part = leaf_with(
            [
                "Content-Type: application/octet-stream",
                "Content-Transfer-Encoding: quoted-printable",
                "Content-Disposition: attachment; filename=q4.bin",
            ],
            "abc ",
        )
        self.assert_code(message(mixed("ROOT", [part])), "INVALID_QUOTED_PRINTABLE")

    def test_bare_lf_rejected(self):
        msg = message(mixed("ROOT", [attachment_part("a", b"a")]))
        self.assert_code(msg.replace(b"\r\n", b"\n"), "BARE_EOL")

    def test_bare_cr_rejected(self):
        msg = message(mixed("ROOT", [attachment_part("a", b"a")]))
        self.assert_code(msg.replace(b"\r\n", b"\r"), "BARE_EOL")

    def test_unclosed_boundary_rejected(self):
        body = f"--ROOT{CRLF}" + attachment_part("a", b"a") + CRLF
        msg = (
            "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=ROOT\r\n\r\n"
        ).encode() + body.encode()
        self.assert_code(msg, "BOUNDARY_NOT_CLOSED")

    def test_epilogue_garbage_rejected(self):
        good = message(mixed("ROOT", [attachment_part("a", b"a")]))
        bad = good.replace(b"--ROOT--\r\n", b"--ROOT--\r\njunk\r\n")
        self.assert_code(bad, "BOUNDARY_TRAILING_GARBAGE")

    def test_boundary_prefix_collision_does_not_confuse_parser(self):
        leaf = attachment_part("z", b"z")
        inner = mixed_entity("B1X", [leaf])
        after = attachment_part("after", b"a")
        # A sibling after the nested part exercises search-cursor reset.
        msg = message(mixed("B1", [inner, after]), boundary="B1")
        atts = audit_message(msg)["attachments"]
        self.assertEqual([a["filename"] for a in atts], ["z", "after"])

    def test_duplicate_closing_delimiter_rejected(self):
        good = message(mixed("ROOT", [attachment_part("a", b"a")]))
        bad = good.replace(b"--ROOT--\r\n", b"--ROOT--\r\n--ROOT--\r\n")
        self.assert_code(bad, "BOUNDARY_TRAILING_GARBAGE")

    def test_boundary_reuse_rejected(self):
        leaf_a = attachment_part("a", b"a")
        leaf_b = attachment_part("b", b"b")
        # Two sibling multiparts share boundary X; the root (boundary ROOT)
        # frames them unambiguously, so the second sibling's header fires the
        # reuse check at its own part ordinal.
        sibling_one = mixed_entity("X", [leaf_a])  # parts 1 (multipart), 2 (leaf)
        sibling_two = mixed_entity("X", [leaf_b])  # part 3 -> reuse
        msg = message(mixed("ROOT", [sibling_one, sibling_two]))
        exc = self.assert_code(msg, "BOUNDARY_REUSE")
        self.assertEqual(exc.part, 3)

    def test_root_not_mixed(self):
        msg = b"MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
        self.assert_code(msg, "ROOT_NOT_MULTIPART_MIXED")

    def test_nested_alternative_rejected(self):
        inner_body = f"--A{CRLF}" + inline_part(b"x") + CRLF + f"--A--{CRLF}"
        part = CRLF.join(["Content-Type: multipart/alternative; boundary=A", "", inner_body])
        self.assert_code(message(mixed("ROOT", [part])), "MULTIPART_SUBTYPE_NOT_MIXED")

    def test_depth_exceeded(self):
        node = attachment_part("deep", b"x")
        for i in range(4):  # four nested multiparts below root -> depth 5
            node = mixed_entity(f"D{i}", [node])
        self.assert_code(message(mixed("ROOT", [node])), "NESTED_DEPTH_EXCEEDED")

    def test_too_many_leaves(self):
        children = [attachment_part(f"f{i:03d}", b"x") for i in range(65)]
        self.assert_code(message(mixed("ROOT", children)), "TOO_MANY_LEAF_PARTS")

    def test_duplicate_filename_rejected(self):
        msg = message(
            mixed("ROOT", [attachment_part("dup.txt", b"1"), attachment_part("dup.txt", b"2")])
        )
        exc = self.assert_code(msg, "DUPLICATE_FILENAME")
        self.assertEqual(exc.part, 2)

    def test_path_component_filename_rejected(self):
        for name in ('"../evil"', '"a/b"', '"a\\\\b"', '".."', '"."'):
            self.assert_code(
                message(mixed("ROOT", [attachment_part(name, b"x")])),
                "FILENAME_PATH_COMPONENT",
            )

    def test_empty_filename_rejected(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                'Content-Disposition: attachment; filename=""',
            ],
            "AAAA",
        )
        self.assert_code(message(mixed("ROOT", [part])), "FILENAME_EMPTY")

    def test_missing_filename_rejected(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment",
            ],
            "AAAA",
        )
        self.assert_code(message(mixed("ROOT", [part])), "MISSING_FILENAME")

    def test_filename_star_wrong_charset(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename*=ISO-8859-1''%E9",
            ],
            "AAAA",
        )
        self.assert_code(message(mixed("ROOT", [part])), "FILENAME_STAR_CHARSET")

    def test_filename_star_bad_utf8(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename*=UTF-8''%FF",
            ],
            "AAAA",
        )
        self.assert_code(message(mixed("ROOT", [part])), "FILENAME_STAR_ENCODING")

    def test_filename_mismatch(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename=euro; filename*=UTF-8''%E2%82%AC",
            ],
            "AAAA",
        )
        self.assert_code(message(mixed("ROOT", [part])), "FILENAME_MISMATCH")

    def test_bad_base64_illegal_char(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename=x",
            ],
            "AA!=",
        )
        self.assert_code(message(mixed("ROOT", [part])), "INVALID_BASE64")

    def test_bad_base64_length(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename=x",
            ],
            "AAA",
        )
        self.assert_code(message(mixed("ROOT", [part])), "INVALID_BASE64")

    def test_bad_base64_padding_position(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename=x",
            ],
            "AA=A",
        )
        self.assert_code(message(mixed("ROOT", [part])), "INVALID_BASE64")

    def test_sevenbit_body_rejected(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: 7bit",
                "Content-Disposition: attachment; filename=x",
            ],
            "hello",
        )
        self.assert_code(message(mixed("ROOT", [part])), "CTE_NOT_ALLOWED")

    def test_missing_cte_rejected(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Disposition: attachment; filename=x",
            ],
            "AAAA",
        )
        self.assert_code(message(mixed("ROOT", [part])), "CTE_NOT_ALLOWED")

    def test_bad_quoted_printable(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: quoted-printable",
                "Content-Disposition: attachment; filename=x",
            ],
            "caf=ZZ",
        )
        self.assert_code(message(mixed("ROOT", [part])), "INVALID_QUOTED_PRINTABLE")

    def test_non_attachment_with_filename(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                'Content-Disposition: inline; filename="x"',
            ],
            "AAAA",
        )
        self.assert_code(message(mixed("ROOT", [part])), "FILENAME_ON_NON_ATTACHMENT")

    def test_oversize_rejected(self):
        payload = b"x" * (MAX_MESSAGE_BYTES + 1)
        self.assert_code(
            message(mixed("ROOT", [attachment_part("big.bin", payload)])),
            "MESSAGE_TOO_LARGE",
        )

    def test_multipart_with_cte_rejected(self):
        inner = f"--A{CRLF}" + inline_part(b"x") + CRLF + f"--A--{CRLF}"
        part = CRLF.join(
            [
                "Content-Type: multipart/mixed; boundary=A",
                "Content-Transfer-Encoding: base64",
                "",
                inner,
            ]
        )
        self.assert_code(message(mixed("ROOT", [part])), "MULTIPART_CTE_FORBIDDEN")

    def test_preamble_rejected(self):
        body = f"preamble text{CRLF}--ROOT{CRLF}"
        body += attachment_part("a", b"a") + CRLF + f"--ROOT--{CRLF}"
        msg = (
            "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=ROOT\r\n\r\n"
        ).encode() + body.encode()
        self.assert_code(msg, "PREAMBLE_NOT_EMPTY")

    def test_duplicate_header_rejected(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename=x",
            ],
            "AAAA",
        )
        self.assert_code(message(mixed("ROOT", [part])), "DUPLICATE_HEADER")

    def test_rfc2231_continuation_rejected(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename*0=ab; filename*1=cd",
            ],
            "AAAA",
        )
        self.assert_code(message(mixed("ROOT", [part])), "PARAM_CONTINUATION_UNSUPPORTED")

    def test_error_locates_part_ordinal(self):
        good = attachment_part("ok", b"ok")
        bad = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: 7bit",
                "Content-Disposition: attachment; filename=bad",
            ],
            "x",
        )
        msg = message(mixed("ROOT", [good, bad]))
        with self.assertRaises(MimeAuditError) as ctx:
            audit_message(msg)
        self.assertEqual(ctx.exception.code, "CTE_NOT_ALLOWED")
        self.assertEqual(ctx.exception.part, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
