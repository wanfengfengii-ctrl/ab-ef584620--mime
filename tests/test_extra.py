"""Additional adversarial ambiguity tests for the strict parser."""

import unittest

from mimeaudit import MimeAuditError, audit_message

from tests.test_audit import (
    attachment_part,
    leaf_with,
    message,
    mixed,
    mixed_entity,
)

CRLF = "\r\n"


class AmbiguityTests(unittest.TestCase):
    def assert_code(self, data, code):
        with self.assertRaises(MimeAuditError) as ctx:
            audit_message(data)
        self.assertEqual(ctx.exception.code, code)

    def test_boundary_transport_padding_rejected(self):
        body = f"--ROOT {CRLF}" + attachment_part("a", b"a") + CRLF + f"--ROOT--{CRLF}"
        msg = (
            "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=ROOT\r\n\r\n"
        ).encode() + body.encode()
        self.assert_code(msg, "BOUNDARY_DELIMITER_INVALID")

    def test_boundary_ending_in_space_rejected(self):
        msg = (
            "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"ab \"\r\n\r\n"
        ).encode()
        self.assert_code(msg, "BOUNDARY_INVALID")

    def test_fullwidth_slash_becomes_path_component(self):
        # U+FF0F FULLWIDTH SOLIDUS NFKC-folds to '/'.
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename*=UTF-8''a%EF%BC%8Fb",
            ],
            "AAAA",
        )
        self.assert_code(message(mixed("ROOT", [part])), "FILENAME_PATH_COMPONENT")

    def test_nfkc_duplicate_filename_rejected(self):
        # "&#64257;le.txt" uses the ligature U+FB01 which NFKC-folds to "fi".
        lig = "Content-Disposition: attachment; filename*=UTF-8''%EF%AC%81le.txt"
        p1 = leaf_with(
            ["Content-Type: text/plain", "Content-Transfer-Encoding: base64", lig],
            "AAAA",
        )
        p2 = attachment_part("file.txt", b"bb")
        with self.assertRaises(MimeAuditError) as ctx:
            audit_message(message(mixed("ROOT", [p1, p2])))
        self.assertEqual(ctx.exception.code, "DUPLICATE_FILENAME")

    def test_nested_message_rfc822_rejected(self):
        inner = "MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nx"
        part = CRLF.join(
            [
                "Content-Type: message/rfc822",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename=m.eml",
                "",
                "AAAA",
            ]
        )
        self.assert_code(message(mixed("ROOT", [part])), "UNSUPPORTED_MEDIA_TYPE")

    def test_missing_mime_version_rejected(self):
        body = mixed("ROOT", [attachment_part("a", b"a")])
        msg = b"Content-Type: multipart/mixed; boundary=ROOT\r\n\r\n" + body.encode()
        self.assert_code(msg, "MIME_VERSION_REQUIRED")

    def test_duplicate_boundary_parameter_rejected(self):
        head = (
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary=A; boundary="A"\r\n\r\n'
        ).encode()
        self.assert_code(head + b"--A\r\n", "DUPLICATE_PARAMETER")

    def test_part_ordinal_nested(self):
        # A bad CTE inside a valid surrounding structure is located precisely.
        bad = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: 8bit",
                "Content-Disposition: attachment; filename=bad",
            ],
            "x",
        )
        good = attachment_part("ok", b"ok")

        inner = mixed_entity("IN", [good, bad])  # good=part2, bad=part3
        with self.assertRaises(MimeAuditError) as ctx:
            audit_message(message(mixed("ROOT", [inner])))
        self.assertEqual(ctx.exception.code, "CTE_NOT_ALLOWED")
        self.assertEqual(ctx.exception.part, 3)

    def test_rfc2047_encoded_word_filename_rejected(self):
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename=\"=?UTF-8?B?YWJj?=.txt\"",
            ],
            "AAAA",
        )
        self.assert_code(message(mixed("ROOT", [part])), "FILENAME_ENCODED_WORD")

    def test_folded_header_physical_line_limit(self):
        # One very long folded physical line must still be rejected.
        long_ws = " " + "x" * 1000
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename=ok",
                f"X-Comment:{long_ws}",
            ],
            "AAAA",
        )
        self.assert_code(message(mixed("ROOT", [part])), "HEADER_LINE_TOO_LONG")

    def test_content_type_name_parameter_rejected(self):
        part = leaf_with(
            [
                "Content-Type: text/plain; name=x.txt",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename=x.txt",
            ],
            "AAAA",
        )
        self.assert_code(message(mixed("ROOT", [part])), "NAME_PARAMETER_NOT_ALLOWED")

    def test_noncanonical_base64_pad_bits_rejected(self):
        # "AB==" decodes to one byte with 4 residual nonzero bits -> rejected.
        part = leaf_with(
            [
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: base64",
                "Content-Disposition: attachment; filename=x",
            ],
            "AB==",
        )
        self.assert_code(message(mixed("ROOT", [part])), "INVALID_BASE64")


if __name__ == "__main__":
    unittest.main(verbosity=2)
