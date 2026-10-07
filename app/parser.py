"""Strict MIME auditor for the research archiving platform.

The auditor accepts a raw RFC 822 message only when its MIME hierarchy,
boundaries and transfer encodings have exactly one interpretation, so the
bytes an email client would save cannot diverge from the archived evidence.
Anything ambiguous or non-canonical rejects the whole message; no partial
attachment list is ever produced.

Rules enforced (see README.md for the full contract):
  * the whole message uses CRLF line endings exclusively;
  * the root entity is multipart/mixed, nesting depth <= 4 (root = depth 1),
    at most 64 leaf entities;
  * multipart boundaries are syntactically valid, properly closed, never
    reused anywhere in the message, and never appear as a line prefix inside
    a body (no delimiter look-alikes);
  * every leaf body uses explicit, strict base64 (canonical alphabet,
    padding and zero pad bits, <= 76 chars per line) or strict
    quoted-printable (valid =XX escapes, soft breaks, no trailing
    whitespace, no raw 8-bit/control bytes, <= 76 chars per line);
  * attachments are exactly the leaf parts with
    ``Content-Disposition: attachment`` and a filename taken from ``filename``
    or a UTF-8 ``filename*`` (RFC 2231 single-section form); when both are
    present their decoded values must be identical. Normalised filenames
    (NFC, trimmed) must be non-empty, free of path components and unique.
"""

import base64
import binascii
import hashlib
import re
import unicodedata

from .errors import MimeAuditError

MAX_MESSAGE_SIZE = 4 * 1024 * 1024  # 4 MiB, hard request limit
MAX_DEPTH = 4                       # root entity counts as depth 1
MAX_LEAVES = 64                     # non-multipart entities per message
MAX_ENCODED_LINE = 76               # base64 / quoted-printable content lines

_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_B64_LINE_RE = re.compile(rb"^[A-Za-z0-9+/]*={0,2}$")
_BCHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()+_,-./:=? "
)
_HEXCHARS = frozenset("0123456789abcdefABCDEF")
_ATTR_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$&+-.^_`|~"
)
_FILENAME_CONT_RE = re.compile(r"^filename\*\d+\*?$")
_SINGULAR_HEADERS = (
    "content-type",
    "content-disposition",
    "content-transfer-encoding",
    "mime-version",
)


class _Context:
    """Mutable state for a single audit pass (never shared across requests)."""

    __slots__ = (
        "next_part",
        "boundaries",
        "leaf_count",
        "max_depth",
        "attachments",
        "filenames",
    )

    def __init__(self):
        self.next_part = 0       # pre-order entity index, root = 0
        self.boundaries = set()  # every boundary used in the message
        self.leaf_count = 0
        self.max_depth = 0
        self.attachments = []
        self.filenames = set()

    def alloc_part(self):
        index = self.next_part
        self.next_part += 1
        return index


def audit_message(data):
    """Audit raw message bytes.

    Returns a JSON-serialisable dict on success; raises MimeAuditError on the
    first violation found (deterministic for a given input).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    data = bytes(data)
    if len(data) > MAX_MESSAGE_SIZE:
        raise MimeAuditError(
            "MESSAGE_TOO_LARGE",
            "message is %d bytes, limit is %d" % (len(data), MAX_MESSAGE_SIZE),
            part=None,
            status=413,
        )
    if not data:
        raise MimeAuditError("EMPTY_MESSAGE", "message is empty", part=None)
    collapsed = data.replace(b"\r\n", b"")
    if b"\r" in collapsed or b"\n" in collapsed:
        raise MimeAuditError(
            "NON_CRLF_LINE_ENDING",
            "message contains a bare CR or LF; every line must end with CRLF",
            part=None,
        )
    lines = data.split(b"\r\n")
    ctx = _Context()
    _parse_entity(lines, 0, len(lines), depth=1, is_root=True, ctx=ctx)
    return {
        "attachments": ctx.attachments,
        "attachment_count": len(ctx.attachments),
        "leaf_count": ctx.leaf_count,
        "max_depth": ctx.max_depth,
    }


# ---------------------------------------------------------------------------
# Entity parsing
# ---------------------------------------------------------------------------

def _parse_entity(lines, start, end, depth, is_root, ctx):
    part = ctx.alloc_part()
    if depth > MAX_DEPTH:
        raise MimeAuditError(
            "MAX_DEPTH_EXCEEDED",
            "MIME nesting depth %d exceeds the limit of %d" % (depth, MAX_DEPTH),
            part,
        )
    if depth > ctx.max_depth:
        ctx.max_depth = depth

    headers, body_start = _parse_headers(lines, start, end, part)
    _check_header_multiplicity(headers, part)

    mime_version = _header_value(headers, "mime-version")
    if mime_version is not None and mime_version.strip() != "1.0":
        raise MimeAuditError(
            "UNSUPPORTED_MIME_VERSION",
            "unsupported MIME-Version %r" % mime_version.strip(),
            part,
        )

    ct_raw = _header_value(headers, "content-type")
    if ct_raw is None:
        maintype, subtype, ct_params = "text", "plain", {}
    else:
        (maintype, subtype), ct_params = _parse_content_type(ct_raw, part)
    media_type = "%s/%s" % (maintype, subtype)

    if is_root and media_type != "multipart/mixed":
        raise MimeAuditError(
            "ROOT_NOT_MULTIPART_MIXED",
            "root entity must be multipart/mixed, got %s" % media_type,
            part,
        )

    cte_raw = _header_value(headers, "content-transfer-encoding")
    cte = cte_raw.strip().lower() if cte_raw is not None else None

    if maintype == "multipart":
        if cte is not None and cte not in ("7bit", "8bit", "binary"):
            raise MimeAuditError(
                "MULTIPART_TRANSFER_ENCODING",
                "multipart entity must not use Content-Transfer-Encoding %r" % cte,
                part,
            )
        boundary = ct_params.get("boundary")
        if boundary is None:
            raise MimeAuditError(
                "MISSING_BOUNDARY",
                "multipart entity %s has no boundary parameter" % media_type,
                part,
            )
        _validate_boundary(boundary, part)
        if boundary in ctx.boundaries:
            raise MimeAuditError(
                "BOUNDARY_REUSED",
                "boundary %r is used more than once in the message" % boundary,
                part,
            )
        ctx.boundaries.add(boundary)
        regions = _split_regions(lines, body_start, end, boundary.encode("ascii"), part)
        for region_start, region_end in regions:
            _parse_entity(lines, region_start, region_end, depth + 1, False, ctx)
        return

    # Leaf entity.
    ctx.leaf_count += 1
    if ctx.leaf_count > MAX_LEAVES:
        raise MimeAuditError(
            "TOO_MANY_LEAVES",
            "message has more than %d leaf parts" % MAX_LEAVES,
            part,
        )
    if cte is None:
        raise MimeAuditError(
            "MISSING_TRANSFER_ENCODING",
            "leaf part has no Content-Transfer-Encoding; only explicit "
            "base64 or quoted-printable is accepted",
            part,
        )
    body = b"\r\n".join(lines[body_start:end])
    if cte == "base64":
        decoded = _decode_base64(body, part)
    elif cte == "quoted-printable":
        decoded = _decode_quoted_printable(body, part)
    else:
        raise MimeAuditError(
            "UNSUPPORTED_TRANSFER_ENCODING",
            "unsupported Content-Transfer-Encoding %r; only base64 or "
            "quoted-printable is accepted" % cte,
            part,
        )

    cd_raw = _header_value(headers, "content-disposition")
    disposition, cd_params = None, {}
    if cd_raw is not None:
        disposition, cd_params = _parse_content_disposition(cd_raw, part)
    if disposition == "attachment":
        filename = _normalize_filename(_extract_filename(cd_params, part), part)
        if filename in ctx.filenames:
            raise MimeAuditError(
                "DUPLICATE_FILENAME",
                "duplicate attachment filename %r" % filename,
                part,
            )
        ctx.filenames.add(filename)
        ctx.attachments.append(
            {
                "part": part,
                "filename": filename,
                "media_type": media_type,
                "size": len(decoded),
                "sha256": hashlib.sha256(decoded).hexdigest(),
            }
        )


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------

def _parse_headers(lines, start, end, part):
    """Parse lines[start:end] into (headers, body_start_index)."""
    headers = []
    name = None
    value_lines = []

    def flush():
        nonlocal name, value_lines
        if name is not None:
            headers.append((name, " ".join(value_lines).strip()))
        name = None
        value_lines = []

    i = start
    while i < end:
        line = lines[i]
        if line == b"":
            break
        for byte in line:
            if byte != 0x09 and (byte < 0x20 or byte > 0x7E):
                raise MimeAuditError(
                    "MALFORMED_HEADER",
                    "header contains control or non-ASCII bytes",
                    part,
                )
        if line[:1] in (b" ", b"\t"):
            if name is None:
                raise MimeAuditError(
                    "MALFORMED_HEADER",
                    "continuation line before any header",
                    part,
                )
            value_lines.append(line.decode("ascii").strip())
        else:
            flush()
            raw_name, sep, raw_value = line.partition(b":")
            if not sep:
                raise MimeAuditError(
                    "MALFORMED_HEADER",
                    "header line without ':' separator",
                    part,
                )
            decoded_name = raw_name.decode("ascii")
            if not _TOKEN_RE.match(decoded_name):
                raise MimeAuditError(
                    "MALFORMED_HEADER",
                    "invalid header name %r" % decoded_name,
                    part,
                )
            name = decoded_name.lower()
            value_lines = [raw_value.decode("ascii").strip()]
        i += 1
    else:
        raise MimeAuditError(
            "MALFORMED_PART",
            "entity headers are not terminated by an empty line",
            part,
        )
    flush()
    return headers, i + 1


def _check_header_multiplicity(headers, part):
    seen = set()
    for name, _value in headers:
        if name in _SINGULAR_HEADERS:
            if name in seen:
                raise MimeAuditError(
                    "DUPLICATE_HEADER",
                    "header %r appears more than once" % name,
                    part,
                )
            seen.add(name)


def _header_value(headers, name):
    for header_name, value in headers:
        if header_name == name:
            return value
    return None


# ---------------------------------------------------------------------------
# Structured header fields (Content-Type / Content-Disposition)
# ---------------------------------------------------------------------------

def _split_semicolon(value, part, code):
    """Split a header value on ';' while respecting quoted strings."""
    segments = []
    current = []
    in_quotes = False
    escaped = False
    for char in value:
        if in_quotes:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quotes = False
        else:
            if char == '"':
                in_quotes = True
                current.append(char)
            elif char == ";":
                segments.append("".join(current))
                current = []
            else:
                current.append(char)
    if in_quotes or escaped:
        raise MimeAuditError(code, "unbalanced quoted string", part)
    segments.append("".join(current))
    return segments


def _unquote(text, part, code):
    out = []
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\\":
            i += 1
            if i >= len(text):
                raise MimeAuditError(code, "trailing backslash in quoted string", part)
            out.append(text[i])
        elif char == '"':
            raise MimeAuditError(code, "unescaped quote in quoted string", part)
        else:
            out.append(char)
        i += 1
    return "".join(out)


def _parse_parameters(value, part, code):
    """Parse 'main; name=value; name="value"' into (main, params)."""
    segments = _split_semicolon(value, part, code)
    main = segments[0].strip()
    params = {}
    for segment in segments[1:]:
        if not segment.strip():
            continue  # tolerate a trailing ';'
        name, sep, raw = segment.partition("=")
        if not sep:
            raise MimeAuditError(
                code, "parameter segment %r has no '='" % segment.strip(), part
            )
        name = name.strip().lower()
        if not _TOKEN_RE.match(name):
            raise MimeAuditError(code, "invalid parameter name %r" % name, part)
        if name in params:
            raise MimeAuditError(
                "DUPLICATE_PARAMETER",
                "parameter %r appears more than once" % name,
                part,
            )
        raw = raw.strip()
        if not raw:
            raise MimeAuditError(
                code, "parameter %r has an empty value" % name, part
            )
        if raw.startswith('"'):
            if len(raw) < 2 or not raw.endswith('"'):
                raise MimeAuditError(
                    code, "parameter %r has an unbalanced quote" % name, part
                )
            params[name] = _unquote(raw[1:-1], part, code)
        else:
            if not _TOKEN_RE.match(raw):
                raise MimeAuditError(
                    code,
                    "parameter %r value %r is neither a token nor a quoted string"
                    % (name, raw),
                    part,
                )
            params[name] = raw
    return main, params


def _parse_content_type(value, part):
    main, params = _parse_parameters(value, part, "INVALID_CONTENT_TYPE")
    if main.count("/") != 1:
        raise MimeAuditError(
            "INVALID_CONTENT_TYPE",
            "Content-Type %r is not of the form type/subtype" % main,
            part,
        )
    maintype, subtype = (piece.strip().lower() for piece in main.split("/"))
    if not _TOKEN_RE.match(maintype) or not _TOKEN_RE.match(subtype):
        raise MimeAuditError(
            "INVALID_CONTENT_TYPE",
            "Content-Type %r contains invalid tokens" % main,
            part,
        )
    return (maintype, subtype), params


def _parse_content_disposition(value, part):
    main, params = _parse_parameters(value, part, "INVALID_CONTENT_DISPOSITION")
    disposition = main.strip().lower()
    if not _TOKEN_RE.match(disposition):
        raise MimeAuditError(
            "INVALID_CONTENT_DISPOSITION",
            "invalid disposition type %r" % main.strip(),
            part,
        )
    return disposition, params


# ---------------------------------------------------------------------------
# Multipart bodies
# ---------------------------------------------------------------------------

def _validate_boundary(boundary, part):
    if not 1 <= len(boundary) <= 70:
        raise MimeAuditError(
            "INVALID_BOUNDARY", "boundary must be 1..70 characters", part
        )
    if boundary[0] == " " or boundary[-1] == " ":
        raise MimeAuditError(
            "INVALID_BOUNDARY", "boundary must not start or end with a space", part
        )
    for char in boundary:
        if char not in _BCHARS:
            raise MimeAuditError(
                "INVALID_BOUNDARY",
                "boundary contains illegal character %r" % char,
                part,
            )


def _split_regions(lines, start, end, boundary, part):
    """Split a multipart body into per-part line ranges.

    Returns a list of (start, end) index pairs into ``lines``. The CRLF
    immediately preceding a delimiter belongs to the delimiter, never to a
    part body. Preamble and epilogue are ignored per RFC 2046.
    """
    delimiter = b"--" + boundary
    closer = delimiter + b"--"
    regions = []
    region_start = None
    closed = False
    i = start
    while i < end:
        stripped = lines[i].rstrip(b" \t")  # optional transport padding
        if stripped == closer:
            if region_start is not None:
                regions.append((region_start, i))
            closed = True
            break
        if stripped == delimiter:
            if region_start is not None:
                regions.append((region_start, i))
            region_start = i + 1
        elif stripped.startswith(delimiter):
            raise MimeAuditError(
                "AMBIGUOUS_BOUNDARY_LINE",
                "body line starts with the boundary delimiter but is neither "
                "a delimiter nor a closing delimiter",
                part,
            )
        i += 1
    if not closed:
        if region_start is not None or regions:
            raise MimeAuditError(
                "BOUNDARY_NOT_CLOSED",
                "closing boundary delimiter is missing",
                part,
            )
        raise MimeAuditError(
            "BOUNDARY_DELIMITER_MISSING",
            "boundary delimiter never appears in the body",
            part,
        )
    if not regions:
        raise MimeAuditError(
            "EMPTY_MULTIPART", "multipart entity contains no parts", part
        )
    return regions


# ---------------------------------------------------------------------------
# Transfer encodings
# ---------------------------------------------------------------------------

def _decode_base64(body, part):
    chunks = []
    for line in body.split(b"\r\n"):
        if len(line) > MAX_ENCODED_LINE:
            raise MimeAuditError(
                "INVALID_BASE64",
                "base64 line longer than 76 characters",
                part,
            )
        if not line:
            continue
        if not _B64_LINE_RE.match(line):
            raise MimeAuditError(
                "INVALID_BASE64",
                "base64 data contains characters outside the alphabet",
                part,
            )
        chunks.append(line)
    compact = b"".join(chunks)
    if not _B64_LINE_RE.match(compact):
        raise MimeAuditError(
            "INVALID_BASE64", "base64 padding appears before the end", part
        )
    if len(compact) % 4 != 0:
        raise MimeAuditError(
            "INVALID_BASE64", "base64 length is not a multiple of 4", part
        )
    try:
        decoded = base64.b64decode(compact, validate=True)
    except binascii.Error as exc:
        raise MimeAuditError(
            "INVALID_BASE64", "base64 decoding failed: %s" % exc, part
        )
    if base64.b64encode(decoded) != compact:
        raise MimeAuditError(
            "INVALID_BASE64",
            "base64 padding bits are not zero (non-canonical encoding)",
            part,
        )
    return decoded


def _decode_quoted_printable(body, part):
    lines = body.split(b"\r\n")
    out = bytearray()
    last_index = len(lines) - 1
    for index, line in enumerate(lines):
        if len(line) > MAX_ENCODED_LINE:
            raise MimeAuditError(
                "INVALID_QUOTED_PRINTABLE",
                "quoted-printable line longer than 76 characters",
                part,
            )
        if line.endswith((b" ", b"\t")):
            raise MimeAuditError(
                "INVALID_QUOTED_PRINTABLE",
                "quoted-printable line has trailing whitespace; it must be "
                "encoded as =20/=09",
                part,
            )
        soft_break = False
        i = 0
        while i < len(line):
            byte = line[i]
            if byte == 0x3D:  # '='
                if i == len(line) - 1:
                    if index == last_index:
                        raise MimeAuditError(
                            "INVALID_QUOTED_PRINTABLE",
                            "soft line break at the end of the body",
                            part,
                        )
                    soft_break = True
                    i += 1
                else:
                    if i + 3 > len(line):
                        raise MimeAuditError(
                            "INVALID_QUOTED_PRINTABLE",
                            "truncated =XX escape",
                            part,
                        )
                    digits = line[i + 1:i + 3]
                    if any(chr(c) not in _HEXCHARS for c in digits):
                        raise MimeAuditError(
                            "INVALID_QUOTED_PRINTABLE",
                            "invalid =XX escape",
                            part,
                        )
                    out.append(int(digits, 16))
                    i += 3
            else:
                if byte > 0x7E:
                    raise MimeAuditError(
                        "INVALID_QUOTED_PRINTABLE",
                        "8-bit byte must be encoded as =XX",
                        part,
                    )
                if byte < 0x20 and byte != 0x09:
                    raise MimeAuditError(
                        "INVALID_QUOTED_PRINTABLE",
                        "control byte must be encoded as =XX",
                        part,
                    )
                out.append(byte)
                i += 1
        if not soft_break and index != last_index:
            out += b"\r\n"
    return bytes(out)


# ---------------------------------------------------------------------------
# Attachment filenames
# ---------------------------------------------------------------------------

def _extract_filename(params, part):
    for name in params:
        if _FILENAME_CONT_RE.match(name):
            raise MimeAuditError(
                "UNSUPPORTED_FILENAME_CONTINUATION",
                "RFC 2231 continuation parameter %r is not supported; use a "
                "single filename* parameter" % name,
                part,
            )
    plain = params.get("filename")
    star = params.get("filename*")
    if plain is None and star is None:
        raise MimeAuditError(
            "MISSING_FILENAME",
            "attachment has neither filename nor filename*",
            part,
        )
    star_value = None
    if star is not None:
        star_value = _decode_filename_star(star, part)
    if plain is not None:
        for char in plain:
            if ord(char) < 0x20 or ord(char) == 0x7F:
                raise MimeAuditError(
                    "INVALID_FILENAME",
                    "filename contains control characters",
                    part,
                )
    if plain is not None and star_value is not None and plain != star_value:
        raise MimeAuditError(
            "FILENAME_MISMATCH",
            "filename and filename* decode to different values",
            part,
        )
    return star_value if star_value is not None else plain


def _decode_filename_star(value, part):
    pieces = value.split("'", 2)
    if len(pieces) != 3:
        raise MimeAuditError(
            "INVALID_FILENAME_STAR",
            "filename* must have the form charset'language'value",
            part,
        )
    charset, _language, encoded = pieces
    if charset.lower() != "utf-8":
        raise MimeAuditError(
            "INVALID_FILENAME_STAR",
            "filename* charset must be utf-8, got %r" % charset,
            part,
        )
    raw = bytearray()
    i = 0
    while i < len(encoded):
        char = encoded[i]
        if char == "%":
            if i + 3 > len(encoded):
                raise MimeAuditError(
                    "INVALID_FILENAME_STAR",
                    "truncated percent-escape in filename*",
                    part,
                )
            digits = encoded[i + 1:i + 3]
            if len(digits) != 2 or any(c not in _HEXCHARS for c in digits):
                raise MimeAuditError(
                    "INVALID_FILENAME_STAR",
                    "invalid percent-escape in filename*",
                    part,
                )
            raw.append(int(digits, 16))
            i += 3
        elif char in _ATTR_CHARS:
            raw.append(ord(char))
            i += 1
        else:
            raise MimeAuditError(
                "INVALID_FILENAME_STAR",
                "character %r must be percent-encoded in filename*" % char,
                part,
            )
    try:
        return bytes(raw).decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise MimeAuditError(
            "INVALID_FILENAME_STAR",
            "filename* is not valid UTF-8: %s" % exc,
            part,
        )


def _normalize_filename(name, part):
    for char in name:
        code = ord(char)
        if code < 0x20 or code == 0x7F:
            raise MimeAuditError(
                "INVALID_FILENAME",
                "filename contains control characters",
                part,
            )
    normalized = unicodedata.normalize("NFC", name).strip()
    if not normalized:
        raise MimeAuditError(
            "FILENAME_EMPTY", "filename is empty after normalisation", part
        )
    if normalized in (".", "..") or "/" in normalized or "\\" in normalized:
        raise MimeAuditError(
            "FILENAME_PATH_COMPONENT",
            "filename %r contains path components" % normalized,
            part,
        )
    return normalized
