"""Strict, single-interpretation MIME (RFC 2045/2046/5322/5987) parser.

Design contract
---------------
* The raw message MUST use CRLF throughout; a bare CR or LF rejects the whole
  message (``BARE_EOL``).
* Headers are parsed with an exact grammar (the lenient :mod:`email` package
  is never used).
* The root entity MUST be ``multipart/mixed``; every nested multipart is
  likewise restricted to ``multipart/mixed`` so structural semantics have a
  single interpretation.
* Multipart delimiters are matched literally at line boundaries (no
  transport padding, no non-empty preamble/epilogue, exactly one closing
  delimiter) and a candidate boundary line is only honoured when the octets
  immediately following the boundary are CRLF or ``--`` -- this prevents a
  parent boundary that is a prefix of a child boundary from being mistaken
  for a delimiter. Boundary values must be unique within the message.
* Leaf (non-multipart) bodies MUST declare ``Content-Transfer-Encoding`` of
  exactly ``base64`` or ``quoted-printable`` and the payload is re-validated
  character by character; decoded bytes (not re-encoded guesses) drive the
  audit output.
* An attachment is a leaf whose ``Content-Disposition`` is exactly
  ``attachment`` and that carries a filename; ``filename`` (RFC 2045) and
  UTF-8 ``filename*`` (RFC 5987), when both present, must decode to the same
  NFKC-normalised name. Normalised names must be non-empty, free of path
  components and unique.

Every failure raises :class:`~mimeaudit.errors.MimeAuditError` with a stable
``code`` and the 1-based depth-first ``part`` ordinal (``None`` for message
/root level). The attachment list is only produced when *all* checks pass.
"""

import binascii
import hashlib
import re
import unicodedata

from .errors import MimeAuditError

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

MAX_MESSAGE_BYTES = 4 * 1024 * 1024
MAX_MULTIPART_DEPTH = 4
MAX_LEAF_PARTS = 64
MAX_BOUNDARY_LEN = 69
MAX_HEADER_LINE_LEN = 998  # RFC 5322 section 2.1.1, excluding CRLF

CRLF = b"\r\n"

# ---------------------------------------------------------------------------
# Character classes (RFC 5322 / RFC 2045 / RFC 5987)
# ---------------------------------------------------------------------------

_TSPECIALS = set(b'()<>@,;:\\"/[]?=')
_TOKEN_BYTES = frozenset(range(0x21, 0x7F)) - _TSPECIALS
_BOUNDARY_CHARS = frozenset(b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'()+_,-./:=? ")
_ATTR_CHARS = frozenset(b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$&+-.^_`|~")
_HEX = frozenset(b"0123456789abcdefABCDEF")
_BASE64_RE = re.compile(rb"[A-Za-z0-9+/]*={0,2}\Z")


def _fail(code, message, part=None):
    raise MimeAuditError(code, message, part)


# ---------------------------------------------------------------------------
# Low level helpers
# ---------------------------------------------------------------------------


def _is_token(data: bytes) -> bool:
    return len(data) > 0 and all(c in _TOKEN_BYTES for c in data)


def _validate_eol(data: bytes) -> None:
    """Reject anything that is not a strict CRLF line break."""
    for i, c in enumerate(data):
        if c == 0x0A:
            if i == 0 or data[i - 1] != 0x0D:
                _fail("BARE_EOL", "bare LF is not allowed; all line breaks must be CRLF")
        elif c == 0x0D:
            if i + 1 >= len(data) or data[i + 1] != 0x0A:
                _fail("BARE_EOL", "bare CR is not allowed; all line breaks must be CRLF")


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------


def _unfold(block: bytes):
    """Unfold RFC 5322 folding (CRLF WSP) into logical header lines."""
    lines = block.split(CRLF)
    out = []
    for line in lines:
        if line and line[0] in (0x20, 0x09):
            if not out:
                _fail("INVALID_HEADER", "continuation line without a preceding header")
            out[-1] += b" " + line[1:].lstrip(b" \t")
        else:
            out.append(line)
    return out


def _parse_headers(block: bytes, part):
    """Return an ordered ``{lower-name: value-bytes}`` mapping."""
    # The 998 octet limit applies to each physical line before unfolding.
    for physical in block.split(CRLF):
        if len(physical) > MAX_HEADER_LINE_LEN:
            _fail("HEADER_LINE_TOO_LONG", "header line exceeds 998 octets", part)
    headers = {}
    for raw in _unfold(block):
        if not raw or any(c < 0x20 and c != 0x09 for c in raw) or any(c >= 0x7F for c in raw):
            _fail("INVALID_HEADER", "header is empty or contains control / non-ASCII octets", part)
        colon = raw.find(b":")
        if colon <= 0:
            _fail("INVALID_HEADER", "header field is missing a colon", part)
        name = raw[:colon]
        if not _is_token(name):
            _fail("INVALID_HEADER_NAME", "header field name is not a valid token", part)
        value = raw[colon + 1 :].lstrip(b" \t").rstrip(b" \t")
        key = name.lower().decode("ascii")
        if key in headers:
            _fail("DUPLICATE_HEADER", f"duplicate header field {key!r}", part)
        headers[key] = value
    if not headers:
        _fail("MALFORMED_PART", "entity has no header section", part)
    return headers


# ---------------------------------------------------------------------------
# Parameter / media-type / disposition parsing
# ---------------------------------------------------------------------------


def _split_parameters(value: bytes, part, header_name: str):
    """Split ``main-value; p1=v1; p2=v2`` honouring quoted strings."""
    segments = []
    buf = bytearray()
    in_quote = False
    i = 0
    while i < len(value):
        c = value[i]
        if in_quote:
            if c == 0x5C:
                if i + 1 >= len(value):
                    _fail("INVALID_HEADER_VALUE", f"dangling backslash in {header_name}", part)
                buf.append(c)
                buf.append(value[i + 1])
                i += 2
                continue
            if c == 0x22:
                in_quote = False
            buf.append(c)
        else:
            if c == 0x22:
                in_quote = True
                buf.append(c)
            elif c == 0x3B:
                segments.append(bytes(buf))
                buf = bytearray()
            else:
                buf.append(c)
        i += 1
    if in_quote:
        _fail("INVALID_HEADER_VALUE", f"unterminated quoted string in {header_name}", part)
    segments.append(bytes(buf))

    main = segments[0].strip(b" \t")
    params = []
    for seg in segments[1:]:
        seg = seg.strip(b" \t")
        if not seg:
            _fail("INVALID_HEADER_VALUE", f"empty parameter in {header_name}", part)
        eq = seg.find(b"=")
        if eq <= 0:
            _fail("INVALID_HEADER_VALUE", f"malformed parameter in {header_name}", part)
        pname = seg[:eq].strip(b" \t")
        pval = seg[eq + 1 :].strip(b" \t")
        if not _is_token(pname):
            _fail("INVALID_HEADER_VALUE", f"parameter name is not a token in {header_name}", part)
        params.append((pname.lower().decode("ascii"), pval))
    return main, params


def _unquote_value(raw: bytes, part, header_name: str) -> bytes:
    """Decode a token-or-quoted-string parameter value to raw bytes."""
    if raw and raw[0] == 0x22:
        if len(raw) < 2 or raw[-1] != 0x22:
            _fail("INVALID_HEADER_VALUE", f"unterminated quoted string in {header_name}", part)
        out = bytearray()
        body = raw[1:-1]
        i = 0
        while i < len(body):
            c = body[i]
            if c == 0x5C:
                if i + 1 >= len(body):
                    _fail("INVALID_HEADER_VALUE", f"dangling backslash in {header_name}", part)
                nxt = body[i + 1]
                if not (0x20 <= nxt <= 0x7E):
                    _fail("INVALID_HEADER_VALUE", f"bad quoted-pair in {header_name}", part)
                out.append(nxt)
                i += 2
            else:
                if c == 0x22 or not (c == 0x09 or c == 0x20 or 0x21 <= c <= 0x7E):
                    _fail("INVALID_HEADER_VALUE", f"illegal octet in quoted string of {header_name}", part)
                out.append(c)
                i += 1
        return bytes(out)
    if not _is_token(raw):
        _fail("INVALID_HEADER_VALUE", f"parameter value is neither token nor quoted string in {header_name}", part)
    return raw


def _dedupe_params(params, part, header_name):
    result = {}
    for name, raw in params:
        # RFC 2231 continuations such as name*0*= give a value multiple
        # interpretations depending on assembler tolerance; refuse them.
        if "*" in name.rstrip("*"):
            _fail("PARAM_CONTINUATION_UNSUPPORTED", f"RFC 2231 continuation parameters are not allowed in {header_name}", part)
        if name in result:
            _fail("DUPLICATE_PARAMETER", f"duplicate parameter {name!r} in {header_name}", part)
        result[name] = raw
    return result


def _parse_content_type(value: bytes, part):
    main, params = _split_parameters(value, part, "Content-Type")
    slash = main.find(b"/")
    if slash <= 0 or main.find(b" ") != -1 or main.find(b"\t") != -1:
        _fail("INVALID_MEDIA_TYPE", "media type must be token/token", part)
    maintype = main[:slash]
    subtype = main[slash + 1 :]
    if not _is_token(maintype) or not _is_token(subtype):
        _fail("INVALID_MEDIA_TYPE", "media type components must be valid tokens", part)
    raw_params = _dedupe_params(params, part, "Content-Type")
    parsed = {name: _unquote_value(raw, part, "Content-Type") for name, raw in raw_params.items()}
    return maintype.lower().decode("ascii"), subtype.lower().decode("ascii"), parsed


# ---------------------------------------------------------------------------
# RFC 5987 filename*
# ---------------------------------------------------------------------------


def _parse_ext_filename(raw: bytes, part) -> str:
    """Parse ``UTF-8'lang'%e2%82%ac`` into a Unicode string."""
    parts = raw.split(b"'")
    if len(parts) != 3:
        _fail("FILENAME_STAR_MALFORMED", "filename* must be charset'language'value", part)
    charset, lang, value = parts
    if charset.lower() != b"utf-8":
        _fail("FILENAME_STAR_CHARSET", "filename* charset must be UTF-8", part)
    if lang and not re.fullmatch(rb"[A-Za-z0-9\-]+", lang):
        _fail("FILENAME_STAR_MALFORMED", "filename* language tag is invalid", part)
    out = bytearray()
    i = 0
    while i < len(value):
        c = value[i]
        if c == 0x25:
            if i + 2 >= len(value) or value[i + 1] not in _HEX or value[i + 2] not in _HEX:
                _fail("FILENAME_STAR_MALFORMED", "filename* contains a malformed percent escape", part)
            out.append(int(value[i + 1 : i + 3], 16))
            i += 3
        else:
            if c not in _ATTR_CHARS:
                _fail("FILENAME_STAR_MALFORMED", "filename* contains an illegal raw octet", part)
            out.append(c)
            i += 1
    try:
        return bytes(out).decode("utf-8")
    except UnicodeDecodeError:
        _fail("FILENAME_STAR_ENCODING", "filename* is not valid UTF-8", part)


def _parse_disposition(value: bytes, part):
    disp, params = _split_parameters(value, part, "Content-Disposition")
    if not _is_token(disp):
        _fail("INVALID_DISPOSITION", "content disposition must be a token", part)
    raw_params = _dedupe_params(params, part, "Content-Disposition")
    parsed = {}
    for name, raw in raw_params.items():
        if name.endswith("*"):
            if name != "filename*":
                _fail("UNSUPPORTED_EXTENDED_PARAM", f"extended parameter {name!r} is not allowed", part)
            parsed[name] = _parse_ext_filename(raw, part)
        else:
            parsed[name] = _unquote_value(raw, part, "Content-Disposition")
    return disp.lower().decode("ascii"), parsed


# ---------------------------------------------------------------------------
# Strict transfer decoders
# ---------------------------------------------------------------------------


def _encoded_lines(body: bytes, part, label: str):
    """Split an encoded leaf body.

    The CRLF immediately preceding a multipart boundary belongs to the
    boundary delimiter (RFC 2046 section 5.1.1), so the body's final encoded
    line is structurally terminated by the boundary and carries no trailing
    CRLF. An internal blank line or an explicit trailing CRLF would make the
    body's extent ambiguous and is rejected.
    """
    if body == b"":
        return []
    lines = body.split(CRLF)
    if any(line == b"" for line in lines):
        _fail(f"{label}_BLANK_LINE", f"{label} body contains an empty or blank line", part)
    return lines


def _decode_base64(body: bytes, part) -> bytes:
    if body == b"":
        return b""
    lines = _encoded_lines(body, part, "BASE64")
    for line in lines:
        if len(line) > 76:
            _fail("INVALID_BASE64", "base64 line exceeds 76 characters", part)
        if any(c > 0x7F for c in line):
            _fail("INVALID_BASE64", "base64 body contains non-ASCII octets", part)
    text = b"".join(lines)
    if not _BASE64_RE.match(text):
        _fail("INVALID_BASE64", "base64 body contains characters outside the alphabet", part)
    if len(text) % 4 != 0:
        _fail("INVALID_BASE64", "base64 body length is not a multiple of four", part)
    if len(text) >= 4:
        core, last4 = text[:-4], text[-4:]
        if b"=" in core:
            _fail("INVALID_BASE64", "base64 padding is only allowed in the final quartet", part)
        pads = last4.count(b"=")
        if pads == 1 and last4[3] != 0x3D:
            _fail("INVALID_BASE64", "base64 padding character is misplaced", part)
        if pads == 2 and last4[2:] != b"==":
            _fail("INVALID_BASE64", "base64 padding characters are misplaced", part)
        if pads not in (0, 1, 2):
            _fail("INVALID_BASE64", "base64 padding is too long", part)
    try:
        decoded = binascii.a2b_base64(text)
    except binascii.Error:
        _fail("INVALID_BASE64", "base64 body could not be decoded", part)

    # Canonical encoding: unused residual bits in the final quantum must be
    # zero. Nonzero pad bits are discarded by decoders but encode no unique
    # value, so they are rejected to guarantee a single interpretation.
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    if pads == 2:
        if alphabet.index(last4[1]) & 0x0F:
            _fail("INVALID_BASE64", "non-canonical base64: residual pad bits are not zero", part)
    elif pads == 1:
        if alphabet.index(last4[2]) & 0x03:
            _fail("INVALID_BASE64", "non-canonical base64: residual pad bits are not zero", part)
    return decoded


def _decode_quoted_printable(body: bytes, part) -> bytes:
    if body == b"":
        return b""
    lines = _encoded_lines(body, part, "QUOTED_PRINTABLE")

    def decode_piece(piece: bytes, soft_terminated: bool) -> bytes:
        if len(piece) > 76:
            _fail("INVALID_QUOTED_PRINTABLE", "quoted-printable line exceeds 76 characters", part)
        # Trailing WSP is only legal before a soft line break: once joined it
        # is interior whitespace. On a hard-terminated line it would be
        # stripped differently by clients and must therefore be encoded.
        if not soft_terminated and piece and piece[-1] in (0x20, 0x09):
            _fail("INVALID_QUOTED_PRINTABLE", "trailing whitespace must be encoded as =20/=09", part)
        out = bytearray()
        i = 0
        while i < len(piece):
            c = piece[i]
            if c == 0x3D:
                if soft_terminated and i == len(piece) - 1:
                    break  # soft line break: caller concatenates the next piece
                if i + 2 >= len(piece) or piece[i + 1] not in _HEX or piece[i + 2] not in _HEX:
                    _fail("INVALID_QUOTED_PRINTABLE", "'=' must be followed by two hex digits or CRLF", part)
                out.append(int(piece[i + 1 : i + 3], 16))
                i += 3
            elif c == 0x09 or (0x20 <= c <= 0x7E and c != 0x3D):
                out.append(c)
                i += 1
            else:
                _fail("INVALID_QUOTED_PRINTABLE", "octet outside printable ASCII must be encoded", part)
        return bytes(out)

    # Group soft-broken pieces; each group is one logical line.
    groups = []
    current = []
    for line in lines:
        current.append(line)
        if not line.endswith(b"="):
            groups.append(current)
            current = []
    if current:
        _fail("INVALID_QUOTED_PRINTABLE", "dangling soft line break at end of body", part)

    result = bytearray()
    for g_idx, pieces in enumerate(groups):
        for p_idx, piece in enumerate(pieces):
            soft = piece.endswith(b"=")
            if p_idx < len(pieces) - 1 and not soft:
                _fail("INVALID_QUOTED_PRINTABLE", "expected a soft line break", part)
            result += decode_piece(piece, soft)
        if g_idx < len(groups) - 1:
            result += CRLF
    return bytes(result)


# ---------------------------------------------------------------------------
# Multipart splitting
# ---------------------------------------------------------------------------


def _validate_boundary(boundary: bytes, part):
    if not boundary or len(boundary) > MAX_BOUNDARY_LEN:
        _fail("BOUNDARY_INVALID", "multipart boundary must be 1..69 octets", part)
    if any(c not in _BOUNDARY_CHARS for c in boundary):
        _fail("BOUNDARY_INVALID", "multipart boundary contains an illegal octet", part)
    # Trailing (or leading) spaces are indistinguishable from transport
    # padding on the delimiter line, so they make framing ambiguous.
    if boundary[0] == 0x20 or boundary[-1] == 0x20:
        _fail("BOUNDARY_INVALID", "multipart boundary must not begin or end with space", part)


def _iter_multipart_parts(body: bytes, boundary: bytes, part):
    """Yield the raw part blocks of a multipart body in order.

    Blocks are streamed: a child is yielded (and can therefore be validated,
    including for boundary reuse) as soon as the following delimiter is seen.
    Missing/duplicate closers and epilogue garbage are raised only after the
    final block, when the generator advances to its end -- so a structural
    error inside a child is reported at the child's own part ordinal rather
    than being masked by a parent-level framing error.

    A candidate ``CRLF--boundary`` occurrence is only honoured as a delimiter
    when immediately followed by CRLF (intermediate) or ``--`` (closing), so
    a boundary that is a prefix of another level's boundary never matches.
    """
    delim = b"--" + boundary

    if not body.startswith(delim):
        _fail("PREAMBLE_NOT_EMPTY", "multipart preamble must be empty", part)
    pos = len(delim)
    if body.startswith(b"--", pos):
        rest = body[pos + 2 :]
        if rest not in (b"", CRLF):
            _fail("BOUNDARY_TRAILING_GARBAGE", "garbage octets after the closing delimiter", part)
        _fail("MULTIPART_EMPTY", "multipart entity contains no parts", part)
    if not body.startswith(CRLF, pos):
        _fail("BOUNDARY_DELIMITER_INVALID", "illegal octets after the opening boundary delimiter", part)

    block_start = pos + 2
    search_from = block_start
    yielded = 0
    closed = False
    while True:
        nxt = body.find(CRLF + delim, search_from)
        if nxt == -1:
            _fail("BOUNDARY_NOT_CLOSED", "multipart boundary is never closed", part)
        after = nxt + 2 + len(delim)
        if body.startswith(b"--", after):
            rest = body[after + 2 :]
            yield body[block_start:nxt]
            yielded += 1
            if rest not in (b"", CRLF):
                _fail("BOUNDARY_TRAILING_GARBAGE", "garbage octets after the closing delimiter", part)
            closed = True
            break
        if body.startswith(CRLF, after):
            yield body[block_start:nxt]
            yielded += 1
            block_start = after + 2
            search_from = block_start
        else:
            # Prefix collision with some other boundary: keep the block start
            # fixed and resume searching just past this candidate.
            search_from = nxt + 2
    if not closed or yielded == 0:  # pragma: no cover - closure always set
        _fail("BOUNDARY_NOT_CLOSED", "multipart boundary is never closed", part)


# ---------------------------------------------------------------------------
# Filename normalisation
# ---------------------------------------------------------------------------


def _normalise_filename(name: str, part) -> str:
    normalised = unicodedata.normalize("NFKC", name).strip()
    if not normalised:
        _fail("FILENAME_EMPTY", "attachment filename is empty after normalisation", part)
    # Checked *after* NFKC so full-width separators (U+FF0F/U+FF3C) are caught.
    if "\x00" in normalised or "/" in normalised or "\\" in normalised:
        _fail("FILENAME_PATH_COMPONENT", "filename must not contain path components", part)
    if normalised in (".", ".."):
        _fail("FILENAME_PATH_COMPONENT", "filename must not be a dot segment", part)
    if any(unicodedata.category(ch) == "Cc" for ch in normalised):
        _fail("FILENAME_CONTROL_CHAR", "filename contains control characters", part)
    return normalised


# ---------------------------------------------------------------------------
# Entity tree walk
# ---------------------------------------------------------------------------


class _Counter:
    def __init__(self):
        self.part = 0
        self.leaves = 0


def _leaf_filename(disp_params, part):
    plain = None
    raw_name = disp_params.get("filename")
    if raw_name is not None:
        try:
            plain = raw_name.decode("ascii")
        except UnicodeDecodeError:
            _fail("FILENAME_NOT_ASCII", "plain filename must be ASCII; use filename* for UTF-8", part)
        # RFC 2047 encoded-words are illegal inside a parameter token, but a
        # tolerant client decodes them while a strict one takes them literally:
        # two different file names -> reject.
        if "=?" in plain:
            _fail("FILENAME_ENCODED_WORD", "RFC 2047 encoded words are not allowed in filename; use filename*", part)
    ext_name = disp_params.get("filename*")
    if plain is None and ext_name is None:
        _fail("MISSING_FILENAME", "attachment disposition requires a filename", part)
    if plain is not None and ext_name is not None:
        if unicodedata.normalize("NFKC", plain) != unicodedata.normalize("NFKC", ext_name):
            _fail("FILENAME_MISMATCH", "filename and filename* decode to different names", part)
    chosen = ext_name if ext_name is not None else plain
    return _normalise_filename(chosen, part)


def _parse_entity(raw: bytes, depth: int, counter: _Counter, boundaries: set, names: set):
    sep = raw.find(CRLF + CRLF)
    if sep == -1:
        _fail("MALFORMED_PART", "entity has no header/body separator", counter.part or None)
    header_block, body = raw[:sep], raw[sep + 4 :]
    part = counter.part if depth > 1 else None

    headers = _parse_headers(header_block, part)

    mime_version = headers.get("mime-version")
    if mime_version is not None and mime_version.strip() != b"1.0":
        _fail("MIME_VERSION_INVALID", "MIME-Version must be 1.0", part)

    ctype_raw = headers.get("content-type")
    if ctype_raw is None:
        _fail("MISSING_CONTENT_TYPE", "every entity must declare Content-Type", part)
    maintype, subtype, ctype_params = _parse_content_type(ctype_raw, part)

    cte = None
    cte_raw = headers.get("content-transfer-encoding")
    if cte_raw is not None:
        cte_val = cte_raw.strip()
        if not _is_token(cte_val):
            _fail("INVALID_CTE", "Content-Transfer-Encoding must be a token", part)
        cte = cte_val.lower().decode("ascii")

    if maintype == "multipart":
        if subtype != "mixed":
            _fail("MULTIPART_SUBTYPE_NOT_MIXED", "only multipart/mixed is accepted", part)
        if cte is not None:
            _fail("MULTIPART_CTE_FORBIDDEN", "multipart entities must not be transfer-encoded", part)
        if depth > MAX_MULTIPART_DEPTH:
            _fail("NESTED_DEPTH_EXCEEDED", f"multipart nesting exceeds {MAX_MULTIPART_DEPTH} levels", part)
        boundary = ctype_params.get("boundary")
        if boundary is None:
            _fail("MULTIPART_BOUNDARY_REQUIRED", "multipart/mixed requires a boundary parameter", part)
        _validate_boundary(boundary, part)
        if boundary in boundaries:
            _fail("BOUNDARY_REUSE", "multipart boundaries must not be reused", part)
        boundaries.add(boundary)
        attachments = []
        for child in _iter_multipart_parts(body, boundary, part):
            counter.part += 1
            attachments.extend(_parse_entity(child, depth + 1, counter, boundaries, names))
        return attachments

    # Leaf entity.
    counter.leaves += 1
    if counter.leaves > MAX_LEAF_PARTS:
        _fail("TOO_MANY_LEAF_PARTS", f"leaf part count exceeds {MAX_LEAF_PARTS}", counter.part)

    # A nested message/* entity is itself MIME-structured; a mail client may
    # recursively extract attachments from it, which would give the archived
    # evidence more than one interpretation. Treat it as a structural refusal.
    if maintype == "message":
        _fail("UNSUPPORTED_MEDIA_TYPE", "nested message/* entities are not accepted", part)

    if cte not in ("base64", "quoted-printable"):
        _fail("CTE_NOT_ALLOWED", "leaf bodies must use strict base64 or quoted-printable encoding", part)
    decoded = _decode_base64(body, part) if cte == "base64" else _decode_quoted_printable(body, part)

    disp_raw = headers.get("content-disposition")
    disposition, disp_params = _parse_disposition(disp_raw, part) if disp_raw is not None else (None, {})

    # The file name must have a single source. A Content-Type name parameter
    # is used as a fallback by some clients but ignored by others, so its mere
    # presence next to a disposition would make the name ambiguous.
    if "name" in ctype_params or "name*" in ctype_params:
        _fail("NAME_PARAMETER_NOT_ALLOWED", "file names are only allowed via Content-Disposition", part)

    if disposition == "attachment":
        filename = _leaf_filename(disp_params, part)
        if filename in names:
            _fail("DUPLICATE_FILENAME", f"duplicate attachment filename {filename!r}", part)
        names.add(filename)
        return [
            {
                "part": counter.part,
                "filename": filename,
                "media_type": f"{maintype}/{subtype}",
                "size": len(decoded),
                "sha256": hashlib.sha256(decoded).hexdigest(),
            }
        ]

    if disposition not in (None, "inline"):
        _fail("DISPOSITION_NOT_ATTACHMENT", "disposition must be attachment or inline", part)
    if "filename" in disp_params or "filename*" in disp_params:
        _fail("FILENAME_ON_NON_ATTACHMENT", "only attachment dispositions may carry a filename", part)
    return []


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def audit_message(data: bytes):
    """Audit a complete ``message/rfc822`` blob.

    Returns ``{"attachments": [...]}`` in depth-first order or raises
    :class:`~mimeaudit.errors.MimeAuditError`.
    """
    if not isinstance(data, (bytes, bytearray)):
        _fail("MALFORMED_MESSAGE", "message must be raw bytes")
    data = bytes(data)
    if len(data) == 0:
        _fail("MALFORMED_MESSAGE", "message is empty")
    if len(data) > MAX_MESSAGE_BYTES:
        _fail("MESSAGE_TOO_LARGE", f"message exceeds {MAX_MESSAGE_BYTES} bytes")

    _validate_eol(data)

    sep = data.find(CRLF + CRLF)
    if sep == -1:
        _fail("MALFORMED_MESSAGE", "message has no header/body separator")
    root_headers = _parse_headers(data[:sep], None)

    if "mime-version" not in root_headers:
        _fail("MIME_VERSION_REQUIRED", "root entity must carry MIME-Version: 1.0")

    ctype = root_headers.get("content-type")
    if ctype is None:
        _fail("ROOT_NOT_MULTIPART_MIXED", "root entity must be multipart/mixed")
    maintype, subtype, ctype_params = _parse_content_type(ctype, None)
    if (maintype, subtype) != ("multipart", "mixed"):
        _fail("ROOT_NOT_MULTIPART_MIXED", "root entity must be multipart/mixed")
    boundary = ctype_params.get("boundary")
    if boundary is None:
        _fail("MULTIPART_BOUNDARY_REQUIRED", "root multipart/mixed requires a boundary parameter")
    _validate_boundary(boundary, None)

    counter = _Counter()
    # The root boundary is registered when the root entity is walked below;
    # it must not be seeded here (that would look like self-reuse).
    attachments = _parse_entity(data, 1, counter, set(), set())
    return {"attachments": attachments}
