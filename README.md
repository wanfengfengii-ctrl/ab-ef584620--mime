Strict MIME Audit Service
=========================

A dependency-free (Python standard library only) HTTP service that performs a
**single-interpretation** audit of an archived RFC 822 message *before* any
attachment extraction. Unlike tolerant mail clients, this parser refuses a
message whenever its MIME layering, boundaries or transfer encodings could be
read more than one way, so the bytes that evidence extraction produces are
exactly the bytes the audit decoded.

Why a hand-written parser?
--------------------------

The stdlib ``email`` package and most MIME libraries normalise line endings,
repair missing closers, accept whitespace after boundaries, and silently pick
one variant when parameters conflict. That leniency is precisely what can
make a saved file diverge from archived evidence. This service therefore
implements its own strict parser; it never calls the ``email`` package for
parsing.

Rules enforced
--------------

* Raw wire message: ``message/rfc822``, <= 4 MiB, **CRLF everywhere**
  (any bare CR/LF => ``BARE_EOL``).
* Root entity **must** be ``multipart/mixed``.
* Nesting at most 4 multipart levels deep (``NESTED_DEPTH_EXCEEDED``);
  at most 64 leaf parts (``TOO_MANY_LEAF_PARTS``).
* Every multipart is ``multipart/mixed``; preamble/epilogue must be empty;
  boundaries must be valid, exactly once closed, never reused
  (``BOUNDARY_NOT_CLOSED`` / ``BOUNDARY_REUSE`` / ...). A boundary that is a
  prefix of another level's boundary is handled without ambiguity.
* Leaf bodies may use only strict ``base64`` or ``quoted-printable``
  (``CTE_NOT_ALLOWED``) and are validated character by character.
* Attachments: only an explicit ``Content-Disposition: attachment`` with a
  filename; inline parts without filenames are allowed as message bodies.
* ``filename`` (ASCII token/quoted) and UTF-8 ``filename*`` (RFC 5987), when
  both present, must decode to the **same** NFKC-normalised name. Normalised
  names must be non-empty, contain no path component (``/``, ``\\``, ``.``/``..``,
  even after Unicode NFKC folding, e.g. full-width slash), and be unique.
* Any structural or encoding error rejects the **whole** message; the error
  carries a stable ``code`` and the offending 1-based depth-first ``part``
  ordinal (``null`` at message/root level). No partial attachment manifest is
  ever returned.

API
---

``POST /api/mime/audit``
    Consumption: ``Content-Type: message/rfc822`` (<= 4 MiB, CRLF).

    Success ``200``::

        {
          "attachments": [
            {"part": 1, "filename": "a.txt", "media_type": "text/plain",
             "size": 84, "sha256": "<lowercase hex>"},
            ...
          ]
        }

    Failure ``400`` (or 413/415)::

        {"code": "BOUNDARY_NOT_CLOSED", "message": "...", "part": 2}

    Depth-first order, one entry per accepted attachment.

``GET /health``
    ``{"status": "ok"}`` (used by the Docker health check).

Running with Docker Compose
---------------------------

The host port is configurable::

    MIME_AUDIT_HOST_PORT=9090 docker compose up --build -d

One-shot verification (builds the same image, runs the unit tests and
submits a valid four-level nested message and a broken-boundary sample to
the running API; exits 0 only on full success)::

    docker compose build
    docker compose run --rm verify

or simply::

    curl --data-binary @valid.msg \
         --header 'Content-Type: message/rfc822' \
         http://localhost:8080/api/mime/audit

Local development (no Docker needed)
------------------------------------

    python -m unittest discover -s tests -v
    MIME_AUDIT_PORT=8080 python -m mimeaudit

Error code reference
--------------------

| code | meaning |
|------|---------|
| ``BARE_EOL`` | bare CR/LF; the message must be all CRLF |
| ``MALFORMED_MESSAGE`` / ``MALFORMED_PART`` | missing separator / headers |
| ``ROOT_NOT_MULTIPART_MIXED`` | root media type is not multipart/mixed |
| ``MULTIPART_SUBTYPE_NOT_MIXED`` | nested multipart is not multipart/mixed |
| ``MULTIPART_BOUNDARY_REQUIRED`` | boundary parameter missing |
| ``BOUNDARY_INVALID`` | boundary length/charset illegal |
| ``BOUNDARY_REUSE`` | same boundary used by two entities |
| ``BOUNDARY_NOT_CLOSED`` | closing delimiter missing |
| ``BOUNDARY_TRAILING_GARBAGE`` | garbage / extra delimiter after close |
| ``PREAMBLE_NOT_EMPTY`` | non-empty multipart preamble |
| ``NESTED_DEPTH_EXCEEDED`` | more than 4 multipart levels |
| ``TOO_MANY_LEAF_PARTS`` | more than 64 leaf parts |
| ``CTE_NOT_ALLOWED`` | leaf CTE is neither base64 nor quoted-printable |
| ``INVALID_BASE64`` / ``INVALID_QUOTED_PRINTABLE`` | encoding violation |
| ``MISSING_FILENAME`` / ``FILENAME_EMPTY`` / ``FILENAME_PATH_COMPONENT`` | filename rules |
| ``FILENAME_MISMATCH`` | filename vs filename* disagree after normalisation |
| ``FILENAME_ENCODED_WORD`` | RFC 2047 ``=?..?=`` in a plain filename (use filename*) |
| ``NAME_PARAMETER_NOT_ALLOWED`` | ``name`` on Content-Type (single filename source only) |
| ``FILENAME_STAR_*`` | RFC 5987 extended filename violations |
| ``UNSUPPORTED_MEDIA_TYPE`` | nested ``message/*`` entity |
| ``PARAM_CONTINUATION_UNSUPPORTED`` | RFC 2231 ``name*0=`` continuations |
| ``DUPLICATE_FILENAME`` / ``DUPLICATE_HEADER`` / ``DUPLICATE_PARAMETER`` | uniqueness |
| ``MESSAGE_TOO_LARGE`` | over 4 MiB |
