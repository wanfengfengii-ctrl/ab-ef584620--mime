"""Stable error codes for strict MIME auditing.

Every failure produces an :class:`Exception` carrying:

* ``code``    -- a stable, machine-readable error code;
* ``part``    -- the 1-based depth-first part ordinal of the offending part,
  or ``None`` when the failure is located at the root entity / message level;
* a human readable ``message`` (in English) describing the violation.

No partial attachment list is ever returned: the audit either succeeds
completely or raises.
"""


class MimeAuditError(Exception):
    """Raised when an audited message violates the strict MIME rules."""

    def __init__(self, code: str, message: str, part=None):
        super().__init__(message)
        self.code = code
        self.part = part
        self.message = message

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "part": self.part}

    def __str__(self):  # pragma: no cover - debugging convenience
        if self.part is not None:
            return f"[{self.code}] part#{self.part}: {self.message}"
        return f"[{self.code}] {self.message}"
