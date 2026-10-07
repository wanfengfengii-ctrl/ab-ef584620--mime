"""Stable error codes raised by the strict MIME auditor.

Every rejection carries:
  * code    - a stable, machine-readable string (never changes meaning);
  * part    - the pre-order index of the MIME entity where the problem was
              detected (root entity is 0), or None for whole-message/request
              level failures;
  * message - a human-readable explanation;
  * status  - the HTTP status the API layer should return.
"""


class MimeAuditError(Exception):
    """A message violates the strict archival rules."""

    def __init__(self, code, message, part=None, status=422):
        super().__init__(message)
        self.code = code
        self.message = message
        self.part = part
        self.status = status

    def to_dict(self):
        return {
            "error": {
                "code": self.code,
                "part": self.part,
                "message": self.message,
            }
        }
