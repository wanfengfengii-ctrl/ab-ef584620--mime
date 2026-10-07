"""Strict MIME audit service for the research archive platform.

The package deliberately implements its own RFC 2045/2046/5987 parser instead
of delegating to the lenient :mod:`email` package: an archived message must
have exactly one interpretation, so every structural and encoding deviation
rejects the whole message.
"""

from .errors import MimeAuditError
from .parser import audit_message

__all__ = ["MimeAuditError", "audit_message"]
