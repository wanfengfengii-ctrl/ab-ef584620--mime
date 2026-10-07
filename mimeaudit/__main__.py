"""Entry point: ``python -m mimeaudit``.

Configuration via environment:
* ``MIME_AUDIT_HOST`` (default ``0.0.0.0``)
* ``MIME_AUDIT_PORT`` (default ``8080``)
"""

import os

from .app import build_server


def main() -> None:
    host = os.environ.get("MIME_AUDIT_HOST", "0.0.0.0")
    port = int(os.environ.get("MIME_AUDIT_PORT", "8080"))
    server = build_server(host, port)
    print(f"mime-audit listening on {host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
