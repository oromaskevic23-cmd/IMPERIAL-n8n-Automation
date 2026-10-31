"""Loopback-only reference service; use a proper TLS/auth proxy in real deployments."""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .gateway import Gateway, MAX_BODY


def serve() -> None:
    transport = os.environ.get("IMPERIAL_INGRESS_SECRET", "").encode()
    approval = os.environ.get("IMPERIAL_APPROVAL_SECRET", "").encode()
    orchestrators = set(filter(None,
        (part.strip() for part in os.getenv("IMPERIAL_ALLOWED_ORCHESTRATORS", "").split(","))))
    gateway = Gateway(os.getenv("IMPERIAL_GATEWAY_DB", "imperial_intake.db"),
                      transport, approval, orchestrators)

    class Handler(BaseHTTPRequestHandler):
        def _respond(self, code: int, payload: dict):
            raw = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path != "/healthz":
                self._respond(404, {"error": "not_found"})
            else:
                self._respond(200, {"status": "local_process_ready",
                                    "execution": "disabled",
                                    "kill_switch_engaged":
                                        os.getenv("IMPERIAL_OWNER_KILL_SWITCH", "1") != "0"})

        def do_POST(self):
            if self.path != "/v1/intake":
                return self._respond(404, {"error": "not_found"})
            # Reject ambiguous duplicate headers and transfer framing.
            required = ("Content-Length", "X-IC-Timestamp", "X-IC-Nonce", "X-IC-Signature")
            if any(len(self.headers.get_all(name, [])) != 1 for name in required):
                return self._respond(400, {"error": "ambiguous_or_missing_headers"})
            if self.headers.get("Transfer-Encoding"):
                return self._respond(400, {"error": "unsupported_transfer_encoding"})
            if self.headers.get_content_type() != "application/json":
                return self._respond(415, {"error": "unsupported_content_type"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._respond(400, {"error": "invalid_content_length"})
            if length <= 0 or length > MAX_BODY:
                return self._respond(413, {"error": "invalid_body_length"})
            raw = self.rfile.read(length)
            status, result = gateway.accept(raw, dict(self.headers))
            self._respond(status, result)

    server = ThreadingHTTPServer(("127.0.0.1", int(os.getenv("IMPERIAL_GATEWAY_PORT", "8765"))),
                                  Handler)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


if __name__ == "__main__":
    serve()
