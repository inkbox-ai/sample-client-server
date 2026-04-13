"""
src/server.py

Inkbox webhook receiver.

Listens for incoming webhooks, verifies signatures via ``inkbox.verify_webhook``,
writes parsed payloads to the spool directory, and logs a domain-aware summary.
Downstream processing is the user's responsibility — tail the spool dir from
whatever agent/workflow you like.
"""

from __future__ import annotations

import json
import logging
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, cast

from inkbox import verify_webhook

from config import Config, get_config
from handlers.dispatch import build_webhook_http_response, summarize_webhook_payload

logger = logging.getLogger(__name__)

CONFIG: Config = cast(Config, {})


class WebhookHandler(BaseHTTPRequestHandler):
    """HTTP handler that authenticates, spools, and dispatches Inkbox webhooks."""

    def _match_path(self, suffix: str) -> bool:
        """Return True if the request path equals ``path_prefix + suffix``."""
        expected = CONFIG["path_prefix"] + suffix
        return self.path == expected

    def do_POST(self) -> None:
        """Handle a POSTed webhook: verify signature, spool, log a summary, and reply."""
        if not self._match_path("/webhook"):
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 10 * 1024 * 1024:
            self.send_response(413)
            self.end_headers()
            return

        body = self.rfile.read(content_length)

        request_id = self.headers.get("X-Inkbox-Request-ID", "")
        header_map = {k: v for k, v in self.headers.items()}

        if header_map.get("X-Inkbox-Signature"):
            if not verify_webhook(
                payload=body,
                headers=header_map,
                secret=CONFIG["signing_key"],
            ):
                logger.info(f"[{time.strftime('%H:%M:%S')}] REJECTED -- invalid signature")
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Invalid signature")
                return

        payload: dict[str, Any]
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {"raw": body.decode("utf-8", errors="replace")}

        spool_dir: Path = CONFIG["spool_dir"]
        spool_dir.mkdir(exist_ok=True)
        ts_ms = int(time.time() * 1_000)
        spool_file = spool_dir / f"{ts_ms}.json"
        with open(spool_file, "w") as f:
            json.dump(
                {
                    "received_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "path": self.path,
                    "inkbox_request_id": request_id,
                    "headers": {
                        "content-type": self.headers.get("Content-Type", ""),
                    },
                    "payload": payload,
                },
                f,
                indent=2,
            )

        logger.info(f"[{time.strftime('%H:%M:%S')}] Spooled -> {spool_file.name}")
        logger.info(summarize_webhook_payload(payload))

        response_body = build_webhook_http_response(payload, CONFIG)
        if response_body is not None:
            body_json = json.dumps(response_body).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body_json)))
            self.end_headers()
            self.wfile.write(body_json)
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_GET(self) -> None:
        """Handle a GET, returning 200 only on the ``/health`` path."""
        if self._match_path("/health"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        """Redirect ``BaseHTTPRequestHandler`` access logs to our logger."""
        logger.info(f"[{time.strftime('%H:%M:%S')}] {format % args}")


def main() -> None:
    """CLI entrypoint that loads config and serves the webhook receiver forever."""
    global CONFIG
    CONFIG = get_config()
    port = CONFIG["listen_port"]
    prefix = CONFIG["path_prefix"] or "/"
    logger.info(f"Inkbox webhook server listening on :{port} (prefix: {prefix})")
    logger.info(f"Spool directory: {CONFIG['spool_dir']}")
    server = HTTPServer(("0.0.0.0", port), WebhookHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("\nShutting down")
        server.server_close()


if __name__ == "__main__":
    main()
