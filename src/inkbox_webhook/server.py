"""Inkbox webhook receiver.
src/inkbox_webhook/server.py

Listens for incoming webhooks, validates signatures per the Inkbox spec,
and writes parsed payloads to the spool directory for pickup.

Signature scheme (https://inkbox.ai/docs/api/mail/webhooks):
  Headers: X-Inkbox-Request-ID, X-Inkbox-Timestamp, X-Inkbox-Signature
  Signed content: {request_id}.{timestamp}.{raw_body}
  Signature header value: sha256=<hex_digest>
  Algorithm: HMAC-SHA256 with your organization's signing key
  Timestamp tolerance: 300 seconds
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, cast

from .config import Config, get_config
from .handlers.dispatch import build_webhook_http_response, summarize_webhook_payload

logger = logging.getLogger(__name__)

CONFIG: Config = cast(Config, {})

MAX_TIMESTAMP_DRIFT = 300  # seconds


def trigger_openclaw_wake(summary: str) -> None:
    """Wake OpenClaw via the gateway's HTTP hooks endpoint."""
    port = CONFIG.get("openclaw_gateway_port", 18789)
    token = CONFIG.get("openclaw_hooks_token", "")
    url = f"http://127.0.0.1:{port}/hooks/wake"
    body = json.dumps({"text": summary, "mode": "now"}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info(f"[{time.strftime('%H:%M:%S')}] OpenClaw wake -> {resp.status}")
    except Exception as exc:
        logger.info(f"[{time.strftime('%H:%M:%S')}] OpenClaw wake failed: {exc}")


def verify_signature(
    body: bytes,
    request_id: str,
    timestamp: str,
    signature: str,
    key: str,
) -> bool:
    """Verify Inkbox webhook signature.

    Returns True if valid, False otherwise.
    """
    try:
        ts = int(timestamp)
    except (ValueError, TypeError):
        return False
    if abs(time.time() - ts) > MAX_TIMESTAMP_DRIFT:
        return False

    if not signature.startswith("sha256="):
        return False
    received_digest = signature[len("sha256="):]

    message = f"{request_id}.{timestamp}.".encode() + body
    expected_digest = hmac.new(
        key=key.encode(),
        msg=message,
        digestmod=hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected_digest, received_digest)


class WebhookHandler(BaseHTTPRequestHandler):
    """HTTP handler that authenticates, spools, and dispatches Inkbox webhooks."""

    def _match_path(self, suffix: str) -> bool:
        """Return True if the request path equals ``path_prefix + suffix``."""
        expected = CONFIG["path_prefix"] + suffix
        return self.path == expected

    def do_POST(self) -> None:
        """Handle a POSTed webhook: verify signature, spool, wake, and reply."""
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
        timestamp = self.headers.get("X-Inkbox-Timestamp", "")
        signature = self.headers.get("X-Inkbox-Signature", "")

        if signature:
            if not verify_signature(
                body, request_id, timestamp, signature, CONFIG["signing_key"]
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
        summary = summarize_webhook_payload(payload)
        trigger_openclaw_wake(summary)

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
