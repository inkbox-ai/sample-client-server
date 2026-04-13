"""
src/media_stream.py

Inkbox phone media stream WebSocket server.

This server handles live call WebSocket sessions. It is intentionally simple:
- Declares Inkbox-managed STT + TTS via handshake response headers.
- Receives transcript events from Inkbox.
- Sends textStream responses for final transcript chunks.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any

from websockets.asyncio.server import ServerConnection, serve
from websockets.datastructures import Headers
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Request, Response

from config import get_config

logger = logging.getLogger(__name__)


def _safe_json(s: str) -> dict[str, Any]:
    """Parse ``s`` as JSON, returning an empty dict on failure or non-object results."""
    try:
        data = json.loads(s)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


@dataclass
class CallSession:
    """Per-connection state extracted from the handshake and call lifecycle events."""

    call_id: str = ""
    local_phone_number: str = ""
    remote_phone_number: str = ""
    direction: str = ""
    call_control_id: str = ""


def _extract_event_name(payload: dict[str, Any]) -> str:
    """Return the event-name field from ``payload``, checking common aliases."""
    for key in ("event", "type", "event_type"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _extract_transcript_text(payload: dict[str, Any]) -> tuple[str, bool]:
    """Return ``(text, is_final)`` from a transcript event payload."""
    candidates: list[dict[str, Any]] = [payload]
    data = payload.get("data")
    if isinstance(data, dict):
        candidates.append(data)
    transcript = payload.get("transcript")
    if isinstance(transcript, dict):
        candidates.append(transcript)

    text = ""
    is_final = False
    for c in candidates:
        for key in ("text", "transcript", "utterance"):
            value = c.get(key)
            if isinstance(value, str) and value.strip() and not text:
                text = value.strip()
        for key in ("is_final", "final", "done"):
            value = c.get(key)
            if isinstance(value, bool):
                is_final = value or is_final
    return text, is_final


def _build_reply_text(user_text: str) -> str:
    """Return a canned conversational reply for a final transcript chunk."""
    if not user_text:
        return "I’m here — can you repeat that?"
    normalized = user_text.lower()

    if any(greet in normalized for greet in ("hello", "hi", "hey")):
        return "Hey — I hear you. What do you need?"
    if "bye" in normalized or "goodbye" in normalized:
        return "Got it. Talk soon — goodbye."

    compact = re.sub(r"\s+", " ", user_text).strip()
    if len(compact) > 220:
        compact = compact[:217] + "..."
    return f"Got it. You said: {compact}"


def _parse_call_context(headers: Headers) -> CallSession:
    """Build a ``CallSession`` from the ``X-Call-Context`` handshake header."""
    raw = headers.get("X-Call-Context", "")
    ctx = _safe_json(raw)
    return CallSession(
        call_id=str(ctx.get("call_id") or ""),
        local_phone_number=str(ctx.get("phone_number") or ""),
        remote_phone_number=str(ctx.get("remote_phone_number") or ""),
        direction=str(ctx.get("direction") or ""),
    )


async def _handle_ws(ws: ServerConnection) -> None:
    """Handle a single call WebSocket: parse context, loop over events, and respond."""
    call = _parse_call_context(ws.request.headers)
    logger.info("Call WS connected call_id=%s remote=%s", call.call_id, call.remote_phone_number)

    try:
        async for raw in ws:
            payload = _safe_json(raw)
            event = _extract_event_name(payload)

            if event == "start":
                for c in (payload, payload.get("data") if isinstance(payload.get("data"), dict) else {}):
                    ccid = c.get("call_control_id")
                    if isinstance(ccid, str) and ccid:
                        call.call_control_id = ccid
                        break
                continue

            if event == "stop":
                logger.info("Call WS stop call_id=%s", call.call_id)
                break

            if event == "barge_in":
                continue

            if event == "transcript":
                text, is_final = _extract_transcript_text(payload)
                if not is_final:
                    continue
                reply = _build_reply_text(text)
                outbound = {
                    "event": "textStream",
                    "text": reply,
                    "done": True,
                }
                await ws.send(json.dumps(outbound))
                continue

    except ConnectionClosed:
        logger.info("Call WS closed call_id=%s", call.call_id)


def _process_request(conn: ServerConnection, request: Request) -> Response | None:
    """Reject WS handshakes whose path does not match the configured media endpoint."""
    cfg = get_config()
    prefix = cfg.get("path_prefix", "")
    expected = f"{prefix}/phone/media/ws" if prefix else "/phone/media/ws"
    if request.path != expected:
        return conn.respond(HTTPStatus.NOT_FOUND, "Not Found")
    return None


def _process_response(
    conn: ServerConnection, request: Request, response: Response
) -> Response:
    """Inject Inkbox-managed STT/TTS opt-in headers onto the handshake response."""
    response.headers["X-Use-Inkbox-Text-To-Speech"] = "true"
    response.headers["X-Use-Inkbox-Speech-To-Text"] = "true"
    return response


async def _run() -> None:
    """Bind and serve the media-stream WebSocket until cancelled."""
    cfg = get_config()
    host = cfg.get("phone_media_host", "0.0.0.0")
    port = int(cfg.get("phone_media_port", 8090))
    prefix = cfg.get("path_prefix", "")
    path = f"{prefix}/phone/media/ws" if prefix else "/phone/media/ws"

    logger.info("Inkbox media WS listening on %s:%s%s", host, port, path)

    async with serve(
        _handle_ws,
        host,
        port,
        process_request=_process_request,
        process_response=_process_response,
        ping_interval=20,
        ping_timeout=20,
        max_size=2**20,
    ):
        await asyncio.Future()


def main() -> None:
    """CLI entrypoint that configures logging and runs the media-stream server."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(_run())


if __name__ == "__main__":
    main()
