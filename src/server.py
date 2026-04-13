"""
src/server.py

Inkbox sample client/server — a single FastAPI process that:

1. Receives Inkbox webhooks over HTTP at ``POST /webhook`` (mail events,
   incoming texts, incoming calls), verifies signatures via
   ``inkbox.verify_webhook``, writes payloads to disk, and logs a
   domain-aware summary. Returns an action body for ``incoming_call``
   events; plain ``200 OK`` for everything else.

2. Handles live phone-media sessions at ``WebSocket /phone/media/ws`` —
   Inkbox opens this connection once a call is answered, streams
   transcript events to us, and consumes ``text`` frames we send back
   for the caller to hear via Inkbox-managed TTS.

Both surfaces live in one ASGI process served by uvicorn. See
``data_models/webhooks.py`` and ``data_models/phone_media.py`` for the
exact shapes exchanged on each side — the app parses every incoming
request using those same Pydantic models.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse
from inkbox import verify_webhook
from pydantic import ValidationError
from starlette.websockets import WebSocketState

from constants import PAYLOADS_DIR
from data_models.phone_media import (
    HANDSHAKE_RESPONSE_HEADERS,
    BargeInEvent,
    CallContext,
    StartEvent,
    StopEvent,
    TranscriptEvent,
)
from data_models.webhooks import (
    IncomingCallActionResponse,
    MailWebhookPayload,
    PhoneIncomingCallWebhookPayload,
    PhoneIncomingTextWebhookPayload,
)
from env_config import EnvConfig
from ngrok_bootstrap import setup_ngrok_and_patch_inkbox
from phone_agent import PhoneAgent

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Inkbox sample client/server",
    version="0.1.0",
)


# ---------------------------------------------------------------------------
# Signature verification helpers
# ---------------------------------------------------------------------------


def _verify_signature_or_raise(body: bytes, headers: dict[str, str]) -> None:
    """
    Verify an ``X-Inkbox-Signature`` header against ``body``.

    Raises ``HTTPException(401)`` if verification is required and fails.
    When ``INKBOX_REQUIRE_SIGNATURE`` is false and no signature header
    is present, returns silently.
    """
    has_header = bool(headers.get("x-inkbox-signature"))
    if not has_header:
        if EnvConfig.INKBOX_REQUIRE_SIGNATURE:
            logger.info("REJECTED — missing X-Inkbox-Signature header")
            raise HTTPException(status_code=401, detail="Missing signature")
        return
    if not EnvConfig.INKBOX_SIGNING_KEY:
        logger.info("REJECTED — signature header present but no signing key configured")
        raise HTTPException(status_code=401, detail="Server not configured to verify")
    if not verify_webhook(
        payload=body,
        headers=headers,
        secret=EnvConfig.INKBOX_SIGNING_KEY,
    ):
        logger.info("REJECTED — invalid signature")
        raise HTTPException(status_code=401, detail="Invalid signature")


# ---------------------------------------------------------------------------
# Webhook parsing + dispatch
# ---------------------------------------------------------------------------

# Type alias for whichever concrete webhook payload model parsed successfully.
ParsedWebhook = (
    MailWebhookPayload
    | PhoneIncomingTextWebhookPayload
    | PhoneIncomingCallWebhookPayload
)


def _parse_webhook(body: bytes) -> ParsedWebhook:
    """
    Parse ``body`` into the concrete Pydantic model for its shape.

    Tries each known shape in order: mail (enveloped, ``event_type``
    starts with ``message.``), phone text (enveloped, ``text.*``), phone
    incoming-call (flat). Raises ``HTTPException(422)`` if none match.
    """
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise HTTPException(status_code=422, detail="Webhook body must be a JSON object")

    event_type = data.get("event_type")
    if isinstance(event_type, str):
        if event_type.startswith("message."):
            return MailWebhookPayload.model_validate(data)
        if event_type.startswith("text."):
            return PhoneIncomingTextWebhookPayload.model_validate(data)

    # No envelope → incoming-call shape.
    return PhoneIncomingCallWebhookPayload.model_validate(data)


def summarize_webhook_payload(payload: ParsedWebhook) -> str:
    """
    Return a compact one-line log summary for a parsed webhook payload.

    Parameters:
        payload (ParsedWebhook): A validated webhook model instance.

    Returns:
        str: Human-readable summary suitable for logging.
    """
    if isinstance(payload, MailWebhookPayload):
        m = payload.data.message
        return (
            f"Inkbox mail webhook: {payload.event_type.value}. "
            f"From: {m.from_address}. "
            f"Subject: {m.subject or '-'}. "
            f"Status: {m.status.value}."
        )
    if isinstance(payload, PhoneIncomingTextWebhookPayload):
        t = payload.data.text_message
        return (
            f"Inkbox text webhook: {payload.event_type}. "
            f"From: {t.remote_phone_number} → {t.local_phone_number}. "
            f"Text: {(t.text or '')[:160]}"
        )
    # PhoneIncomingCallWebhookPayload
    return (
        f"Inkbox phone webhook: incoming_call. "
        f"Call ID: {payload.id}. "
        f"From: {payload.remote_phone_number} → {payload.local_phone_number}. "
        f"Status: {payload.status.value}."
    )


def build_webhook_http_response(payload: ParsedWebhook) -> IncomingCallActionResponse | None:
    """
    Return the response body for webhooks that require one.

    Only incoming-call webhooks expect a structured response. Mail and
    text webhooks return ``None``; the caller should reply with a plain
    ``200 OK``.

    Parameters:
        payload (ParsedWebhook): A validated webhook model instance.

    Returns:
        IncomingCallActionResponse | None: Response body to send, or
        ``None`` if no body is required.
    """
    if not isinstance(payload, PhoneIncomingCallWebhookPayload):
        return None
    # client_websocket_url is stored on the phone number itself (patched at
    # boot by ngrok_bootstrap), so we don't need to override it here.
    return IncomingCallActionResponse(action="answer")


# ---------------------------------------------------------------------------
# Payload persistence
# ---------------------------------------------------------------------------


def _persist_payload(
    *,
    body_bytes: bytes,
    headers: dict[str, str],
    request_path: str,
) -> str:
    """Write the raw webhook body + metadata to ``PAYLOADS_DIR`` and return the filename."""
    PAYLOADS_DIR.mkdir(exist_ok=True)
    ts_ms = int(time.time() * 1_000)
    payload_file = PAYLOADS_DIR / f"{ts_ms}.json"
    try:
        raw = json.loads(body_bytes) if body_bytes else {}
    except json.JSONDecodeError:
        raw = {"raw": body_bytes.decode("utf-8", errors="replace")}
    with open(payload_file, mode="w") as f:
        json.dump(
            obj={
                "received_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "path": request_path,
                "inkbox_request_id": headers.get("x-inkbox-request-id", ""),
                "headers": {"content-type": headers.get("content-type", "")},
                "payload": raw,
            },
            fp=f,
            indent=2,
        )
    return payload_file.name


# ---------------------------------------------------------------------------
# HTTP routes
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> PlainTextResponse:
    """Liveness endpoint. Always returns 200 OK."""
    return PlainTextResponse("OK")


@app.post("/webhook", response_model=None)
async def webhook(request: Request) -> JSONResponse | PlainTextResponse:
    """
    Inkbox webhook receiver.

    1. Reads the raw body (needed for HMAC verification — do not parse
       and re-serialize).
    2. Verifies ``X-Inkbox-Signature`` if required / present.
    3. Parses the body into the concrete Pydantic model for its shape.
    4. Persists the raw payload to ``payloads/<ts_ms>.json``.
    5. Logs a compact summary.
    6. Returns an ``IncomingCallActionResponse`` for incoming-call
       webhooks; a plain ``200 OK`` otherwise.
    """
    body = await request.body()
    if len(body) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Payload too large")

    headers = {k.lower(): v for k, v in request.headers.items()}
    _verify_signature_or_raise(body, headers)

    try:
        payload = _parse_webhook(body)
    except ValidationError as exc:
        logger.info("REJECTED — validation error: %s", exc)
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    saved_name = _persist_payload(
        body_bytes=body,
        headers=headers,
        request_path=request.url.path,
    )
    logger.info("Saved -> %s", saved_name)
    logger.info(summarize_webhook_payload(payload))

    response_body = build_webhook_http_response(payload)
    if response_body is not None:
        return JSONResponse(response_body.model_dump(exclude_none=True))
    return PlainTextResponse("OK")


# ---------------------------------------------------------------------------
# WebSocket: phone media stream
# ---------------------------------------------------------------------------


def _parse_call_context(headers: Any) -> CallContext:
    """Parse the ``X-Call-Context`` handshake header into a ``CallContext``."""
    raw = headers.get("x-call-context", "") if headers else ""
    if not raw:
        return CallContext()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return CallContext()
    if not isinstance(data, dict):
        return CallContext()
    try:
        return CallContext.model_validate(data)
    except ValidationError:
        return CallContext()


def _verify_ws_handshake_signature(headers: dict[str, str]) -> bool:
    """
    Verify the optional signature on a WS upgrade request.

    Per the Inkbox spec, the signed body for a WS handshake is the raw
    value of the ``X-Call-Context`` header. Returns ``True`` when the
    request either passes verification or verification is not required
    and no signature header is present.
    """
    has_header = bool(headers.get("x-inkbox-signature"))
    if not has_header:
        return not EnvConfig.INKBOX_REQUIRE_SIGNATURE
    if not EnvConfig.INKBOX_SIGNING_KEY:
        return False
    call_context = headers.get("x-call-context", "")
    return verify_webhook(
        payload=call_context.encode("utf-8"),
        headers=headers,
        secret=EnvConfig.INKBOX_SIGNING_KEY,
    )


@app.websocket("/phone/media/ws")
async def phone_media_ws(websocket: WebSocket) -> None:
    """
    Live phone-media WebSocket handler.

    Inkbox opens this connection once a call is answered. We optionally
    verify the handshake signature, accept the upgrade with the
    ``X-Use-Inkbox-*`` opt-in headers, then loop over JSON text frames:
    platform events in, outbound ``text`` frames out.
    """
    headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in websocket.headers.raw}
    if not _verify_ws_handshake_signature(headers):
        logger.info("Call WS REJECTED — invalid or missing handshake signature")
        await websocket.close(code=1008)
        return

    call = _parse_call_context(headers)
    await websocket.accept(
        headers=[
            (k.lower().encode(), v.encode())
            for k, v in HANDSHAKE_RESPONSE_HEADERS.items()
        ],
    )
    logger.info(
        "Call WS connected call_id=%s local=%s direction=%s",
        call.call_id, call.phone_number, call.direction,
    )

    agent = PhoneAgent(api_key=EnvConfig.OPENAI_API_KEY)

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue

            event = data.get("event")
            if event == "start":
                try:
                    StartEvent.model_validate(data)
                except ValidationError:
                    pass
                await agent.greet(websocket)
                continue
            if event == "stop":
                try:
                    parsed_stop = StopEvent.model_validate(data)
                    logger.info(
                        "Call WS stop call_id=%s reason=%s",
                        call.call_id, parsed_stop.reason,
                    )
                except ValidationError:
                    logger.info("Call WS stop call_id=%s", call.call_id)
                await agent.cancel_active_response("stream_stopped")
                break
            if event == "barge_in":
                try:
                    parsed_barge_in = BargeInEvent.model_validate(data)
                    logger.info(
                        "Call WS barge_in call_id=%s trigger=%s interrupted=%s",
                        call.call_id, parsed_barge_in.trigger, parsed_barge_in.tts_interrupted,
                    )
                except ValidationError:
                    pass
                await agent.cancel_active_response("caller_barge_in")
                continue
            if event == "transcript":
                try:
                    transcript = TranscriptEvent.model_validate(data)
                except ValidationError:
                    continue
                if not transcript.is_final:
                    continue
                logger.info("Call WS final transcript call_id=%s text=%s", call.call_id, transcript.text[:160])
                await agent.handle_final_transcript(websocket, transcript.text)
                continue
            # ignore unknown / unmodelled events (e.g. media) — extend here
    except WebSocketDisconnect:
        logger.info("Call WS closed call_id=%s", call.call_id)
    finally:
        await agent.close()
        if websocket.client_state != WebSocketState.DISCONNECTED:
            try:
                await websocket.close()
            except RuntimeError:
                pass


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entrypoint: configure logging and serve the FastAPI app via uvicorn."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if EnvConfig.INKBOX_REQUIRE_SIGNATURE and not EnvConfig.INKBOX_SIGNING_KEY:
        raise RuntimeError(
            "INKBOX_SIGNING_KEY is required when INKBOX_REQUIRE_SIGNATURE=true "
            "(the default). Set the key in .env or export INKBOX_REQUIRE_SIGNATURE=false "
            "for local testing.",
        )
    if not EnvConfig.OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY is required for the sample phone agent.")
    logger.info(
        "Inkbox sample client/server listening on :%d (verify signatures: %s)",
        EnvConfig.LISTEN_PORT,
        EnvConfig.INKBOX_REQUIRE_SIGNATURE,
    )
    logger.info("Payloads directory: %s", PAYLOADS_DIR)
    setup_ngrok_and_patch_inkbox()
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=EnvConfig.LISTEN_PORT,
        log_level="info",
    )


if __name__ == "__main__":
    main()
