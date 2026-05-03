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

import asyncio
import json
import logging
import re
import socket
import time
from contextlib import asynccontextmanager, suppress
from typing import Any

import uvicorn
from data_models.tunnel import TunnelTLSMode
from fastapi import APIRouter, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
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
from inkbox_tunnel_bootstrap import (
    InkboxTunnelClient,
    bootstrap_tunnel,
    patch_inkbox_objects_to_tunnel,
)
from phone_agent import PhoneAgent
from realtime_phone_agent import run_realtime_bridge


# Handshake response headers used when ``USE_OPENAI_REALTIME=true``: opt
# out of Inkbox-managed STT/TTS so the platform sends raw caller audio
# as ``media`` events and forwards our ``media`` events to the caller.
REALTIME_HANDSHAKE_RESPONSE_HEADERS: dict[str, str] = {
    "X-Use-Inkbox-Text-To-Speech": "false",
    "X-Use-Inkbox-Speech-To-Text": "false",
}

logger = logging.getLogger(__name__)


_HEALTHY_STATUS_RE = re.compile(rb"^HTTP/\d\.\d 2\d\d\b")
_LOOPBACK_HEALTH_TIMEOUT_SEC = 5.0


async def _loopback_healthy(port: int, timeout: float = _LOOPBACK_HEALTH_TIMEOUT_SEC) -> bool:
    """HTTP /__loopback_health probe that proves the ASGI app is up.

    A bare TCP connect is not enough: ``main()`` already called
    ``listen()`` on the loopback socket, so the kernel SYN-ACKs even
    if hypercorn crashed before installing an accept handler. Drive
    a real HTTP request through the app to confirm it's serving.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port),
            timeout=timeout,
        )
    except (OSError, asyncio.TimeoutError):
        return False
    try:
        writer.write(
            b"GET /__loopback_health HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Connection: close\r\n\r\n"
        )
        await writer.drain()
        status_line = await asyncio.wait_for(
            reader.readline(), timeout=timeout,
        )
        return bool(_HEALTHY_STATUS_RE.match(status_line))
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        with suppress(Exception):
            writer.close()
            await writer.wait_closed()


async def _await_loopback_until_healthy(port: int, deadline_sec: float = 10.0) -> bool:
    """Probe loopback every 100 ms until healthy or deadline expires."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + deadline_sec
    while loop.time() < deadline:
        if await _loopback_healthy(port, timeout=1.0):
            return True
        await asyncio.sleep(0.1)
    return False


def _serve_loopback_hypercorn(loopback_app: FastAPI, sock: socket.socket) -> asyncio.Task[None]:
    """Spawn hypercorn serving ``loopback_app`` on the pre-bound socket.

    Hypercorn's ``fd://N`` bind syntax wraps the existing fd in a new
    socket object without re-binding or re-listening — the only way to
    hand it a socket main() already owns. ``set_inheritable`` keeps the
    fd alive across the wrap.
    """
    from hypercorn.asyncio import serve  # noqa: PLC0415
    from hypercorn.config import Config  # noqa: PLC0415

    try:
        sock.set_inheritable(True)
    except AttributeError:
        pass

    config = Config()
    config.bind = [f"fd://{sock.fileno()}"]
    # Stream accesslog to stdout so each passthrough request shows
    # method / path / status — the only signal we have post-decrypt.
    config.accesslog = "-"

    async def _run() -> None:
        await serve(loopback_app, config)

    return asyncio.create_task(_run())


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run the loopback hypercorn (passthrough only) and the persistent
    tunnel-client connection for the life of the app."""
    client: InkboxTunnelClient | None = getattr(app.state, "tunnel_client", None)
    loopback_sock: socket.socket | None = getattr(app.state, "loopback_sock", None)
    loopback_app_obj: FastAPI | None = getattr(app.state, "loopback_app", None)
    loopback_task: asyncio.Task[None] | None = None
    tunnel_task: asyncio.Task[None] | None = None

    if loopback_sock is not None and loopback_app_obj is not None:
        loopback_port = loopback_sock.getsockname()[1]
        # Share state with the loopback app so any future route reading
        # request.app.state.tunnel_client sees the same instance.
        loopback_app_obj.state.tunnel_client = client
        loopback_task = _serve_loopback_hypercorn(loopback_app_obj, loopback_sock)
        logger.info(
            "[passthrough] loopback hypercorn starting on 127.0.0.1:%d",
            loopback_port,
        )
        if not await _await_loopback_until_healthy(loopback_port):
            logger.error(
                "[passthrough] loopback /__loopback_health did not respond 2xx; "
                "REFUSING to start the tunnel client. Process stays up so the "
                "failure surfaces to monitoring.",
            )
            client = None  # short-circuit tunnel-client startup below
        else:
            logger.info(
                "[passthrough] loopback /__loopback_health OK on port %d",
                loopback_port,
            )

    if client is not None:
        tunnel_task = asyncio.create_task(client.serve_forever())
    try:
        yield
    finally:
        if client is not None:
            await client.aclose()
        if tunnel_task is not None:
            tunnel_task.cancel()
            try:
                await tunnel_task
            except asyncio.CancelledError:
                pass
        if loopback_task is not None:
            loopback_task.cancel()
            try:
                await loopback_task
            except (asyncio.CancelledError, Exception):
                pass
        if loopback_sock is not None:
            with suppress(Exception):
                loopback_sock.close()


app = FastAPI(
    title="Inkbox sample client/server",
    version="0.1.0",
    lifespan=lifespan,
)


# Loopback ASGI surface for passthrough mode. Same routes as ``app``
# (registered below by ``_register_routes``), but no tunnel-client
# lifespan — running the same FastAPI instance under hypercorn would
# re-fire the outer lifespan and double-start the tunnel client.
loopback_app = FastAPI(
    title="Inkbox sample client/server (loopback)",
    version="0.1.0",
)


@loopback_app.get("/__loopback_health")
async def _loopback_health() -> PlainTextResponse:
    """Loopback hypercorn liveness probe.

    MUST NOT be gated by signature/auth dependencies — the bootstrap
    health check sends an unsigned request, and any future global auth
    middleware would otherwise return non-2xx and trigger a misleading
    "loopback unhealthy" startup error.
    """
    return PlainTextResponse("OK")


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
    # client_websocket_url is stored on the phone number itself (patched
    # at boot by inkbox_tunnel_bootstrap), so we don't need to override
    # it here.
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


# Routes are registered on a router and then mounted on both ``app`` and
# ``loopback_app`` so the loopback hypercorn (passthrough mode) serves
# the same surface the third party would otherwise hit at the edge.
router = APIRouter()


@router.get("/health")
async def health() -> PlainTextResponse:
    """Liveness endpoint. Always returns 200 OK."""
    return PlainTextResponse("OK")


@router.post("/webhook", response_model=None)
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


@router.websocket("/phone/media/ws")
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
    use_realtime = EnvConfig.USE_OPENAI_REALTIME
    accept_headers = (
        REALTIME_HANDSHAKE_RESPONSE_HEADERS if use_realtime else HANDSHAKE_RESPONSE_HEADERS
    )
    await websocket.accept(
        headers=[
            (k.lower().encode(), v.encode())
            for k, v in accept_headers.items()
        ],
    )
    logger.info(
        "Call WS connected call_id=%s local=%s direction=%s mode=%s",
        call.call_id, call.phone_number, call.direction,
        "openai-realtime" if use_realtime else "inkbox-tts-stt",
    )

    if use_realtime:
        try:
            await run_realtime_bridge(
                websocket=websocket,
                api_key=EnvConfig.OPENAI_API_KEY,
                model=EnvConfig.OPENAI_REALTIME_MODEL,
                call_id=call.call_id,
            )
        except WebSocketDisconnect:
            pass
        finally:
            logger.info("Call WS closed call_id=%s", call.call_id)
            if websocket.client_state != WebSocketState.DISCONNECTED:
                with suppress(RuntimeError):
                    await websocket.close()
        return

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


app.include_router(router)
loopback_app.include_router(router)


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

    # 1. Ensure the Inkbox tunnel exists (mode-aware). For passthrough
    #    this also generates the keypair, gets a signed cert via
    #    /sign-csr, and persists everything to the state dir.
    bundle = bootstrap_tunnel()

    # 2. Patch all phone numbers + mailboxes to the public host.
    patch_inkbox_objects_to_tunnel(bundle.public_host)

    # 3. For passthrough mode, pre-bind the loopback listening socket
    #    here (synchronously) so the port is known before the tunnel
    #    client constructor and the kernel queues SYNs the moment we
    #    publish it. listen() is required — bind() alone gives
    #    ECONNREFUSED on dial.
    loopback_port: int | None = None
    loopback_sock: socket.socket | None = None
    if bundle.tls_mode is TunnelTLSMode.PASSTHROUGH:
        loopback_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        loopback_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        loopback_sock.bind(("127.0.0.1", EnvConfig.INKBOX_TUNNEL_LOOPBACK_PORT))
        loopback_sock.listen(128)
        loopback_sock.setblocking(False)
        loopback_port = loopback_sock.getsockname()[1]
        logger.info(
            "[passthrough] loopback listening socket bound to 127.0.0.1:%d",
            loopback_port,
        )

    app.state.loopback_sock = loopback_sock
    app.state.loopback_app = loopback_app if loopback_sock is not None else None

    # 4. Build + register the tunnel client. Started in the lifespan hook.
    app.state.tunnel_client = InkboxTunnelClient(
        tunnel_id=bundle.tunnel_id,
        secret=bundle.secret,
        zone=EnvConfig.INKBOX_TUNNEL_ZONE,
        pool_size=EnvConfig.INKBOX_TUNNEL_POOL_SIZE,
        local_app=app,
        tls_terminator=bundle.tls_terminator,
        loopback_port=loopback_port,
    )

    # Pass the FastAPI instance directly. Using the import string
    # ("server:app") would have uvicorn re-import the module fresh,
    # producing a *different* `app` whose `.state.tunnel_client` is
    # unset — and the lifespan would silently no-op the tunnel client.
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=EnvConfig.LISTEN_PORT,
        log_level="info",
    )


if __name__ == "__main__":
    main()
