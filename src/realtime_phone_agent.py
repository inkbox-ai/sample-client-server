"""
src/realtime_phone_agent.py

OpenAI Realtime API bridge for the Inkbox phone media WebSocket.

When ``USE_OPENAI_REALTIME=true`` we opt out of Inkbox-managed STT/TTS
(``X-Use-Inkbox-Text-To-Speech: false`` and
``X-Use-Inkbox-Speech-To-Text: false`` on the WS handshake response) so
Inkbox runs in raw-audio bridge mode: caller audio arrives as ``media``
events with base64 PCMU payload, and we send ``media`` events back to
play to the caller.

PCMU @ 8 kHz is the same wire format OpenAI Realtime calls
``g711_ulaw``, so we don't need to transcode — just pass the base64
payload through both directions.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import suppress

from fastapi import WebSocket
from openai import AsyncOpenAI

logger = logging.getLogger(__name__)


REALTIME_SYSTEM_PROMPT = (
    "You are the Inkbox interactive demo AI phone assistant on a live phone "
    "call. Speak naturally, briefly, one or two sentences at a time. "
    "Greet the caller once at the start, then continue the conversation "
    "normally. Inkbox is an identity and communications platform for AI "
    "agents — phone numbers, mailboxes, signed webhooks, and a tunneled "
    "dev surface. Help the caller understand what Inkbox does or answer "
    "anything else they want to try."
)

REALTIME_VOICE = "alloy"


async def run_realtime_bridge(
    *,
    websocket: WebSocket,
    api_key: str,
    model: str,
    call_id: str,
) -> None:
    """
    Bridge an accepted Inkbox phone-media WebSocket to OpenAI Realtime.

    Two concurrent loops:

    - ``inkbox_to_openai``: parse incoming JSON frames from Inkbox.
      ``media`` → ``input_audio_buffer.append`` to OpenAI. ``stop`` /
      disconnect → break.
    - ``openai_to_inkbox``: read events from the Realtime connection.
      ``response.audio.delta`` → ``media`` event to Inkbox. The Realtime
      server-VAD path drives turn taking automatically; we just relay
      audio.

    The function returns when either side closes or errors.
    """
    client = AsyncOpenAI(api_key=api_key)
    stream_id: str | None = None

    async with client.beta.realtime.connect(model=model) as conn:
        await conn.session.update(
            session={
                "modalities": ["audio", "text"],
                "instructions": REALTIME_SYSTEM_PROMPT,
                "voice": REALTIME_VOICE,
                "input_audio_format": "g711_ulaw",
                "output_audio_format": "g711_ulaw",
                "turn_detection": {
                    "type": "server_vad",
                    "threshold": 0.5,
                    "prefix_padding_ms": 300,
                    "silence_duration_ms": 600,
                },
            }
        )
        logger.info("Realtime session.update sent call_id=%s model=%s", call_id, model)

        async def inkbox_to_openai() -> None:
            nonlocal stream_id
            greeted = False
            media_count = 0
            other_events: dict[str, int] = {}
            try:
                while True:
                    raw = await websocket.receive_text()
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(msg, dict):
                        continue
                    event = msg.get("event")
                    if event == "start":
                        stream_id = msg.get("stream_id") or stream_id
                        logger.info(
                            "Realtime got start event call_id=%s stream_id=%s start=%s",
                            call_id, stream_id, msg.get("start"),
                        )
                        if not greeted:
                            greeted = True
                            await conn.response.create(
                                response={
                                    "instructions": (
                                        "Greet the caller in one short sentence. "
                                        "Mention this is the Inkbox AI phone agent demo, "
                                        "and offer to explain how this sample is set up "
                                        "or answer whatever else they want to try."
                                    ),
                                }
                            )
                            logger.info("Realtime sent greeting response.create call_id=%s", call_id)
                        continue
                    if event == "media":
                        payload_b64 = (msg.get("media") or {}).get("payload")
                        if not payload_b64:
                            continue
                        media_count += 1
                        if media_count in (1, 5, 50, 200):
                            logger.info(
                                "Realtime forwarded inbound media call_id=%s count=%d bytes_b64=%d",
                                call_id, media_count, len(payload_b64),
                            )
                        await conn.input_audio_buffer.append(audio=payload_b64)
                        continue
                    if event == "stop":
                        logger.info("Realtime got stop event call_id=%s", call_id)
                        return
                    other_events[event or "<no-event>"] = other_events.get(event or "<no-event>", 0) + 1
                    if other_events[event or "<no-event>"] <= 3:
                        logger.info(
                            "Realtime got unhandled inkbox event call_id=%s event=%s keys=%s",
                            call_id, event, list(msg.keys()),
                        )
            except Exception:
                logger.exception(
                    "Realtime inkbox→openai loop crashed call_id=%s media_count=%d others=%s",
                    call_id, media_count, other_events,
                )

        async def openai_to_inkbox() -> None:
            audio_count = 0
            event_type_counts: dict[str, int] = {}
            try:
                async for event in conn:
                    etype = getattr(event, "type", None) or "<unknown>"
                    event_type_counts[etype] = event_type_counts.get(etype, 0) + 1
                    if event_type_counts[etype] <= 2:
                        logger.info("Realtime got openai event call_id=%s type=%s", call_id, etype)
                    if etype == "response.audio.delta":
                        delta_b64 = getattr(event, "delta", None)
                        if not delta_b64:
                            continue
                        audio_count += 1
                        if audio_count in (1, 5, 50):
                            logger.info(
                                "Realtime forwarded outbound audio chunk call_id=%s count=%d bytes_b64=%d",
                                call_id, audio_count, len(delta_b64),
                            )
                        out: dict = {
                            "event": "media",
                            "media": {
                                "payload": delta_b64,
                                "track": "outbound",
                            },
                        }
                        if stream_id:
                            out["stream_id"] = stream_id
                        await websocket.send_text(json.dumps(out))
                        continue
                    if etype == "response.audio.done":
                        if stream_id:
                            await websocket.send_text(json.dumps({
                                "event": "audio_done",
                                "stream_id": stream_id,
                            }))
                        else:
                            await websocket.send_text(json.dumps({"event": "audio_done"}))
                        continue
                    if etype == "input_audio_buffer.speech_started":
                        try:
                            await websocket.send_text(json.dumps({"event": "clear"}))
                        except Exception:
                            pass
                        continue
                    if etype == "error":
                        logger.warning(
                            "Realtime error event call_id=%s payload=%s",
                            call_id, getattr(event, "error", None),
                        )
                        continue
            except Exception:
                logger.exception(
                    "Realtime openai→inkbox loop crashed call_id=%s audio_count=%d types=%s",
                    call_id, audio_count, event_type_counts,
                )

        in_task = asyncio.create_task(inkbox_to_openai())
        out_task = asyncio.create_task(openai_to_inkbox())
        try:
            done, pending = await asyncio.wait(
                {in_task, out_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for t in pending:
                t.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await t
        finally:
            with suppress(Exception):
                await conn.close()
