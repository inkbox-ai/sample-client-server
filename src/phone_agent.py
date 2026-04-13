"""
src/phone_agent.py

Small OpenAI-powered phone agent used by the sample WebSocket server.
Inkbox handles speech-to-text and text-to-speech; this module only turns
final caller transcripts into streamed text replies.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress

from fastapi import WebSocket
from openai import AsyncOpenAI

from data_models.phone_media import TextEvent

logger = logging.getLogger(__name__)

PHONE_AGENT_MODEL = "gpt-5.1"

PHONE_AGENT_SYSTEM_PROMPT = (
    "You are the Inkbox interactive demo AI phone assistant. This is a live phone call. "
    "Use natural spoken language only: no markdown, no bullets, no emojis, no formatting. "
    "Keep responses concise, warm, and useful, usually one or two sentences. "
    "Give the demo greeting only once at the beginning of the call. "
    "After that, continue the conversation normally and do not repeat the intro unless asked. "
    "If the caller says goodbye or clearly wants to end the call, say a brief farewell. "
    "Inkbox is an identity and communications platform for AI agents and applications. "
    "It lets developers give agents real communication surfaces: email mailboxes, phone "
    "numbers for calls, inbound SMS webhooks, and secret vaults for securely storing "
    "credentials or sensitive agent context. Phone numbers can receive calls and incoming "
    "texts; outbound SMS is not part of this demo. "
    "This sample repo is a tiny customer-owned server. On startup, it opens an ngrok tunnel "
    "and patches the developer's Inkbox phone numbers and mailboxes so webhooks and the live "
    "phone WebSocket point back to this local process. When someone calls the configured "
    "phone number, Inkbox sends an incoming-call webhook here, this server answers it, and "
    "Inkbox opens a WebSocket to stream the live call. Inkbox handles speech-to-text and "
    "text-to-speech; this server receives final transcripts, asks OpenAI for the next reply, "
    "and streams text back for Inkbox to speak. "
    "If someone asks how to set up this repo, explain the steps briefly: clone the sample "
    "repo; copy .env.example to .env; get an Inkbox API key from the Inkbox console for "
    "patching phone numbers and mailboxes; get an Inkbox webhook signing key from the "
    "Inkbox webhooks console for verifying inbound webhooks and WebSocket handshakes; "
    "get an ngrok authtoken from the ngrok dashboard authtoken page so the local server "
    "can expose a public HTTPS URL; get an OpenAI API key from the OpenAI platform for "
    "the demo phone agent; put those values in .env as INKBOX_API_KEY, INKBOX_SIGNING_KEY, "
    "NGROK_AUTHTOKEN, and OPENAI_API_KEY; then run uv run python src/server.py. Explain "
    "that startup opens ngrok, patches Inkbox objects to the new URL, and starts the "
    "webhook plus phone WebSocket server."
)

GREETING_PROMPT = (
    "This is the first turn of the call. Briefly say this is an Inkbox AI phone "
    "agent demo, then offer to explain how this sample repo is set up or answer "
    "whatever else they want to try."
)


class PhoneAgent:
    """Conversation state and streamed response generation for one phone call."""

    def __init__(self, *, api_key: str) -> None:
        self._client = AsyncOpenAI(api_key=api_key)
        self._conversation: list[dict[str, str]] = [
            {"role": "system", "content": PHONE_AGENT_SYSTEM_PROMPT},
        ]
        self._response_task: asyncio.Task | None = None
        self._has_greeted = False

    async def close(self) -> None:
        """Cancel any active response task."""
        await self.cancel_active_response("call_closed")

    async def cancel_active_response(self, reason: str) -> None:
        """Cancel any in-flight assistant response."""
        if self._response_task and not self._response_task.done():
            self._response_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._response_task
            logger.info("Phone agent canceled in-flight response (%s)", reason)
        self._response_task = None

    async def greet(self, websocket: WebSocket) -> None:
        """Start the one-time greeting response."""
        if self._has_greeted:
            return
        self._has_greeted = True
        await self.cancel_active_response("new_greeting")
        self._conversation.append({"role": "user", "content": GREETING_PROMPT})
        self._response_task = asyncio.create_task(self._stream_response(websocket))

    async def handle_final_transcript(self, websocket: WebSocket, text: str) -> None:
        """Add a caller utterance and start a fresh streamed reply."""
        clean_text = " ".join(text.split())
        if not clean_text:
            return
        await self.cancel_active_response("caller_turn")
        self._conversation.append({"role": "user", "content": clean_text})
        self._response_task = asyncio.create_task(self._stream_response(websocket))

    async def _stream_response(self, websocket: WebSocket) -> None:
        """Stream one assistant response as Inkbox text deltas."""
        full_response = ""
        try:
            stream = await self._client.chat.completions.create(
                model=PHONE_AGENT_MODEL,
                messages=self._conversation,
                stream=True,
            )

            async for chunk in stream:
                delta = chunk.choices[0].delta
                if not delta.content:
                    continue
                full_response += delta.content
                if not delta.content.strip():
                    continue
                await websocket.send_text(
                    TextEvent(delta=delta.content).model_dump_json(exclude_none=True)
                )

            await websocket.send_text(TextEvent(done=True).model_dump_json(exclude_none=True))
            self._conversation.append({"role": "assistant", "content": full_response})
            logger.info("Phone agent sent response (%d chars)", len(full_response))
        except asyncio.CancelledError:
            with suppress(Exception):
                await websocket.send_text(TextEvent(done=True).model_dump_json(exclude_none=True))
            raise
