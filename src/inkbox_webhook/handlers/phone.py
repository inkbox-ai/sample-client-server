"""
src/inkbox_webhook/handlers/phone.py

Phone-specific webhook helpers.
"""

from __future__ import annotations

from typing import Any

from inkbox_webhook.config import Config


def _pick_first(*values: Any) -> str:
    """Return the first non-empty stripped string from ``values``, or ``""``."""
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _truncate(text: str, limit: int = 180) -> str:
    """Collapse whitespace in ``text`` and truncate with an ellipsis at ``limit`` chars."""
    text = " ".join(str(text).split())
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _event_type(payload: dict[str, Any]) -> str:
    """Return the event-name field from ``payload``, checking common aliases."""
    return _pick_first(
        payload.get("event"),
        payload.get("type"),
        payload.get("event_type"),
    )


def is_phone_event(payload: dict[str, Any]) -> bool:
    """Return True if ``payload`` is an incoming call/text or a ``call.*`` event."""
    if not isinstance(payload, dict):
        return False
    event = _event_type(payload)
    return event in {"incoming_call", "incoming_text"} or event.startswith("call.")


def summarize_phone_payload(payload: dict[str, Any]) -> str:
    """Build a compact summary for Inkbox phone-related webhook payloads."""
    if not isinstance(payload, dict):
        return "Inkbox phone webhook received. Check the latest spool file."

    event = _event_type(payload) or "unknown"

    call = payload.get("call") if isinstance(payload.get("call"), dict) else {}
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    phone_number = payload.get("phone_number") if isinstance(payload.get("phone_number"), dict) else {}

    call_id = _pick_first(call.get("id"), data.get("call_id"), payload.get("call_id"))
    remote = _pick_first(
        call.get("remote_phone_number"),
        data.get("remote_phone_number"),
        payload.get("remote_phone_number"),
    )
    local = _pick_first(
        call.get("local_phone_number"),
        data.get("local_phone_number"),
        phone_number.get("number"),
        payload.get("local_phone_number"),
    )
    status = _pick_first(call.get("status"), data.get("status"), payload.get("status"))

    parts = [f"Inkbox phone webhook: {event}."]
    if call_id:
        parts.append(f"Call ID: {call_id}.")
    if remote:
        parts.append(f"Remote: {_truncate(remote, 60)}.")
    if local:
        parts.append(f"Local: {_truncate(local, 60)}.")
    if status:
        parts.append(f"Status: {status}.")
    parts.append(
        "Check the newest file in ~/openclaw-config/spool/ and handle phone events carefully. For incoming calls, use the configured TTS/STT call path and escalate to the user on Telegram if context is sensitive or ambiguous."
    )
    return " ".join(parts)


def build_phone_webhook_response(
    payload: dict[str, Any], config: Config
) -> dict[str, Any] | None:
    """Return an HTTP JSON response body for phone webhooks when required.

    Inkbox phone webhooks (incoming_call) expect an action response.
    """
    if not is_phone_event(payload):
        return None

    event = _event_type(payload)
    if event != "incoming_call":
        return None

    auto_answer = bool(config.get("phone_auto_answer", True))
    if not auto_answer:
        return {"action": "reject"}

    response: dict[str, Any] = {"action": "answer"}
    ws_url = config.get("phone_client_websocket_url") or ""
    if isinstance(ws_url, str) and ws_url.strip():
        response["client_websocket_url"] = ws_url.strip()
    return response
