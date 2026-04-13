"""
src/handlers/email.py

Email-specific webhook helpers.
"""

from __future__ import annotations

from typing import Any


def _pick_first(*values: Any) -> str:
    """Return the first non-empty stripped string from ``values``, or ``""``."""
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _truncate(text: str, limit: int = 160) -> str:
    """Collapse whitespace in ``text`` and truncate with an ellipsis at ``limit`` chars."""
    text = " ".join(str(text).split())
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def is_email_event(payload: dict[str, Any]) -> bool:
    """Return True if ``payload`` looks like an Inkbox ``message.*`` email event."""
    if not isinstance(payload, dict):
        return False
    event = _pick_first(payload.get("event"), payload.get("type"), payload.get("event_type"))
    return event.startswith("message.")


def summarize_email_payload(payload: dict[str, Any]) -> str:
    """Build a compact summary for Inkbox email-related webhook payloads."""
    if not isinstance(payload, dict):
        return "Inkbox email webhook received. Check the latest payload file."

    event = _pick_first(
        payload.get("event"),
        payload.get("type"),
        payload.get("event_type"),
    ) or "unknown"

    message = payload.get("message") if isinstance(payload.get("message"), dict) else {}
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    mailbox = payload.get("mailbox") if isinstance(payload.get("mailbox"), dict) else {}

    from_value = _pick_first(
        message.get("from"),
        message.get("from_address"),
        data.get("from"),
        payload.get("from"),
        mailbox.get("email_address"),
    )
    subject = _pick_first(
        message.get("subject"),
        data.get("subject"),
        payload.get("subject"),
    )
    snippet = _pick_first(
        message.get("text"),
        message.get("snippet"),
        data.get("text"),
        data.get("snippet"),
        payload.get("text"),
        payload.get("snippet"),
        payload.get("preview"),
    )

    parts = [f"Inkbox email webhook: {event}."]
    if from_value:
        parts.append(f"From: {_truncate(from_value, 120)}.")
    if subject:
        parts.append(f"Subject: {_truncate(subject, 140)}.")
    if snippet:
        parts.append(f"Snippet: {_truncate(snippet, 220)}.")
    return " ".join(parts)
