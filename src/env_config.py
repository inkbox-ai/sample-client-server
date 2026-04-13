"""
src/env_config.py

Centralized environment configuration.
"""

import os

from dotenv import load_dotenv

load_dotenv()

# Env class

class EnvConfig():
    """
    Centralized configuration for environment variables.
    """

    # Inkbox credentials

    INKBOX_SIGNING_KEY: str | None = os.getenv("INKBOX_SIGNING_KEY")
    # Inkbox API key; unused by the server today, but wire it in if you extend
    # this repo with `inkbox` SDK client code (send email, place call, etc.)
    INKBOX_API_KEY: str | None = os.getenv("INKBOX_API_KEY")


    # Webhook server

    LISTEN_PORT: int = int(os.getenv("LISTEN_PORT", "8080"))
    # Path prefix when mounted behind a CDN with path-based routing (e.g. "my-agent")
    PATH_PREFIX: str = os.getenv("PATH_PREFIX", "").strip("/")


    # Phone webhook behavior

    # If true, incoming_call webhooks respond with {"action": "answer"} (default true)
    INKBOX_PHONE_AUTO_ANSWER: bool = os.getenv(
        "INKBOX_PHONE_AUTO_ANSWER", "true"
    ).strip().lower() in {"1", "true", "yes", "on"}

    # WebSocket URL Inkbox should connect to for live call media
    INKBOX_PHONE_CLIENT_WEBSOCKET_URL: str = os.getenv("INKBOX_PHONE_CLIENT_WEBSOCKET_URL", "")


    # Phone media-stream server

    INKBOX_PHONE_MEDIA_HOST: str = os.getenv("INKBOX_PHONE_MEDIA_HOST", "0.0.0.0")
    INKBOX_PHONE_MEDIA_PORT: int = int(os.getenv("INKBOX_PHONE_MEDIA_PORT", "8090"))
