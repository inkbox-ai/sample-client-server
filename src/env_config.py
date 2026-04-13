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

    # Inkbox signing

    # Webhook signing secret. Required when INKBOX_REQUIRE_SIGNATURE=true
    # (the default). Can be left unset in dev if you disable verification.
    INKBOX_SIGNING_KEY: str | None = os.getenv("INKBOX_SIGNING_KEY")

    # OpenAI key used by the live sample phone agent.
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "").strip()

    # When true (default), the /webhook HTTP endpoint and the
    # /phone/media/ws WebSocket handshake both reject requests that
    # lack a valid X-Inkbox-Signature. Set to "false" for local testing
    # only.
    INKBOX_REQUIRE_SIGNATURE: bool = os.getenv(
        "INKBOX_REQUIRE_SIGNATURE", "true",
    ).strip().lower() in {"1", "true", "yes", "on"}


    # Webhook server

    LISTEN_PORT: int = int(os.getenv("LISTEN_PORT", "8080"))

    # ngrok auto-tunnel + Inkbox auto-patching

    # Required. A pyngrok tunnel is opened on LISTEN_PORT at startup and
    # every phone number + mailbox in the org is PATCHed to point at it.
    NGROK_AUTHTOKEN: str = os.getenv("NGROK_AUTHTOKEN", "").strip()

    # Inkbox API key used by the bootstrap step to list + update phone
    # numbers and mailboxes. Required.
    INKBOX_API_KEY: str = os.getenv("INKBOX_API_KEY", "").strip()
