"""
src/env_config.py

Centralized environment configuration.
"""

import os

from dotenv import load_dotenv

from inkbox.tunnels import TLSMode

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

    # When true, bypass Inkbox-managed STT/TTS and bridge the live phone
    # WebSocket directly to OpenAI's Realtime API (g711_ulaw both ways).
    # Used to isolate tunnel transport from STT/TTS plumbing during
    # end-to-end testing.
    USE_OPENAI_REALTIME: bool = os.getenv(
        "USE_OPENAI_REALTIME", "false",
    ).strip().lower() in {"1", "true", "yes", "on"}

    # Realtime model identifier. The GA model name is "gpt-realtime"; older
    # previews used "gpt-4o-realtime-preview". Override via env if you need
    # a specific snapshot.
    OPENAI_REALTIME_MODEL: str = os.getenv(
        "OPENAI_REALTIME_MODEL", "gpt-realtime",
    ).strip()

    # When true (default), the /webhook HTTP endpoint and the
    # /phone/media/ws WebSocket handshake both reject requests that
    # lack a valid X-Inkbox-Signature. Set to "false" for local testing
    # only.
    INKBOX_REQUIRE_SIGNATURE: bool = os.getenv(
        "INKBOX_REQUIRE_SIGNATURE", "true",
    ).strip().lower() in {"1", "true", "yes", "on"}


    # Webhook server

    LISTEN_PORT: int = int(os.getenv("LISTEN_PORT", "8080"))

    # Inkbox API key used by the bootstrap step to list + update phone
    # numbers and mailboxes, and to call the tunnels control plane.
    INKBOX_API_KEY: str = os.getenv("INKBOX_API_KEY", "").strip()

    # --- Inkbox tunnel ----------------------------------------------------

    # Customer-chosen subdomain label. Must match `^[a-z0-9][a-z0-9-]{0,62}$`,
    # globally unique within the env (two orgs can't both own
    # `foo.development.inkboxwire.com`). Reserved labels — `api`, `mcp`,
    # `admin`, `console`, `mail`, `www`, `pr-*`, `console-pr-*` — are 409'd
    # on create. Required.
    INKBOX_TUNNEL_NAME: str = os.getenv("INKBOX_TUNNEL_NAME", "").strip()

    # `edge` (default) | `passthrough`. Fixed at tunnel creation; switching
    # modes requires deleting the existing tunnel and creating a new one
    # under a different name (the old name is locked for 60 days).
    INKBOX_TUNNEL_TLS_MODE: TLSMode = TLSMode(
        os.getenv("INKBOX_TUNNEL_TLS_MODE", TLSMode.EDGE.value).strip().lower(),
    )

    # Per-tunnel data-plane secret. Returned ONCE from POST /api/v1/tunnels
    # at creation time. The bootstrap will (a) try to use this if set,
    # (b) otherwise read from the local state file, (c) otherwise create
    # a tunnel and write the secret to the state file. Argon2id-hashed at
    # rest server-side.
    INKBOX_TUNNEL_SECRET: str = os.getenv("INKBOX_TUNNEL_SECRET", "").strip()

    # Pinned to development.
    INKBOX_API_BASE: str = os.getenv(
        "INKBOX_API_BASE", "https://development.inkbox.ai/api/v1",
    )
    INKBOX_TUNNEL_ZONE: str = os.getenv(
        "INKBOX_TUNNEL_ZONE", "development.inkboxwire.com",
    )

    # Number of parked /_system/intake streams to keep in the pool. Server
    # honors `x-pool-size` up to 32 by default.
    INKBOX_TUNNEL_POOL_SIZE: int = int(os.getenv("INKBOX_TUNNEL_POOL_SIZE", "32"))

    # State directory. Holds .inkbox-tunnel-state.json plus, for passthrough
    # mode, the local keypair + signed cert chain.
    INKBOX_TUNNEL_STATE_DIR: str = os.getenv(
        "INKBOX_TUNNEL_STATE_DIR", "./.inkbox-tunnel-state",
    )

    # Loopback hypercorn bind port for passthrough TLS termination. ``0``
    # auto-picks a free ephemeral port at bind time. The plaintext sink
    # is bound to ``127.0.0.1`` only — never expose this externally.
    INKBOX_TUNNEL_LOOPBACK_PORT: int = int(
        os.getenv("INKBOX_TUNNEL_LOOPBACK_PORT", "0"),
    )
