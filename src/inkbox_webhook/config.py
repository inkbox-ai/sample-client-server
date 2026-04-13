"""Configuration loader -- reads .env from project root.
src/inkbox_webhook/config.py
"""

import os
from pathlib import Path
from typing import TypedDict


class Config(TypedDict):
    """Typed application configuration returned by ``get_config``."""

    signing_key: str
    api_key: str
    listen_port: int
    path_prefix: str
    spool_dir: Path
    processed_dir: Path
    failed_dir: Path
    openclaw_gateway_port: int
    openclaw_hooks_token: str
    phone_auto_answer: bool
    phone_client_websocket_url: str
    phone_media_host: str
    phone_media_port: int


PROJECT_ROOT = Path(__file__).parent.parent.parent
SPOOL_DIR = PROJECT_ROOT / "spool"


def load_env() -> None:
    """Load .env file into environment (no external deps)."""
    env_file = PROJECT_ROOT / ".env"
    if not env_file.exists():
        raise RuntimeError(
            f"Missing {env_file} -- copy .env.example and fill in your secrets"
        )
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


def get_config() -> Config:
    """Return the typed application configuration, loading ``.env`` first."""
    load_env()
    signing_key = os.environ.get("INKBOX_SIGNING_KEY", "")
    if not signing_key:
        raise RuntimeError("INKBOX_SIGNING_KEY not set in .env")
    prefix = os.environ.get("PATH_PREFIX", "").strip("/")

    auto_answer_env = os.environ.get("INKBOX_PHONE_AUTO_ANSWER", "true").strip().lower()
    phone_auto_answer = auto_answer_env in {"1", "true", "yes", "on"}

    return {
        "signing_key": signing_key,
        "api_key": os.environ.get("INKBOX_API_KEY", ""),
        "listen_port": int(os.environ.get("LISTEN_PORT", "8080")),
        "path_prefix": f"/{prefix}" if prefix else "",
        "spool_dir": SPOOL_DIR,
        "processed_dir": SPOOL_DIR / "processed",
        "failed_dir": SPOOL_DIR / "failed",
        "openclaw_gateway_port": int(os.environ.get("OPENCLAW_GATEWAY_PORT", "18789")),
        "openclaw_hooks_token": os.environ.get("OPENCLAW_HOOKS_TOKEN", ""),
        "phone_auto_answer": phone_auto_answer,
        "phone_client_websocket_url": os.environ.get("INKBOX_PHONE_CLIENT_WEBSOCKET_URL", ""),
        "phone_media_host": os.environ.get("INKBOX_PHONE_MEDIA_HOST", "0.0.0.0"),
        "phone_media_port": int(os.environ.get("INKBOX_PHONE_MEDIA_PORT", "8090")),
    }
