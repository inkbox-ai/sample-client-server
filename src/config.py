"""
src/config.py

Configuration loader -- reads .env from project root.
"""

import os
from pathlib import Path
from typing import TypedDict

from dotenv import load_dotenv


class Config(TypedDict):
    """Typed application configuration returned by ``get_config``."""
    signing_key: str
    api_key: str
    listen_port: int
    path_prefix: str
    spool_dir: Path
    phone_auto_answer: bool
    phone_client_websocket_url: str
    phone_media_host: str
    phone_media_port: int


PROJECT_ROOT = Path(__file__).parent.parent
SPOOL_DIR = PROJECT_ROOT / "spool"


def get_config() -> Config:
    """Return the typed application configuration, loading ``.env`` first."""
    load_dotenv(PROJECT_ROOT / ".env", override=False)
    signing_key = os.environ.get("INKBOX_SIGNING_KEY", "")
    if not signing_key:
        raise RuntimeError("INKBOX_SIGNING_KEY not set (use .env or pass via env vars)")
    prefix = os.environ.get("PATH_PREFIX", "").strip("/")

    auto_answer_env = os.environ.get("INKBOX_PHONE_AUTO_ANSWER", "true").strip().lower()
    phone_auto_answer = auto_answer_env in {"1", "true", "yes", "on"}

    return {
        "signing_key": signing_key,
        "api_key": os.environ.get("INKBOX_API_KEY", ""),
        "listen_port": int(os.environ.get("LISTEN_PORT", "8080")),
        "path_prefix": f"/{prefix}" if prefix else "",
        "spool_dir": SPOOL_DIR,
        "phone_auto_answer": phone_auto_answer,
        "phone_client_websocket_url": os.environ.get("INKBOX_PHONE_CLIENT_WEBSOCKET_URL", ""),
        "phone_media_host": os.environ.get("INKBOX_PHONE_MEDIA_HOST", "0.0.0.0"),
        "phone_media_port": int(os.environ.get("INKBOX_PHONE_MEDIA_PORT", "8090")),
    }
