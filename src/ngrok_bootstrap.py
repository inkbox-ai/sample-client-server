"""
src/ngrok_bootstrap.py

Open a pyngrok tunnel on the local listen port, then PATCH every phone
number and mailbox in the caller's Inkbox org so their webhook / WS
URLs point at the public tunnel host. Run once at process start, before
uvicorn binds.
"""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import urlparse

from inkbox import Inkbox
from pyngrok import conf, ngrok

from env_config import EnvConfig

logger = logging.getLogger(__name__)
NGROK_RUNTIME_DIR = Path("/tmp/inkbox-sample-ngrok")


def _https_host(public_url: str) -> str:
    """Return the host (netloc) portion of ``public_url`` with no scheme."""
    parsed = urlparse(public_url)
    return parsed.netloc or public_url.removeprefix("https://").removeprefix("http://")


def _open_tunnel(port: int, authtoken: str) -> str:
    """Open an HTTPS ngrok tunnel to ``port`` and return its public URL."""
    NGROK_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    pyngrok_config = conf.PyngrokConfig(
        auth_token=authtoken,
        config_path=str(NGROK_RUNTIME_DIR / "ngrok.yml"),
        ngrok_path=str(NGROK_RUNTIME_DIR / "ngrok"),
    )
    tunnel = ngrok.connect(
        addr=port,
        proto="http",
        bind_tls=True,
        pyngrok_config=pyngrok_config,
    )
    public_url = tunnel.public_url
    if public_url.startswith("http://"):
        public_url = "https://" + public_url[len("http://"):]
    return public_url


def _patch_inkbox_objects(public_url: str) -> None:
    """List and patch every phone number + mailbox to point at ``public_url``."""
    client = Inkbox(api_key=EnvConfig.INKBOX_API_KEY)

    host = _https_host(public_url)
    webhook_url = f"https://{host}/webhook"
    ws_url = f"wss://{host}/phone/media/ws"

    numbers = client.phone_numbers.list()
    for number in numbers:
        client.phone_numbers.update(
            number.id,
            incoming_call_action="webhook",
            incoming_call_webhook_url=webhook_url,
            incoming_text_webhook_url=webhook_url,
            client_websocket_url=ws_url,
        )
        logger.info("Patched phone number %s -> %s / %s", number.number, webhook_url, ws_url)

    mailboxes = client.mailboxes.list()
    for mailbox in mailboxes:
        client.mailboxes.update(
            mailbox.email_address,
            webhook_url=webhook_url,
        )
        logger.info("Patched mailbox %s -> %s", mailbox.email_address, webhook_url)

    logger.info(
        "Inkbox objects patched: %d phone number(s), %d mailbox(es)",
        len(numbers), len(mailboxes),
    )


def setup_ngrok_and_patch_inkbox() -> str:
    """
    Open the ngrok tunnel and patch all Inkbox objects in the org.

    Returns the public tunnel URL. Raises if required credentials are
    missing so the sample never runs with stale webhook URLs.
    """
    missing = [
        name
        for name, value in (
            ("INKBOX_API_KEY", EnvConfig.INKBOX_API_KEY),
            ("NGROK_AUTHTOKEN", EnvConfig.NGROK_AUTHTOKEN),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Missing required environment variable(s): "
            + ", ".join(missing)
            + ". Set them in .env before starting the sample server.",
        )

    public_url = _open_tunnel(EnvConfig.LISTEN_PORT, EnvConfig.NGROK_AUTHTOKEN)
    logger.info("ngrok tunnel open: %s -> http://localhost:%d", public_url, EnvConfig.LISTEN_PORT)

    _patch_inkbox_objects(public_url)
    return public_url
