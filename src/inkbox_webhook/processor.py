"""
src/inkbox_webhook/processor.py

Deterministic wake trigger for pending Inkbox spool files.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from inkbox_webhook.config import get_config


SYSTEM_TEXT: str = (
    "Inkbox email queue pending. Process all pending files in "
    "~/openclaw-config/spool/*.json. For each inbound message.received event, "
    "read the spool file, use judgment, reply directly to the user, reply directly to others when the response is relatively obvious. "
    "After handling a file, move it to ~/openclaw-config/spool/processed/. If handling fails, move it to ~/openclaw-config/spool/failed/ and leave a sibling .error.txt note."
)


def _gateway_env() -> dict[str, str]:
    """Return a subprocess env with the OpenClaw gateway token injected from ``openclaw.json``."""
    env = os.environ.copy()
    cfg_path = Path.home() / ".openclaw" / "openclaw.json"
    if cfg_path.exists():
        cfg = json.loads(cfg_path.read_text())
        token = (((cfg.get("gateway") or {}).get("auth") or {}).get("token"))
        if token:
            env.setdefault("OPENCLAW_GATEWAY_TOKEN", token)
    return env


def process_once() -> int:
    """Fire one ``openclaw system event`` wake for the current spool and return the pending count."""
    cfg = get_config()
    spool_dir = Path(cfg["spool_dir"])
    pending = sorted(p for p in spool_dir.glob("*.json") if p.is_file())
    if not pending:
        return 0

    cmd = [
        "openclaw",
        "system",
        "event",
        "--mode",
        "now",
        "--text",
        SYSTEM_TEXT,
    ]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=_gateway_env(),
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown error").strip()
        raise RuntimeError(f"openclaw system event failed ({result.returncode}): {detail}")
    return len(pending)


def main() -> None:
    """CLI entrypoint that runs one ``process_once`` pass and prints the count."""
    count = process_once()
    print(f"Queued wake for {count} spool files")


if __name__ == "__main__":
    main()
