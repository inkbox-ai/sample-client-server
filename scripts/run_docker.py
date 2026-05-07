#!/usr/bin/env python3
"""
scripts/run_docker.py

Build and run the sample-client-server Docker image locally. Reads
.env from the repo root — create it from .env.example first.

Usage:
    ./scripts/run_docker.py
    ./scripts/run_docker.py --host-port 9000
    ./scripts/run_docker.py --image-name my-inkbox-server --skip-build
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IMAGE_NAME = "inkbox-sample-client-server"
DEFAULT_HOST_PORT = 8080
CONTAINER_PORT = 8080


def _parse_args() -> argparse.Namespace:
    """Parse CLI flags for image name, host port, and skip-build toggle."""
    parser = argparse.ArgumentParser(
        description="Build and run the sample-client-server Docker image locally.",
    )
    parser.add_argument(
        "--image-name",
        default=os.environ.get("IMAGE_NAME", DEFAULT_IMAGE_NAME),
        help=f"Docker image tag (default: {DEFAULT_IMAGE_NAME})",
    )
    parser.add_argument(
        "--host-port",
        type=int,
        default=int(os.environ.get("HOST_PORT", DEFAULT_HOST_PORT)),
        help=f"Host port to publish container :{CONTAINER_PORT} on (default: {DEFAULT_HOST_PORT})",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip the docker build step and run the existing image.",
    )
    return parser.parse_args()


def _check_env_file() -> None:
    """Exit with a helpful message if ``.env`` is missing at the repo root."""
    env_file = REPO_ROOT / ".env"
    if not env_file.is_file():
        print(f"error: .env not found at {env_file}", file=sys.stderr)
        print(
            "       cp .env.example .env, fill in INKBOX_SIGNING_KEY, then rerun.",
            file=sys.stderr,
        )
        sys.exit(1)


def _run(cmd: list[str]) -> None:
    """Run ``cmd``, streaming output, and exit with its return code on failure."""
    print(f">> {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=REPO_ROOT)
    if result.returncode != 0:
        sys.exit(result.returncode)


def main() -> None:
    """Build the image (unless ``--skip-build``) and run it with the .env file mounted."""
    args = _parse_args()
    _check_env_file()

    if not args.skip_build:
        _run(["docker", "build", "-t", args.image_name, "."])

    payloads_dir = REPO_ROOT / "payloads"
    payloads_dir.mkdir(exist_ok=True)

    tunnel_state_dir = REPO_ROOT / ".inkbox-tunnel-state"
    tunnel_state_dir.mkdir(exist_ok=True)

    print(f">> running {args.image_name} on :{args.host_port} (ctrl-c to stop)...")
    os.execvp(
        "docker",
        [
            "docker",
            "run",
            "--rm",
            "-p",
            f"{args.host_port}:{CONTAINER_PORT}",
            "--env-file",
            str(REPO_ROOT / ".env"),
            "-v",
            f"{payloads_dir}:/app/payloads",
            "-v",
            f"{tunnel_state_dir}:/app/.inkbox-tunnel-state",
            args.image_name,
        ],
    )


if __name__ == "__main__":
    main()
