"""
src/inkbox_tunnel_bootstrap.py

Replaces the old ngrok bootstrap. Three concerns live here:

1. Control-plane CRUD via the Inkbox tunnels API (``bootstrap_tunnel``).
   For passthrough mode it also generates a local keypair, builds a
   CSR, and submits it to ``POST /tunnels/{id}/sign-csr`` to obtain a
   Let's Encrypt-signed cert chain. Persistence is on disk in the
   configured state dir.

2. SDK side-effects (``patch_inkbox_objects_to_tunnel``) — patch every
   phone number + mailbox to point at the new public host.

3. Data-plane runtime (``InkboxTunnelClient``) — maintain the persistent
   HTTP/2 connection to ``/_system/connect``, park intake streams,
   dispatch envelopes into the local FastAPI app, post replies, and
   bridge WS upgrades via RFC-8441 extended CONNECT. All streams ride
   the single persistent connection. Both ``edge`` and ``passthrough``
   modes share the data-plane plumbing; the difference is whether
   envelope bodies are plaintext HTTP (edge) or encrypted bytes that
   must be terminated through ``TLSTerminator`` (passthrough).
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import json
import logging
import os
import random
import socket
import ssl
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.settings
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import NameOID
from inkbox import Inkbox

from data_models.tunnel import TunnelTLSMode
from env_config import EnvConfig
from inkbox_tunnels_api import TunnelsAPI, TunnelsAPIError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Bootstrap: control-plane CRUD + local state
# ---------------------------------------------------------------------------


_STATE_FILE = "state.json"
_KEY_FILE = "private_key.pem"
_CERT_FILE = "cert_chain.pem"
_CERT_RENEWAL_THRESHOLD = _dt.timedelta(days=14)


@dataclass(frozen=True)
class TunnelBundle:
    """Everything the data-plane runtime needs to operate."""

    tunnel_id: UUID
    secret: str
    public_host: str
    tls_mode: TunnelTLSMode
    tls_terminator: "TLSTerminator | None"


def _load_state(state_dir: Path) -> dict[str, Any] | None:
    state_path = state_dir / _STATE_FILE
    if not state_path.is_file():
        return None
    try:
        return json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _save_state(state_dir: Path, state: dict[str, Any]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    state_path = state_dir / _STATE_FILE
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True))
    try:
        os.chmod(state_path, 0o600)
    except OSError:
        pass


def _print_secret_once(secret: str, path: Path) -> None:
    """One-time disclosure of the connect secret on stderr.

    Goes to ``sys.stderr`` directly — never the logger — so it isn't
    indexed by structured log shippers (CloudWatch / Datadog / Loki /
    etc). The secret is also persisted under ``path`` (chmod 600).
    """
    import sys
    banner = (
        "\n"
        "=================================================================\n"
        "  Inkbox tunnel: ONE-TIME connect_secret disclosure\n"
        "  This will not appear on subsequent runs.\n"
        f"  Secret persisted at: {path} (chmod 600)\n"
        "  Optionally copy into .env as INKBOX_TUNNEL_SECRET.\n"
        "=================================================================\n"
        f"  connect_secret = {secret}\n"
        "=================================================================\n"
    )
    print(banner, file=sys.stderr, flush=True)


def _load_or_create_keypair(state_dir: Path) -> PrivateKeyTypes:
    key_path = state_dir / _KEY_FILE
    if key_path.is_file():
        return serialization.load_pem_private_key(
            key_path.read_bytes(), password=None,
        )

    # Default to EC P-256: 30-50× faster keygen than RSA-2048, smaller
    # handshakes, and accepted by Let's Encrypt. Both EC and RSA load
    # back through the same load_pem_private_key path.
    logger.info("[bootstrap] generating EC P-256 keypair -> %s", key_path)
    state_dir.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(pem)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return key


def _build_csr(key: PrivateKeyTypes, public_host: str) -> str:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, public_host)]),
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(public_host)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _cert_expiry(state_dir: Path) -> _dt.datetime | None:
    cert_path = state_dir / _CERT_FILE
    if not cert_path.is_file():
        return None
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except ValueError:
        return None
    return cert.not_valid_after_utc


def _maybe_resign_cert(
    *,
    api: TunnelsAPI,
    tunnel_id: UUID,
    state_dir: Path,
    key: PrivateKeyTypes,
    public_host: str,
) -> bytes:
    """Return the cert chain PEM; sign a fresh CSR if the cached cert is stale."""
    cert_path = state_dir / _CERT_FILE
    expiry = _cert_expiry(state_dir)
    now = _dt.datetime.now(_dt.timezone.utc)
    needs_sign = (
        not cert_path.is_file()
        or expiry is None
        or expiry - now < _CERT_RENEWAL_THRESHOLD
    )
    if not needs_sign and expiry is not None:
        days_left = (expiry - now).days
        logger.info(
            "[bootstrap]   reusing cert_chain.pem; cert_expires_at=%s (%d days remaining)",
            expiry.date().isoformat(), days_left,
        )
        return cert_path.read_bytes()

    if expiry is not None:
        logger.info("[bootstrap]   cert within renewal window; resigning CSR")
    csr_pem = _build_csr(key, public_host)
    logger.info("[bootstrap] POST /tunnels/%s/sign-csr", tunnel_id)
    result = api.sign_csr(tunnel_id, csr_pem)
    cert_pem = result.get("cert_pem", "")
    chain_pem = result.get("chain_pem", "")
    full_chain = (cert_pem + chain_pem).encode("ascii")
    cert_path.write_bytes(full_chain)
    try:
        os.chmod(cert_path, 0o600)
    except OSError:
        pass
    if expires_at := result.get("cert_expires_at"):
        logger.info("[bootstrap]   sign-csr 200 cert_expires_at=%s", expires_at)
    return full_chain


def _find_tunnel_by_name(api: TunnelsAPI, name: str) -> dict[str, Any] | None:
    for t in api.list():
        if t.get("tunnel_name") == name and t.get("status") != "deleted":
            return t
    return None


def bootstrap_tunnel() -> TunnelBundle:
    """
    Idempotent bootstrap. Creates the tunnel if needed, otherwise reuses
    an existing one matching ``INKBOX_TUNNEL_NAME``. Branches on
    ``INKBOX_TUNNEL_TLS_MODE`` for the cert dance.
    """
    if not EnvConfig.INKBOX_API_KEY:
        raise RuntimeError("INKBOX_API_KEY is required to bootstrap a tunnel.")
    if not EnvConfig.INKBOX_TUNNEL_NAME:
        raise RuntimeError("INKBOX_TUNNEL_NAME is required.")

    state_dir = Path(EnvConfig.INKBOX_TUNNEL_STATE_DIR)
    state_dir.mkdir(parents=True, exist_ok=True)
    name = EnvConfig.INKBOX_TUNNEL_NAME
    zone = EnvConfig.INKBOX_TUNNEL_ZONE
    public_host = f"{name}.{zone}"
    mode = EnvConfig.INKBOX_TUNNEL_TLS_MODE

    logger.info(
        "[bootstrap] mode=%s name=%s zone=%s", mode.value, name, zone,
    )

    api = TunnelsAPI(
        base_url=EnvConfig.INKBOX_API_BASE,
        api_key=EnvConfig.INKBOX_API_KEY,
    )

    try:
        tunnel_id: UUID | None = None
        secret: str | None = None
        existing: dict[str, Any] | None = None

        # Resolution order: state file (per-tunnel), then env-provided
        # secret override, then look up by name on the server, then
        # create new.
        state = _load_state(state_dir)
        if state and state.get("name") == name:
            try:
                tunnel_id = UUID(state["tunnel_id"])
                secret = state.get("secret") or None
                logger.info(
                    "[bootstrap]   loaded state from %s (tunnel_id=%s)",
                    state_dir / _STATE_FILE, tunnel_id,
                )
            except (KeyError, ValueError):
                tunnel_id = None
                secret = None

        if EnvConfig.INKBOX_TUNNEL_SECRET:
            secret = EnvConfig.INKBOX_TUNNEL_SECRET

        if tunnel_id is None:
            existing = _find_tunnel_by_name(api, name)
            if existing is not None:
                tunnel_id = UUID(existing["id"])
                logger.info(
                    "[bootstrap]   found existing tunnel %s by name", tunnel_id,
                )

        if tunnel_id is None:
            logger.info(
                "[bootstrap] POST /tunnels/ tls_mode=%s", mode.value,
            )
            try:
                created = api.create(
                    tunnel_name=name,
                    tls_mode=mode,
                    description="sample-client-server",
                )
            except TunnelsAPIError as exc:
                raise RuntimeError(
                    f"Failed to create tunnel {name!r}: {exc}",
                ) from exc
            tunnel_obj = created.get("tunnel") or created
            tunnel_id = UUID(tunnel_obj["id"])
            secret = created.get("connect_secret") or tunnel_obj.get("connect_secret")
            existing = tunnel_obj
            logger.info(
                "[bootstrap]   201 status=%s tunnel_id=%s",
                tunnel_obj.get("status"), tunnel_id,
            )
            if secret:
                # Persist immediately so a crash anywhere in cert /
                # CSR flow below doesn't strand us with no on-disk
                # record of the connect secret. Cert paths get added
                # by a later _save_state call.
                _save_state(
                    state_dir,
                    {
                        "tunnel_id": str(tunnel_id),
                        "name": name,
                        "secret": secret,
                        "mode": mode.value,
                        "zone": zone,
                    },
                )
                # Print the secret directly to stderr — bypassing the
                # logger keeps it out of CloudWatch / Datadog / Loki
                # ingestion pipelines. Logged-INFO breadcrumb says
                # where it lives instead.
                _print_secret_once(secret, state_dir / _STATE_FILE)
                logger.info(
                    "[bootstrap]   connect_secret saved to %s (chmod 600). "
                    "It will not be printed again on subsequent runs.",
                    state_dir / _STATE_FILE,
                )

        if existing is None:
            existing = api.get(tunnel_id)

        server_mode_raw = existing.get("tls_mode")
        if server_mode_raw:
            server_mode = TunnelTLSMode(server_mode_raw)
            if server_mode != mode:
                raise RuntimeError(
                    f"tls_mode drift: env={mode.value} but server reports "
                    f"{server_mode.value}. tls_mode is fixed at creation; "
                    "delete the tunnel and recreate (60-day name cooldown applies).",
                )

        status = existing.get("status")
        if status == "deleted":
            raise RuntimeError(
                f"Tunnel {tunnel_id} is soft-deleted; pick a new name.",
            )
        if status == "disabled":
            logger.info("[bootstrap]   re-enabling disabled tunnel")
            api.patch(tunnel_id, status="active")

        if not secret:
            raise RuntimeError(
                "No connect secret available. Set INKBOX_TUNNEL_SECRET "
                f"explicitly or delete {state_dir} to recreate the tunnel.",
            )

        terminator: TLSTerminator | None = None
        if mode is TunnelTLSMode.PASSTHROUGH:
            key = _load_or_create_keypair(state_dir)
            chain_pem = _maybe_resign_cert(
                api=api,
                tunnel_id=tunnel_id,
                state_dir=state_dir,
                key=key,
                public_host=public_host,
            )
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            terminator = TLSTerminator(
                cert_chain_pem=chain_pem, key_pem=key_pem,
            )

        _save_state(
            state_dir,
            {
                "tunnel_id": str(tunnel_id),
                "name": name,
                "secret": secret,
                "mode": mode.value,
                "zone": zone,
            },
        )

        return TunnelBundle(
            tunnel_id=tunnel_id,
            secret=secret,
            public_host=public_host,
            tls_mode=mode,
            tls_terminator=terminator,
        )
    finally:
        api.close()


# ---------------------------------------------------------------------------
# Inkbox SDK side-effects
# ---------------------------------------------------------------------------


def patch_inkbox_objects_to_tunnel(public_host: str) -> None:
    """
    PATCH every phone number and mailbox in the org to point at the
    tunnel's public host. Same SDK calls as the old ngrok bootstrap;
    only the host changes.
    """
    client = Inkbox(api_key=EnvConfig.INKBOX_API_KEY)

    webhook_url = f"https://{public_host}/webhook"
    ws_url = f"wss://{public_host}/phone/media/ws"

    numbers = client.phone_numbers.list()
    for number in numbers:
        client.phone_numbers.update(
            number.id,
            incoming_call_action="webhook",
            incoming_call_webhook_url=webhook_url,
            incoming_text_webhook_url=webhook_url,
            client_websocket_url=ws_url,
        )
        logger.info(
            "Patched phone number %s -> %s / %s",
            number.number, webhook_url, ws_url,
        )

    mailboxes = client.mailboxes.list()
    for mailbox in mailboxes:
        client.mailboxes.update(
            mailbox.email_address,
            webhook_url=webhook_url,
        )
        logger.info("Patched mailbox %s -> %s", mailbox.email_address, webhook_url)

    logger.info(
        "Inkbox objects patched: %d phone number(s), %d mailbox(es) -> %s",
        len(numbers), len(mailboxes), public_host,
    )


# ---------------------------------------------------------------------------
# TLSTerminator (passthrough only)
# ---------------------------------------------------------------------------


class TLSTerminator:
    """
    Memory-only TLS endpoint built from the LE-signed cert+chain and
    customer-held private key. Used by the data-plane runtime in
    passthrough mode to terminate inbound TLS without ever opening a
    real socket — cert/key + plaintext bytes never leave this process.
    """

    def __init__(self, *, cert_chain_pem: bytes, key_pem: bytes):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # ssl.SSLContext.load_cert_chain only takes paths, so the PEMs
        # round-trip through tempfiles. To avoid relying on platform
        # default umasks, create with O_CREAT|O_EXCL|O_WRONLY mode 0600
        # and unlink in finally even on exception.
        import tempfile
        cert_path = key_path = None
        try:
            cert_fd, cert_path = tempfile.mkstemp(suffix=".pem")
            try:
                os.fchmod(cert_fd, 0o600)
            except (AttributeError, OSError):
                pass
            with os.fdopen(cert_fd, "wb") as f:
                f.write(cert_chain_pem)

            key_fd, key_path = tempfile.mkstemp(suffix=".pem")
            try:
                os.fchmod(key_fd, 0o600)
            except (AttributeError, OSError):
                pass
            with os.fdopen(key_fd, "wb") as f:
                f.write(key_pem)

            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        finally:
            for p in (cert_path, key_path):
                if p is not None:
                    try:
                        os.unlink(p)
                    except OSError:
                        pass
        self._ctx = ctx

    def session(self) -> "TLSSession":
        return TLSSession(self._ctx)


class TLSSession:
    """One inbound third-party TLS connection's worth of state."""

    def __init__(self, ctx: ssl.SSLContext):
        self._in_bio = ssl.MemoryBIO()
        self._out_bio = ssl.MemoryBIO()
        self._sslobj = ctx.wrap_bio(
            incoming=self._in_bio,
            outgoing=self._out_bio,
            server_side=True,
        )
        self._handshake_done = False

    def feed(self, encrypted: bytes) -> tuple[list[bytes], bytes]:
        """
        Feed encrypted bytes; return ``(plaintext_chunks, encrypted_to_send)``.
        Idempotent — call repeatedly until the wire stream is exhausted.
        """
        if encrypted:
            self._in_bio.write(encrypted)

        plaintext: list[bytes] = []
        if not self._handshake_done:
            try:
                self._sslobj.do_handshake()
                self._handshake_done = True
            except ssl.SSLWantReadError:
                pass

        if self._handshake_done:
            while True:
                try:
                    chunk = self._sslobj.read(16384)
                except ssl.SSLWantReadError:
                    break
                except ssl.SSLZeroReturnError:
                    break
                if not chunk:
                    break
                plaintext.append(chunk)

        encrypted_out = self._out_bio.read() or b""
        return plaintext, encrypted_out

    def send(self, plaintext: bytes) -> bytes:
        """Encrypt outbound plaintext; return encrypted bytes for the wire."""
        if plaintext:
            offset = 0
            while offset < len(plaintext):
                offset += self._sslobj.write(plaintext[offset:])
        return self._out_bio.read() or b""

    def close(self) -> bytes:
        try:
            self._sslobj.unwrap()
        except (ssl.SSLWantReadError, ssl.SSLError, OSError):
            pass
        return self._out_bio.read() or b""


# ---------------------------------------------------------------------------
# InkboxTunnelClient — the data-plane runtime
# ---------------------------------------------------------------------------


_PING_INTERVAL = 20.0
_BACKOFF_CAP = 30.0
_BACKOFF_JITTER = 0.25  # ±25% jitter on each backoff sleep


class _TunnelAuthError(RuntimeError):
    """Permanent auth failure; do not retry the connection."""
_HOP_BY_HOP_REQUEST = frozenset({
    "host", "connection", "upgrade", "keep-alive", "te", "trailer",
    "transfer-encoding", "proxy-authenticate", "proxy-authorization",
    "sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions",
})
_HOP_BY_HOP_RESPONSE = frozenset({
    "connection", "keep-alive", "transfer-encoding", "upgrade",
    "proxy-authenticate", "proxy-authorization", "te", "trailer",
})


# Inbound stream messages from the network reader to per-stream handlers.
@dataclass
class _StreamEvent:
    kind: str  # "headers" | "data" | "end" | "reset"
    headers: list[tuple[str, str]] = field(default_factory=list)
    data: bytes = b""


@dataclass
class _Envelope:
    request_id: str
    method: str
    path: str
    route_kind: str
    ws_id: str | None
    forwarded_headers: list[tuple[str, str]]
    body: bytes


class InkboxTunnelClient:
    """
    Data-plane runtime. Maintains one persistent HTTP/2 connection to
    ``https://{zone}/_system/connect``, parks N intake streams, and
    dispatches envelopes back into the local FastAPI app. All replies +
    WS extended-CONNECT streams ride the same connection.
    """

    def __init__(
        self,
        *,
        tunnel_id: UUID,
        secret: str,
        zone: str,
        pool_size: int,
        local_app: Any,
        tls_terminator: TLSTerminator | None,
    ):
        self._tunnel_id = str(tunnel_id)
        self._secret = secret
        self._zone = zone
        self._pool_size = pool_size
        self._app = local_app
        self._terminator = tls_terminator

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._h2: h2.connection.H2Connection | None = None
        self._stop = asyncio.Event()
        # Single source of truth for synchronous h2 mutations + writer access.
        self._send_lock = asyncio.Lock()
        # stream_id -> queue of _StreamEvent for handlers awaiting frames.
        self._streams: dict[int, asyncio.Queue[_StreamEvent]] = {}
        # stream_id -> asyncio.Event signalled when send window opens.
        self._window_events: dict[int, asyncio.Event] = {}
        # Connection-level send-window event.
        self._conn_window_event = asyncio.Event()
        self._conn_window_event.set()
        # In-flight handler tasks; we wait on them at shutdown.
        self._tasks: set[asyncio.Task[Any]] = set()

    async def aclose(self) -> None:
        self._stop.set()
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except (OSError, ConnectionError):
                pass

    async def serve_forever(self) -> None:
        """Maintain the connection with jittered exponential-backoff reconnects.

        Auth failures from ``/_system/hello`` propagate out — there's
        no point hot-looping a permanently-bad secret. Other failures
        (network blips, GOAWAY, h2 protocol errors) reconnect.
        """
        backoff = 1.0
        consecutive_failures = 0
        while not self._stop.is_set():
            try:
                await self._run_once()
                backoff = 1.0
                consecutive_failures = 0
            except asyncio.CancelledError:
                raise
            except _TunnelAuthError:
                logger.error(
                    "[tunnel-client] /_system/hello rejected the connect "
                    "secret — refusing to retry. Rotate the secret via "
                    "POST /api/v1/tunnels/{id}/rotate-secret, update "
                    "INKBOX_TUNNEL_SECRET (or wipe the state file), and "
                    "restart.",
                )
                raise
            except Exception:
                consecutive_failures += 1
                logger.exception(
                    "[tunnel-client] connection error (#%d); reconnecting",
                    consecutive_failures,
                )
            if self._stop.is_set():
                return
            jitter = backoff * _BACKOFF_JITTER * (2 * random.random() - 1)
            sleep_for = max(0.1, backoff + jitter)
            await asyncio.sleep(sleep_for)
            backoff = min(backoff * 2, _BACKOFF_CAP)

    # --- connection lifecycle ------------------------------------------------

    async def _run_once(self) -> None:
        await self._open_connection()
        try:
            await self._send_hello()
            for slot in range(self._pool_size):
                self._spawn(self._intake_loop(slot))

            ping_task = asyncio.create_task(self._ping_loop())
            try:
                await self._read_loop()
            finally:
                ping_task.cancel()
                try:
                    await ping_task
                except asyncio.CancelledError:
                    pass
        finally:
            for task in list(self._tasks):
                task.cancel()
            for task in list(self._tasks):
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
            self._tasks.clear()
            self._streams.clear()
            self._window_events.clear()
            if self._writer is not None:
                try:
                    self._writer.close()
                    await self._writer.wait_closed()
                except (OSError, ConnectionError):
                    pass
            self._writer = None
            self._reader = None
            self._h2 = None

    def _spawn(self, coro: Any) -> asyncio.Task[Any]:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def _open_connection(self) -> None:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2"])
        logger.info(
            "[tunnel-client] connecting to https://%s/_system/connect", self._zone,
        )
        self._reader, self._writer = await asyncio.open_connection(
            host=self._zone,
            port=443,
            ssl=ctx,
            server_hostname=self._zone,
        )
        sock = self._writer.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
        config = h2.config.H2Configuration(
            client_side=True, header_encoding="utf-8",
        )
        self._h2 = h2.connection.H2Connection(config=config)
        # Allow extended CONNECT (RFC 8441) on our side too — h2 honors
        # this by accepting :protocol pseudo-header on outbound CONNECT.
        self._h2.local_settings.update({
            h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL: 1,
        })
        self._h2.initiate_connection()
        await self._flush()

    async def _flush(self) -> None:
        assert self._h2 is not None and self._writer is not None
        data = self._h2.data_to_send()
        if data:
            self._writer.write(data)
            await self._writer.drain()

    # --- handshake -----------------------------------------------------------

    async def _send_hello(self) -> None:
        async with self._send_lock:
            stream_id = self._open_stream_locked(
                [
                    (":method", "POST"),
                    (":scheme", "https"),
                    (":authority", self._zone),
                    (":path", "/_system/hello"),
                    ("x-tunnel-id", self._tunnel_id),
                    ("x-tunnel-secret", self._secret),
                    ("x-pool-size", str(self._pool_size)),
                    ("content-length", "0"),
                ],
                end_stream=True,
            )

        status = await self._await_response_status(stream_id)
        self._streams.pop(stream_id, None)
        if status in (401, 403):
            raise _TunnelAuthError(
                f"/_system/hello returned {status}; connect secret is invalid",
            )
        if status != 200:
            raise RuntimeError(
                f"/_system/hello returned {status}; transient — will retry",
            )
        logger.info(
            "[tunnel-client] /_system/hello 200; opening %d parked intake streams",
            self._pool_size,
        )

    def _open_stream_locked(
        self,
        headers: list[tuple[str, str]],
        *,
        end_stream: bool,
    ) -> int:
        assert self._h2 is not None
        stream_id = self._h2.get_next_available_stream_id()
        self._h2.send_headers(stream_id, headers, end_stream=end_stream)
        self._streams[stream_id] = asyncio.Queue()
        return stream_id

    async def _await_response_status(self, stream_id: int) -> int:
        queue = self._streams[stream_id]
        while True:
            event = await queue.get()
            if event.kind == "headers":
                status_str = next(
                    (v for k, v in event.headers if k == ":status"), "0",
                )
                # Drain remaining frames so the queue can be GC'd.
                while True:
                    try:
                        evt = queue.get_nowait()
                        if evt.kind in ("end", "reset"):
                            break
                    except asyncio.QueueEmpty:
                        break
                return int(status_str)
            if event.kind in ("end", "reset"):
                return 0

    # --- intake pool --------------------------------------------------------

    async def _intake_loop(self, slot: int) -> None:
        """
        Maintain one parked intake slot indefinitely. Transient errors
        (h2 protocol blips, single-stream resets, parse failures) get a
        short backoff and a retry — the slot only exits on real teardown
        (``_stop`` set, or h2 connection gone).
        """
        while not self._stop.is_set() and self._h2 is not None:
            try:
                envelope = await self._park_one_intake(slot)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(
                    "[tunnel-client] intake slot %d transient error; retrying",
                    slot,
                )
                await asyncio.sleep(0.25)
                continue
            if envelope is None:
                continue  # stream RST'd or empty; reopen immediately
            self._spawn(self._dispatch(envelope))

    async def _park_one_intake(self, slot: int) -> _Envelope | None:
        async with self._send_lock:
            stream_id = self._open_stream_locked(
                [
                    (":method", "POST"),
                    (":scheme", "https"),
                    (":authority", self._zone),
                    (":path", "/_system/intake"),
                    ("x-tunnel-id", self._tunnel_id),
                    ("x-pool-slot", str(slot)),
                    ("content-length", "0"),
                ],
                end_stream=True,
            )
            await self._flush()

        queue = self._streams[stream_id]
        headers: list[tuple[str, str]] | None = None
        body = bytearray()
        try:
            while True:
                event = await queue.get()
                if event.kind == "headers" and headers is None:
                    headers = event.headers
                elif event.kind == "data":
                    body.extend(event.data)
                elif event.kind == "end":
                    break
                elif event.kind == "reset":
                    return None
        finally:
            self._streams.pop(stream_id, None)

        if headers is None:
            return None
        status = next((v for k, v in headers if k == ":status"), "0")
        if status != "200":
            return None
        return _parse_envelope(headers, bytes(body))

    # --- read pump ----------------------------------------------------------

    async def _ping_loop(self) -> None:
        while not self._stop.is_set():
            await asyncio.sleep(_PING_INTERVAL)
            if self._h2 is None or self._writer is None:
                return
            try:
                async with self._send_lock:
                    self._h2.ping(b"keepaliv")
                    await self._flush()
            except Exception:
                return

    async def _read_loop(self) -> None:
        assert self._h2 is not None and self._reader is not None
        while not self._stop.is_set():
            chunk = await self._reader.read(65536)
            if not chunk:
                return
            try:
                events = self._h2.receive_data(chunk)
            except h2.exceptions.ProtocolError:
                logger.exception("[tunnel-client] h2 protocol error")
                return
            for event in events:
                await self._handle_event(event)
            async with self._send_lock:
                await self._flush()

    async def _handle_event(self, event: h2.events.Event) -> None:
        if isinstance(event, h2.events.ResponseReceived):
            queue = self._streams.get(event.stream_id)
            if queue is not None:
                await queue.put(_StreamEvent(kind="headers", headers=list(event.headers)))
        elif isinstance(event, h2.events.InformationalResponseReceived):
            # 1xx; ignore.
            pass
        elif isinstance(event, h2.events.DataReceived):
            queue = self._streams.get(event.stream_id)
            if queue is not None:
                await queue.put(_StreamEvent(kind="data", data=event.data))
            if self._h2 is not None:
                self._h2.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id,
                )
        elif isinstance(event, h2.events.StreamEnded):
            queue = self._streams.get(event.stream_id)
            if queue is not None:
                await queue.put(_StreamEvent(kind="end"))
        elif isinstance(event, h2.events.StreamReset):
            queue = self._streams.get(event.stream_id)
            if queue is not None:
                await queue.put(_StreamEvent(kind="reset"))
            ev = self._window_events.pop(event.stream_id, None)
            if ev is not None:
                ev.set()
        elif isinstance(event, h2.events.WindowUpdated):
            if event.stream_id == 0:
                self._conn_window_event.set()
            else:
                ev = self._window_events.get(event.stream_id)
                if ev is not None:
                    ev.set()
        elif isinstance(event, h2.events.ConnectionTerminated):
            logger.info(
                "[tunnel-client] GOAWAY error_code=%s last_stream_id=%s",
                event.error_code, event.last_stream_id,
            )
            raise ConnectionError("tunnel server sent GOAWAY")
        elif isinstance(event, h2.events.SettingsAcknowledged):
            pass
        elif isinstance(event, h2.events.RemoteSettingsChanged):
            pass

    # --- envelope dispatch --------------------------------------------------

    async def _dispatch(self, envelope: _Envelope) -> None:
        try:
            if envelope.route_kind == "ws-upgrade":
                await self._dispatch_ws_upgrade(envelope)
                return
            await self._dispatch_http(envelope)
        except Exception:
            logger.exception(
                "[tunnel-client] dispatch failed request_id=%s", envelope.request_id,
            )
            try:
                await self._post_response(
                    envelope.request_id,
                    status=500,
                    headers=[("content-type", "text/plain")],
                    body=b"internal error",
                )
            except Exception:
                logger.exception("[tunnel-client] failed to post error response")

    # --- HTTP envelope dispatch (edge + passthrough) ------------------------

    async def _dispatch_http(self, envelope: _Envelope) -> None:
        disconnect_event = asyncio.Event()
        if self._stop.is_set():
            disconnect_event.set()
        try:
            if self._terminator is None:
                # Edge mode: envelope body is already plaintext request body.
                status, resp_headers, resp_body = await _invoke_asgi_http(
                    app=self._app,
                    method=envelope.method,
                    path=envelope.path,
                    headers=envelope.forwarded_headers,
                    body=envelope.body,
                    disconnect_event=disconnect_event,
                )
                await self._post_response(
                    envelope.request_id,
                    status=status,
                    headers=_filter_response_headers(resp_headers),
                    body=resp_body,
                )
                return

            # Passthrough mode: envelope.body is encrypted bytes from
            # the third-party TCP stream (TLS records). Drive the BIO
            # until a full HTTP/1.1 request is parseable, dispatch,
            # encrypt response.
            session = self._terminator.session()
            plaintext_chunks, _ = session.feed(envelope.body)
            plaintext = bytearray(b"".join(plaintext_chunks))
            try:
                method, path, req_headers, body = _parse_complete_http_request(
                    plaintext,
                )
            except _NeedMoreData:
                await self._post_response(
                    envelope.request_id,
                    status=400,
                    headers=[("content-type", "text/plain")],
                    body=b"passthrough: incomplete HTTP/1.1 request",
                )
                return

            status, resp_headers, resp_body = await _invoke_asgi_http(
                app=self._app,
                method=method,
                path=path,
                headers=req_headers,
                body=body,
                disconnect_event=disconnect_event,
            )
            wire_response = _build_http_response(
                status, _filter_response_headers(resp_headers), resp_body,
            )
            encrypted = session.send(wire_response)
            encrypted += session.close()
            await self._post_response(
                envelope.request_id,
                status=200,
                headers=[("content-type", "application/octet-stream")],
                body=bytes(encrypted),
                opaque=True,
            )
        finally:
            # Unblock any handler still parked in receive() so the task
            # can finish cleanly instead of leaking forever.
            disconnect_event.set()

    # --- WebSocket bridge ---------------------------------------------------

    async def _dispatch_ws_upgrade(self, envelope: _Envelope) -> None:
        """
        Bridge a third-party WS upgrade end-to-end:

        1. Run the local FastAPI ASGI app's websocket route until it
           sends ``websocket.accept`` (or ``websocket.close``).
        2. Open an extended-CONNECT stream
           ``CONNECT :protocol=inkbox-tunnel-ws :path=/_system/ws/{ws_id}``
           with our chosen subprotocol + accept headers under
           ``inkbox-h-*``. The tunnel server forwards them to the third
           party as the 101 response and opens a bidi stream.
        3. Pump messages: ASGI ``websocket.send`` → length-prefixed JSON
           DATA frame; inbound DATA → ``websocket.receive``.
        """
        if envelope.ws_id is None:
            await self._reject_ws(envelope.request_id, status=400, reason="missing ws_id")
            return

        ws_session = _WSASGISession(
            app=self._app,
            path=envelope.path,
            headers=envelope.forwarded_headers,
        )
        accept_msg = await ws_session.run_until_accept()

        if accept_msg["type"] == "websocket.close":
            code = accept_msg.get("code", 1006)
            await self._reject_ws(
                envelope.request_id,
                status=403,
                reason=f"app rejected WS (close code={code})",
            )
            return

        subprotocol = accept_msg.get("subprotocol")
        accept_headers: list[tuple[str, str]] = []
        for raw_k, raw_v in accept_msg.get("headers", []):
            try:
                k = raw_k.decode("latin-1") if isinstance(raw_k, bytes) else raw_k
                v = raw_v.decode("latin-1") if isinstance(raw_v, bytes) else raw_v
            except UnicodeDecodeError:
                continue
            if k.lower() in _HOP_BY_HOP_RESPONSE:
                continue
            accept_headers.append((k, v))

        # Open the extended-CONNECT stream.
        connect_headers: list[tuple[str, str]] = [
            (":method", "CONNECT"),
            (":scheme", "https"),
            (":authority", self._zone),
            (":path", f"/_system/ws/{envelope.ws_id}"),
            (":protocol", "inkbox-tunnel-ws"),
            ("x-tunnel-id", self._tunnel_id),
            ("x-tunnel-secret", self._secret),
            ("inkbox-request-id", envelope.request_id),
            ("inkbox-ws-id", envelope.ws_id),
        ]
        if subprotocol:
            connect_headers.append(
                ("inkbox-h-sec-websocket-protocol", subprotocol),
            )
        for k, v in accept_headers:
            connect_headers.append((f"inkbox-h-{k.lower()}", v))

        async with self._send_lock:
            stream_id = self._open_stream_locked(connect_headers, end_stream=False)
            await self._flush()

        queue = self._streams[stream_id]
        # Wait for :status=200 on the CONNECT response.
        while True:
            event = await queue.get()
            if event.kind == "headers":
                status_str = next(
                    (v for k, v in event.headers if k == ":status"), "0",
                )
                if status_str != "200":
                    logger.info(
                        "[tunnel-client] CONNECT /_system/ws/%s -> %s; aborting bridge",
                        envelope.ws_id, status_str,
                    )
                    await ws_session.close(code=1011)
                    self._streams.pop(stream_id, None)
                    return
                break
            if event.kind in ("end", "reset"):
                await ws_session.close(code=1006)
                self._streams.pop(stream_id, None)
                return

        try:
            await self._pump_ws(stream_id, ws_session)
        finally:
            await ws_session.close(code=1000)
            self._streams.pop(stream_id, None)

    async def _reject_ws(self, request_id: str, *, status: int, reason: str) -> None:
        await self._post_response(
            request_id,
            status=status,
            headers=[("content-type", "text/plain")],
            body=reason.encode("utf-8"),
        )

    async def _pump_ws(self, stream_id: int, ws_session: "_WSASGISession") -> None:
        """Bidirectional ASGI <-> length-prefixed-JSON envelope pump."""
        recv_buf = bytearray()
        recv_done = False

        async def app_to_wire() -> None:
            try:
                async for msg in ws_session.outbound():
                    payload = _encode_ws_envelope(msg)
                    await self._send_data(stream_id, payload, end_stream=False)
                # ASGI handler completed; signal close.
                close_payload = _encode_ws_envelope(
                    {"type": "websocket.close", "code": 1000, "reason": ""},
                )
                await self._send_data(stream_id, close_payload, end_stream=True)
            except (ConnectionError, h2.exceptions.ProtocolError):
                pass

        sender = self._spawn(app_to_wire())

        try:
            while not recv_done:
                event = await self._streams[stream_id].get()
                if event.kind == "data":
                    recv_buf.extend(event.data)
                    while True:
                        if len(recv_buf) < 4:
                            break
                        (length,) = struct.unpack(">I", bytes(recv_buf[:4]))
                        if len(recv_buf) < 4 + length:
                            break
                        env_bytes = bytes(recv_buf[4:4 + length])
                        del recv_buf[:4 + length]
                        try:
                            envelope_msg = json.loads(env_bytes.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            continue
                        await ws_session.deliver(envelope_msg)
                        if envelope_msg.get("type") == "close":
                            recv_done = True
                            break
                elif event.kind in ("end", "reset"):
                    recv_done = True
        finally:
            # Clean shutdown: signal the outbound queue with a sentinel
            # so app_to_wire exits its loop on its own. Only fall back
            # to cancel if it's still running after a short grace.
            ws_session.signal_outbound_eof()
            try:
                await asyncio.wait_for(sender, timeout=2.0)
            except asyncio.TimeoutError:
                sender.cancel()
                try:
                    await sender
                except (asyncio.CancelledError, Exception):
                    pass
            except (asyncio.CancelledError, Exception):
                pass

    # --- response posting ---------------------------------------------------

    async def _post_response(
        self,
        request_id: str,
        *,
        status: int,
        headers: list[tuple[str, str]],
        body: bytes,
        opaque: bool = False,
    ) -> None:
        """
        POST /_system/response/{id} on the existing h2 connection.
        ``opaque=True`` flags passthrough-mode encrypted bytes; we set
        ``inkbox-route-kind=tcp-passthrough`` so the public handler
        forwards them as opaque TCP rather than HTTP.
        """
        req_headers: list[tuple[str, str]] = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", self._zone),
            (":path", f"/_system/response/{request_id}"),
            ("x-tunnel-id", self._tunnel_id),
            ("x-tunnel-secret", self._secret),
            ("inkbox-status", str(status)),
            ("inkbox-request-id", request_id),
            ("content-length", str(len(body))),
        ]
        if opaque:
            req_headers.append(("inkbox-route-kind", "tcp-passthrough"))
        # Drop any inbound content-length / transfer-encoding before
        # forwarding under inkbox-h-* — the outer content-length set on
        # this stream is the source of truth for the wire body length.
        # Forwarding both would land two `content-length` headers on
        # the third party, which HTTP/1.1 says to reject.
        for k, v in headers:
            kl = k.lower()
            if kl in ("content-length", "transfer-encoding"):
                continue
            req_headers.append((f"inkbox-h-{kl}", v))

        async with self._send_lock:
            stream_id = self._open_stream_locked(
                req_headers, end_stream=(len(body) == 0),
            )
            await self._flush()
        if body:
            await self._send_data(stream_id, body, end_stream=True)
        # Drain response status; don't require 200 strictly — log non-2xx.
        try:
            status_code = await asyncio.wait_for(
                self._await_response_status(stream_id), timeout=30.0,
            )
            if status_code >= 400:
                logger.warning(
                    "[tunnel-client] /_system/response/%s -> %d",
                    request_id, status_code,
                )
        except asyncio.TimeoutError:
            logger.warning(
                "[tunnel-client] /_system/response/%s timed out", request_id,
            )
        finally:
            self._streams.pop(stream_id, None)

    async def _send_data(
        self, stream_id: int, data: bytes, *, end_stream: bool,
    ) -> None:
        """Send DATA on ``stream_id`` respecting flow control + frame size."""
        assert self._h2 is not None
        offset = 0
        total = len(data)
        while offset < total:
            await self._await_window(stream_id)
            async with self._send_lock:
                if self._h2 is None:
                    raise ConnectionError("h2 connection torn down")
                window = min(
                    self._h2.local_flow_control_window(stream_id),
                    self._h2.max_outbound_frame_size,
                )
                if window <= 0:
                    self._mark_window_blocked(stream_id)
                    continue
                chunk = data[offset:offset + window]
                end = end_stream and (offset + len(chunk) >= total)
                self._h2.send_data(stream_id, chunk, end_stream=end)
                offset += len(chunk)
                await self._flush()
        if end_stream and offset == 0:
            async with self._send_lock:
                if self._h2 is not None:
                    self._h2.send_data(stream_id, b"", end_stream=True)
                    await self._flush()

    def _mark_window_blocked(self, stream_id: int) -> None:
        """
        Mark whichever window is empty (stream, conn, or both). Callers
        pass ``stream_id`` for the stream side; the conn side is decided
        by inspecting h2 state directly so we never spuriously clear the
        conn event when only the stream is exhausted.
        """
        ev = self._window_events.setdefault(stream_id, asyncio.Event())
        if self._h2 is not None and self._h2.local_flow_control_window(
            stream_id,
        ) <= 0:
            ev.clear()
        if self._h2 is not None and self._h2.outbound_flow_control_window <= 0:
            self._conn_window_event.clear()

    async def _await_window(self, stream_id: int) -> None:
        async with self._send_lock:
            if self._h2 is None:
                raise ConnectionError("h2 connection torn down")
            stream_window = self._h2.local_flow_control_window(stream_id)
            conn_window = self._h2.outbound_flow_control_window
            if stream_window > 0 and conn_window > 0:
                return
        # One of the windows is closed; await whichever events will fire.
        # Track every wait-task we create so we can cancel the loser(s)
        # — asyncio.wait(FIRST_COMPLETED) does not cancel them for us.
        wait_tasks: list[asyncio.Task[Any]] = []
        if stream_window <= 0:
            ev = self._window_events.setdefault(stream_id, asyncio.Event())
            wait_tasks.append(asyncio.create_task(ev.wait()))
        if conn_window <= 0:
            wait_tasks.append(asyncio.create_task(self._conn_window_event.wait()))
        if not wait_tasks:
            return
        try:
            done, pending = await asyncio.wait(
                wait_tasks, return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            for t in wait_tasks:
                if not t.done():
                    t.cancel()
            for t in wait_tasks:
                if not t.done():
                    try:
                        await t
                    except (asyncio.CancelledError, Exception):
                        pass


# ---------------------------------------------------------------------------
# Envelope parsing + ASGI plumbing
# ---------------------------------------------------------------------------


class _NeedMoreData(Exception):
    """Internal signal: passthrough plaintext is not yet a full HTTP request."""


def _parse_envelope(headers: list[tuple[str, str]], body: bytes) -> _Envelope | None:
    request_id = ""
    method = "GET"
    path = "/"
    route_kind = "webhook"
    ws_id: str | None = None
    forwarded: list[tuple[str, str]] = []
    for k, v in headers:
        if k == "inkbox-request-id":
            request_id = v
        elif k == "inkbox-method":
            method = v
        elif k == "inkbox-path":
            path = v
        elif k == "inkbox-route-kind":
            route_kind = v
        elif k == "inkbox-ws-id":
            ws_id = v
        elif k.startswith("inkbox-h-"):
            forwarded.append((k.removeprefix("inkbox-h-"), v))
    if not request_id:
        return None
    return _Envelope(
        request_id=request_id,
        method=method,
        path=path,
        route_kind=route_kind,
        ws_id=ws_id,
        forwarded_headers=forwarded,
        body=body,
    )


def _filter_response_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(k, v) for k, v in headers if k.lower() not in _HOP_BY_HOP_RESPONSE]


async def _invoke_asgi_http(
    *,
    app: Any,
    method: str,
    path: str,
    headers: list[tuple[str, str]],
    body: bytes,
    disconnect_event: asyncio.Event | None = None,
) -> tuple[int, list[tuple[str, str]], bytes]:
    raw_path, _, query_string = path.partition("?")
    asgi_headers = []
    for k, v in headers:
        if k.lower() in _HOP_BY_HOP_REQUEST:
            continue
        asgi_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "https",
        "path": raw_path,
        "raw_path": raw_path.encode("utf-8"),
        "query_string": query_string.encode("utf-8"),
        "root_path": "",
        "headers": asgi_headers,
        "client": ("0.0.0.0", 0),
        "server": ("inkbox-tunnel", 443),
    }

    body_sent = False
    disc = disconnect_event if disconnect_event is not None else asyncio.Event()

    async def receive() -> dict[str, Any]:
        nonlocal body_sent
        if not body_sent:
            body_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        # Subsequent calls must block until the dispatch is genuinely
        # cancelled (stream RST, connection drop, etc.) rather than
        # returning http.disconnect immediately — ASGI handlers that
        # poll receive() for backpressure / disconnect (SSE, streaming
        # responses) would otherwise terminate the moment they checked.
        await disc.wait()
        return {"type": "http.disconnect"}

    response_status = 500
    response_headers: list[tuple[str, str]] = []
    response_body = bytearray()

    async def send(message: dict[str, Any]) -> None:
        nonlocal response_status
        if message["type"] == "http.response.start":
            response_status = int(message["status"])
            for k, v in message.get("headers", []):
                response_headers.append((k.decode("latin-1"), v.decode("latin-1")))
        elif message["type"] == "http.response.body":
            chunk = message.get("body") or b""
            if chunk:
                response_body.extend(chunk)

    await app(scope, receive, send)
    return response_status, response_headers, bytes(response_body)


def _parse_complete_http_request(
    buf: bytes,
) -> tuple[str, str, list[tuple[str, str]], bytes]:
    """Strict HTTP/1.1 request parser; honors Content-Length only."""
    head, sep, rest = bytes(buf).partition(b"\r\n\r\n")
    if not sep:
        raise _NeedMoreData()
    lines = head.split(b"\r\n")
    if not lines:
        raise _NeedMoreData()
    request_line = lines[0].decode("latin-1")
    parts = request_line.split(" ", 2)
    method = parts[0] if parts else "GET"
    path = parts[1] if len(parts) > 1 else "/"
    headers: list[tuple[str, str]] = []
    content_length = 0
    for raw in lines[1:]:
        if not raw:
            continue
        k, _, v = raw.decode("latin-1").partition(":")
        key = k.strip().lower()
        val = v.strip()
        headers.append((key, val))
        if key == "content-length":
            try:
                content_length = int(val)
            except ValueError:
                content_length = 0
    if len(rest) < content_length:
        raise _NeedMoreData()
    body = rest[:content_length]
    return method, path, headers, body


def _build_http_response(
    status: int,
    headers: list[tuple[str, str]],
    body: bytes,
) -> bytes:
    reason = {
        200: "OK", 201: "Created", 204: "No Content",
        301: "Moved Permanently", 302: "Found", 304: "Not Modified",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 405: "Method Not Allowed", 413: "Payload Too Large",
        422: "Unprocessable Entity", 500: "Internal Server Error",
        502: "Bad Gateway", 503: "Service Unavailable",
    }.get(status, "OK")
    lines = [f"HTTP/1.1 {status} {reason}"]
    has_cl = any(k.lower() == "content-length" for k, _ in headers)
    has_conn = any(k.lower() == "connection" for k, _ in headers)
    for k, v in headers:
        lines.append(f"{k}: {v}")
    if not has_cl:
        lines.append(f"content-length: {len(body)}")
    if not has_conn:
        lines.append("connection: close")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + body


# ---------------------------------------------------------------------------
# WebSocket ASGI session
# ---------------------------------------------------------------------------


def _encode_ws_envelope(msg: dict[str, Any]) -> bytes:
    """Encode an ASGI websocket message as the wire envelope (length-prefixed JSON)."""
    if msg["type"] == "websocket.send":
        if msg.get("text") is not None:
            wire = {"type": "text", "data": msg["text"]}
        elif msg.get("bytes") is not None:
            wire = {
                "type": "binary",
                "data": msg["bytes"].decode("latin-1"),
            }
        else:
            wire = {"type": "text", "data": ""}
    elif msg["type"] == "websocket.close":
        wire = {
            "type": "close",
            "code": msg.get("code", 1000),
            "reason": msg.get("reason", "") or "",
        }
    else:
        wire = {"type": "text", "data": ""}
    payload = json.dumps(wire, separators=(",", ":")).encode("utf-8")
    return struct.pack(">I", len(payload)) + payload


class _WSASGISession:
    """
    Drives the local FastAPI ASGI websocket route. Owns the receive/
    send queues and exposes:

    - ``run_until_accept()`` — start the route, block until the app
      sends ``accept`` or ``close``; return the message it sent.
    - ``deliver(msg)`` — push an inbound wire envelope as an ASGI
      ``websocket.receive`` (or ``websocket.disconnect``) message.
    - ``outbound()`` — async-iterate every ``websocket.send`` /
      ``websocket.close`` the app produces after accept.
    - ``close(code)`` — terminate the ASGI handler.
    """

    def __init__(
        self,
        *,
        app: Any,
        path: str,
        headers: list[tuple[str, str]],
    ):
        self._app = app
        raw_path, _, query_string = path.partition("?")
        asgi_headers: list[tuple[bytes, bytes]] = []
        offered_subprotocols: list[str] = []
        for k, v in headers:
            if k.lower() in _HOP_BY_HOP_REQUEST:
                continue
            if k.lower() == "sec-websocket-protocol":
                offered_subprotocols.extend(
                    p.strip() for p in v.split(",") if p.strip()
                )
                continue
            asgi_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
        self._scope = {
            "type": "websocket",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "scheme": "wss",
            "path": raw_path,
            "raw_path": raw_path.encode("utf-8"),
            "query_string": query_string.encode("utf-8"),
            "root_path": "",
            "headers": asgi_headers,
            "client": ("0.0.0.0", 0),
            "server": ("inkbox-tunnel", 443),
            "subprotocols": offered_subprotocols,
        }
        self._inbound: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._outbound: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        self._accepted = asyncio.Event()
        self._accept_msg: dict[str, Any] | None = None
        self._closed = False
        self._task: asyncio.Task[None] | None = None

    async def run_until_accept(self) -> dict[str, Any]:
        await self._inbound.put({"type": "websocket.connect"})
        self._task = asyncio.create_task(self._run_app())
        await self._accepted.wait()
        assert self._accept_msg is not None
        return self._accept_msg

    async def _run_app(self) -> None:
        try:
            await self._app(self._scope, self._inbound.get, self._send)
        except Exception:
            logger.exception("[tunnel-client] WS ASGI app raised")
            if not self._accepted.is_set():
                self._accept_msg = {"type": "websocket.close", "code": 1011}
                self._accepted.set()
        finally:
            await self._outbound.put(None)

    async def _send(self, msg: dict[str, Any]) -> None:
        if msg["type"] in ("websocket.accept", "websocket.close") and not self._accepted.is_set():
            self._accept_msg = msg
            self._accepted.set()
            if msg["type"] == "websocket.close":
                # The app rejected before accepting; nothing to pump.
                return
            return
        if msg["type"] in ("websocket.send", "websocket.close"):
            await self._outbound.put(msg)

    async def outbound(self):
        while True:
            msg = await self._outbound.get()
            if msg is None:
                return
            yield msg
            if msg["type"] == "websocket.close":
                return

    def signal_outbound_eof(self) -> None:
        """Push the sentinel that ends ``outbound()`` cleanly.

        Used by the pump on shutdown so the sender task can exit on
        its own (no cancel required), and idempotent — extra sentinels
        on an already-closed queue are harmless.
        """
        try:
            self._outbound.put_nowait(None)
        except asyncio.QueueFull:
            pass

    async def deliver(self, wire: dict[str, Any]) -> None:
        kind = wire.get("type")
        if kind == "text":
            await self._inbound.put(
                {"type": "websocket.receive", "text": wire.get("data", "")},
            )
        elif kind == "binary":
            data = wire.get("data", "")
            payload = data.encode("latin-1") if isinstance(data, str) else bytes(data)
            await self._inbound.put(
                {"type": "websocket.receive", "bytes": payload},
            )
        elif kind == "close":
            await self._inbound.put(
                {
                    "type": "websocket.disconnect",
                    "code": int(wire.get("code", 1000)),
                },
            )

    async def close(self, *, code: int) -> None:
        if self._closed:
            return
        self._closed = True
        await self._inbound.put({"type": "websocket.disconnect", "code": code})
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
                try:
                    await self._task
                except (asyncio.CancelledError, Exception):
                    pass
