"""
src/inkbox_tunnels_api.py

Interim raw-httpx wrapper for the Inkbox tunnels control plane. The
currently-pinned ``inkbox`` SDK does not expose a ``client.tunnels.*``
surface yet, so the bootstrap drives the REST API directly.

Synchronous on purpose — the bootstrap runs before uvicorn starts the
event loop.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import httpx

from data_models.tunnel import TunnelTLSMode


class TunnelsAPIError(RuntimeError):
    """Raised when the tunnels control plane returns a non-2xx response."""

    def __init__(self, status_code: int, body: str, *, method: str, path: str):
        super().__init__(f"{method} {path} -> {status_code}: {body}")
        self.status_code = status_code
        self.body = body


class TunnelsAPI:
    """
    Thin sync wrapper around ``/api/v1/tunnels/*``.

    Authentication is the same ``X-API-Key`` header used elsewhere by
    the Inkbox SDK. Returns parsed JSON dicts; the caller is responsible
    for picking the fields it cares about.
    """

    def __init__(self, *, base_url: str, api_key: str, timeout: float = 30.0):
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={"X-API-Key": api_key, "Accept": "application/json"},
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "TunnelsAPI":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _request(
        self, method: str, path: str, *, json: Any = None, timeout: float | None = None,
    ) -> Any:
        kwargs: dict[str, Any] = {"json": json}
        if timeout is not None:
            kwargs["timeout"] = timeout
        resp = self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            raise TunnelsAPIError(
                resp.status_code, resp.text, method=method, path=path,
            )
        if not resp.content:
            return None
        return resp.json()

    def create(
        self,
        *,
        tunnel_name: str,
        tls_mode: TunnelTLSMode = TunnelTLSMode.EDGE,
        description: str | None = None,
    ) -> dict[str, Any]:
        """POST /tunnels/ — returns ``{tunnel, connect_secret}``."""
        body: dict[str, Any] = {
            "tunnel_name": tunnel_name,
            "tls_mode": tls_mode.value,
        }
        if description is not None:
            body["description"] = description
        return self._request("POST", "/tunnels/", json=body)

    def list(self) -> list[dict[str, Any]]:
        """GET /tunnels/ — list this org's tunnels."""
        result = self._request("GET", "/tunnels/")
        if isinstance(result, dict) and "tunnels" in result:
            return list(result["tunnels"])
        if isinstance(result, list):
            return result
        return []

    def get(self, tunnel_id: UUID | str) -> dict[str, Any]:
        return self._request("GET", f"/tunnels/{tunnel_id}")

    def patch(self, tunnel_id: UUID | str, **fields: Any) -> dict[str, Any]:
        return self._request("PATCH", f"/tunnels/{tunnel_id}", json=fields)

    def delete(self, tunnel_id: UUID | str) -> dict[str, Any] | None:
        return self._request("DELETE", f"/tunnels/{tunnel_id}")

    def rotate_secret(self, tunnel_id: UUID | str) -> dict[str, Any]:
        return self._request("POST", f"/tunnels/{tunnel_id}/rotate-secret")

    def sign_csr(self, tunnel_id: UUID | str, csr_pem: str) -> dict[str, Any]:
        # The server runs the full ACME flow synchronously inside this
        # request (Route53 TXT write + INSYNC waiter + LE order polling).
        # 30s isn't enough; LE polling alone can eat that much before
        # the order transitions to ``valid``.
        return self._request(
            "POST",
            f"/tunnels/{tunnel_id}/sign-csr",
            json={"csr_pem": csr_pem},
            timeout=180.0,
        )
