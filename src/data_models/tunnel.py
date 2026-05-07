"""
src/data_models/tunnel.py

Sample-client tunnel-mode enum. Mirrors the ``tls_mode`` field of the
Inkbox ``POST /api/v1/tunnels/`` request — keep the values in sync with
the server contract.
"""

from __future__ import annotations

from enum import StrEnum


class TunnelTLSMode(StrEnum):
    """
    TLS-termination model for the customer's Inkbox tunnel.

    Attributes:
        EDGE: Inkbox terminates TLS at the shared edge NLB using its
            wildcard ACM cert. Customer code never sees raw bytes; the
            tunnel envelope arrives as plaintext HTTP. Default.
        PASSTHROUGH: Inkbox forwards raw TCP via the passthrough NLB.
            Customer terminates TLS in this process using a Let's
            Encrypt cert obtained via ``POST /tunnels/{id}/sign-csr``;
            the private key never leaves the customer.
    """
    EDGE = "edge"
    PASSTHROUGH = "passthrough"
