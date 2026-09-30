"""Local gateway.

WebSocket frames plus HTTP on 127.0.0.1. Token auth. One protocol for the
CLI and channel adapters (ARCHITECTURE §3.1, §4, and §12).
"""

from praxis_prime.gateway.protocol import PROTOCOL_VERSION, ListenError, parse_listen

__all__ = ["PROTOCOL_VERSION", "ListenError", "parse_listen"]
