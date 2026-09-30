"""MCP client and the optional stdio server.

The client speaks stdio and streamable HTTP, with a legacy SSE fallback.
``praxis-prime mcp serve`` is off unless that command is run.

ARCHITECTURE §8.
"""

from praxis_prime.mcp.config import ServerSpec, load_servers

__all__ = ["ServerSpec", "load_servers"]
