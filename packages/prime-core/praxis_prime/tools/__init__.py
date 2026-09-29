"""Tool registry and the built-in tools.

Risk classes are READ, DRAFT, SEND, DESTRUCTIVE, SPEND, and SHARE. The
policy engine reads them before a tool runs.

ARCHITECTURE §8. The MVP set is read_file, list_dir, shell, and web_fetch.
"""

from praxis_prime.tools.builtin import builtin_registry
from praxis_prime.tools.registry import Risk, Tool, ToolContext, ToolRegistry

__all__ = [
    "Risk",
    "Tool",
    "ToolContext",
    "ToolRegistry",
    "builtin_registry",
]
