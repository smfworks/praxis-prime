"""Tool registry and the built-in tools.

Risk classes are READ, DRAFT, SEND, DESTRUCTIVE, SPEND, and SHARE. The
policy engine reads them before a tool runs.

ARCHITECTURE §8. Chat ships read_file, list_dir, shell, and web_fetch.
The runtime also registers ``decide``. Coding mode adds write_file,
edit_file, grep, glob, run_command, and run_tests.
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
