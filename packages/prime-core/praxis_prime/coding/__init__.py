"""Coding-agent mode.

Worktrees, instruction discovery, repo context, and project hooks.
``praxis-prime code`` and ``/code`` in chat run a task on ``prime/<slug>``
so the user's checkout stays unchanged until they accept.

ARCHITECTURE §14.
"""

from praxis_prime.coding.session import CodingResult, run_coding_task
from praxis_prime.coding.worktree import CodingError

__all__ = ["CodingError", "CodingResult", "run_coding_task"]
