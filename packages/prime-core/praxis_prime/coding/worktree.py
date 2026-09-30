"""Per-task git worktrees.

Each coding task gets a branch named ``prime/<slug>`` and a worktree under
the XDG data directory. The user's checkout is not updated until accept
merges that branch. Discard deletes the branch. Keep leaves the branch
and removes the worktree. None of these paths run ``git push``.

ARCHITECTURE §14. The layout follows ``~/.local/share/praxis-prime/worktrees/``.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from praxis_prime.sandbox.bwrap import scrub_env

_DIFF_LIMIT = 20_000


class CodingError(RuntimeError):
    """The coding task cannot start or cannot finish the git step."""


@dataclass
class TaskWorktree:
    """One isolated checkout for a coding task."""

    repo: Path
    path: Path
    branch: str
    base: str
    commands: list[list[str]] = field(default_factory=list)


def git_root(start: Path) -> Path:
    """Return the repository root that contains ``start``."""
    completed = _git(Path(start), ["rev-parse", "--show-toplevel"], record=None)
    if completed.returncode != 0 or not completed.stdout.strip():
        detail = completed.stderr.strip() or "git did not recognize a repository"
        raise CodingError(f"not a git repository: {start} ({detail})")
    return Path(completed.stdout.strip()).resolve()


def create_worktree(repo: Path, task: str, data_dir: Path) -> TaskWorktree:
    """Add ``prime/<slug>`` at ``data_dir/worktrees/<repo>/<slug>`` from HEAD."""
    root = Path(repo).resolve()
    base = _head(root)
    slug = slugify(task)
    branch = _unique_branch(root, slug)
    leaf = branch.split("/", 1)[1]
    destination = data_dir / "worktrees" / _repo_key(root) / leaf
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        destination = destination.with_name(destination.name + "-" + base[:7])
    record: list[list[str]] = []
    completed = _git(
        root,
        ["worktree", "add", "-b", branch, str(destination), "HEAD"],
        record=record,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise CodingError(f"could not create worktree: {detail}")
    return TaskWorktree(
        repo=root,
        path=destination.resolve(),
        branch=branch,
        base=base,
        commands=record,
    )


def readable_diff(worktree: Path) -> str:
    """Unified diff plus untracked files, truncated for the terminal."""
    status = _git(worktree, ["status", "--short"], record=None)
    diff = _git(worktree, ["diff", "HEAD"], record=None)
    parts: list[str] = []
    if status.stdout.strip():
        parts.append(status.stdout.strip())
    if diff.stdout.strip():
        parts.append(diff.stdout.strip())
    others = _git(worktree, ["ls-files", "--others", "--exclude-standard"], record=None)
    for line in others.stdout.splitlines():
        file = worktree / line
        if not file.is_file():
            continue
        preview = file.read_text(encoding="utf-8", errors="replace")[:2000]
        parts.append(f"new file {line}\n{preview}")
    body = "\n\n".join(parts) if parts else "(no changes)"
    if len(body) > _DIFF_LIMIT:
        return body[:_DIFF_LIMIT] + "\n…[diff truncated]"
    return body


def commit_draft(task: TaskWorktree, message: str) -> bool:
    """Commit pending edits on the task branch. Returns whether a commit was made."""
    status = _git(task.path, ["status", "--porcelain"], record=task.commands)
    if not status.stdout.strip():
        return False
    added = _git(task.path, ["add", "-A"], record=task.commands)
    if added.returncode != 0:
        raise CodingError((added.stderr or "git add failed").strip())
    committed = _git(
        task.path,
        [
            "-c",
            "user.name=Praxis Prime",
            "-c",
            "user.email=praxis-prime@localhost",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            message,
        ],
        record=task.commands,
    )
    if committed.returncode != 0:
        raise CodingError((committed.stderr or "git commit failed").strip())
    return True


def remove_worktree(task: TaskWorktree) -> None:
    """Delete the worktree directory and leave the branch in place."""
    completed = _git(
        task.repo,
        ["worktree", "remove", "--force", str(task.path)],
        record=task.commands,
    )
    if completed.returncode != 0:
        raise CodingError((completed.stderr or "could not remove worktree").strip())
    _git(task.repo, ["worktree", "prune"], record=task.commands)


def accept_task(task: TaskWorktree, message: str) -> str:
    """Commit, remove the worktree, and merge the branch locally. Does not push."""
    commit_draft(task, message)
    remove_worktree(task)
    merged = _git(
        task.repo,
        [
            "-c",
            "user.name=Praxis Prime",
            "-c",
            "user.email=praxis-prime@localhost",
            "-c",
            "commit.gpgsign=false",
            "merge",
            "--no-edit",
            task.branch,
        ],
        record=task.commands,
    )
    if merged.returncode != 0:
        detail = (merged.stderr or merged.stdout).strip()
        raise CodingError(
            f"merge of {task.branch} failed. The branch was kept. {detail}"
        )
    return f"Merged {task.branch} into the current branch. Nothing was pushed."


def discard_task(task: TaskWorktree) -> str:
    """Remove the worktree and delete the task branch. Does not push."""
    remove_worktree(task)
    deleted = _git(task.repo, ["branch", "-D", task.branch], record=task.commands)
    if deleted.returncode != 0:
        raise CodingError((deleted.stderr or "could not delete the branch").strip())
    return f"Discarded {task.branch}. The working tree was not changed."


def keep_task(task: TaskWorktree, message: str) -> str:
    """Commit, remove the worktree, and leave the branch. Does not merge or push."""
    commit_draft(task, message)
    remove_worktree(task)
    return f"Kept branch {task.branch}. It was not merged and nothing was pushed."


def slugify(task: str) -> str:
    """Turn a task sentence into a branch slug."""
    chars: list[str] = []
    for char in task.lower():
        if char.isalnum():
            chars.append(char)
        elif chars and chars[-1] != "-":
            chars.append("-")
    slug = "".join(chars).strip("-")[:40].strip("-")
    return slug or "task"


def _unique_branch(repo: Path, slug: str) -> str:
    branch = f"prime/{slug}"
    number = 2
    while _branch_exists(repo, branch):
        branch = f"prime/{slug}-{number}"
        number += 1
    return branch


def _branch_exists(repo: Path, branch: str) -> bool:
    completed = _git(repo, ["show-ref", "--verify", "--quiet", f"refs/heads/{branch}"], record=None)
    return completed.returncode == 0


def _head(repo: Path) -> str:
    completed = _git(repo, ["rev-parse", "HEAD"], record=None)
    if completed.returncode != 0 or not completed.stdout.strip():
        raise CodingError("repository has no commits yet")
    return completed.stdout.strip()


def _repo_key(repo: Path) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", repo.name).strip("-") or "repo"
    digest = hashlib.sha256(str(repo).encode()).hexdigest()[:8]
    return f"{name}-{digest}"


def _git(
    cwd: Path,
    args: list[str],
    *,
    record: list[list[str]] | None,
) -> subprocess.CompletedProcess[str]:
    """Run git. ``push`` is refused here so accept/discard/keep cannot publish."""
    if _subcommand(args) == "push":
        raise CodingError("refusing to git push; push only runs as an approved tool")
    argv = ["git", "-C", str(cwd), *args]
    if record is not None:
        record.append(argv)
    try:
        return subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            env=_git_env(),
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CodingError(f"git failed: {exc}") from exc


def _subcommand(args: list[str]) -> str:
    skip_value = False
    for arg in args:
        if skip_value:
            skip_value = False
            continue
        if arg in {"-c", "-C"}:
            skip_value = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return ""


def _git_env() -> dict[str, str]:
    env = scrub_env(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["PATH"] = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")
    return env
