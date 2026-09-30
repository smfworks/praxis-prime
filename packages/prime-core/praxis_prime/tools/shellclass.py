"""Fail-closed classification of shell commands.

A denylist cannot name every delete. A command runs without approval only
when every simple command is on the read-only allowlist and the line has no
expansion, redirection, or other syntax we cannot account for. Anything else
needs a human. ``shlex`` parses each simple command; a parse error needs
approval too.

The allowlist is small on purpose: ``ls``, ``cat`` / ``head`` / ``tail`` of
concrete paths inside the workspace, ``git status``, ``git diff`` of existing
non-secret files (or ``--stat`` / ``--name-only`` / ``--name-status``),
``git log`` without ``-p``, and ``pytest --collect-only`` (check mode,
including ``python -m pytest``). A directory, ``.``, or other on-disk non-file
beside those files asks unless a summary flag is present. Secret filenames use
:func:`praxis_prime.policy.boundary.is_secret_path`, including git pathspecs.
Globs, ``rev:path``, and exclude or stacked pathspec magic are not allowlisted.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from praxis_prime.policy.boundary import is_secret_path
from praxis_prime.tools.registry import Risk

_RANK = {
    Risk.READ: 0,
    Risk.DRAFT: 1,
    Risk.SEND: 2,
    Risk.SHARE: 3,
    Risk.SPEND: 4,
    Risk.DESTRUCTIVE: 5,
}

# Risk labels for the approval card. Missing a pattern is not "safe":
# the allowlist below is what permits a command to skip approval.
_DESTRUCTIVE = (
    re.compile(
        r"(?i)(?:^|[;&|(`\n])\s*(?:sudo\s+|command\s+|exec\s+)*"
        r"(?:rm|rmdir|unlink|shred)\b"
    ),
    re.compile(r"(?i)\b(?:busybox|toybox)\s+(?:rm|shred|dd)\b"),
    re.compile(r"(?i)\bmkfs(?:\.\w+)?\b"),
    re.compile(r"(?i)(?:^|[;&|(`\n])\s*(?:sudo\s+)?dd\b"),
    re.compile(r"(?i)\btruncate\b"),
    re.compile(r"(?i)\bgit\s+clean\b"),
    re.compile(r"(?i)\bgit\s+reset\b[^\n]*--hard\b"),
    re.compile(r"(?i)\bgit\s+checkout\b[^\n]*(?:\s--(?:\s|$)|\s-f\b|--force\b)"),
    re.compile(r"(?i)\bgit\s+push\b[^\n]*(?:\s-f\b|\s--force\b)"),
    re.compile(r"(?i)\b(?:drop\s+table|delete\s+from|truncate\s+table)\b"),
    re.compile(
        r"(?i)\bfind\b[^\n]*(?:\s-delete\b|\s-exec\b|\s-execdir\b|\s-okdir\b|\s-ok\b)"
    ),
    re.compile(r"(?i)\bgio\s+trash\b"),
    re.compile(r"(?i)\bsed\b[^\n]*(?:\s--in-place\b|\s-[A-Za-z]*i\b)"),
    re.compile(r"(?i)(?:^|[;&|(`\n])\s*(?:sudo\s+)?tee\b"),
    re.compile(r"(?i)(?:^|[;&|(`\n])\s*(?:sudo\s+)?(?:mv|cp)\b"),
    re.compile(r"(?i)(?:^|[;&|(`\n])\s*(?:sudo\s+)?(?:xargs|eval)\b"),
    re.compile(
        r"(?i)\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|python|python3|perl|ruby|node)\b"
    ),
    re.compile(r"(?i)(?:^|[;&|(`\n])\s*alias\b"),
    re.compile(r"(?i)\bexpand_aliases\b"),
    re.compile(
        r"(?i)(?:^|[;&|(`\n])\s*(?:sudo\s+)?env\b|"
        r"(?:^|[;&|(`\n])\s*[A-Za-z_][A-Za-z0-9_]*="
    ),
)
_SEND = (
    re.compile(r"(?i)(?:^|[;&|(`\n])\s*(?:sudo\s+)?(?:sendmail|msmtp|mail|mailx)\b"),
    re.compile(r"(?i)\bgit\s+push\b"),
    re.compile(r"(?i)(?:^|[;&|(`\n])\s*(?:scp|rsync)\b"),
)
_SPEND = (re.compile(r"(?i)\b(?:stripe|paypal)\b[^\n]*(?:charge|pay|transfer)\b"),)
_SHARE = (
    re.compile(r"(?i)(?:^|[;&|(`\n])\s*(?:sudo\s+)?(?:chmod|chown|chgrp)\b"),
    re.compile(r"(?i)\bgit\s+remote\s+add\b"),
)
# Applied only after the allowlist misses, so ``python -m pytest --collect-only``
# stays a read. An interpreter that is not that check mode can delete files.
_INTERPRETER = re.compile(
    r"(?i)(?:^|[;&|(`\n])\s*(?:sudo\s+)?(?:python|python3|perl|ruby|node|php|sh|bash|zsh|dash)\b"
)

_LS_SHORT = re.compile(r"^-[lah1AFCrtSRs]+$")
_LS_LONG = frozenset(
    {
        "--all",
        "--almost-all",
        "--human-readable",
        "--classify",
        "--directory",
        "--size",
        "--color=never",
        "--color=auto",
        "--color=always",
        "--group-directories-first",
    }
)
_GIT_STATUS = frozenset(
    {
        "-s",
        "-b",
        "-z",
        "--short",
        "--porcelain",
        "--porcelain=v1",
        "--branch",
        "--ignored",
        "--column",
        "--no-column",
        "-uno",
        "--untracked-files=no",
        "--untracked-files=normal",
        "--untracked-files=all",
    }
)
_GIT_DIFF = frozenset(
    {
        "--stat",
        "--numstat",
        "--shortstat",
        "--name-only",
        "--name-status",
        "--cached",
        "--staged",
        "--exit-code",
        "--quiet",
        "--raw",
        "--summary",
        "-w",
        "-b",
        "--check",
        "--no-color",
        "--color",
        "--ignore-space-change",
        "--ignore-all-space",
        "--word-diff",
        "--word-diff=plain",
        "--word-diff=none",
    }
)
_GIT_LOG = frozenset(
    {
        "--oneline",
        "--graph",
        "--decorate",
        "--all",
        "--stat",
        "--name-only",
        "--name-status",
        "--no-color",
        "--color",
        "--reverse",
    }
)
_SUMMARY_FLAGS = frozenset({"--stat", "--name-only", "--name-status"})
_SAFE_PATHSPEC_MAGIC = frozenset({"literal", "top", "icase"})
_PYTEST_FLAGS = frozenset(
    {"--collect-only", "--co", "-q", "--quiet", "--disable-warnings"}
)
_METACHAR_RISK = frozenset(
    {
        "redirection requires approval",
        "parameter or command substitution requires approval",
        "expansion inside quotes requires approval",
        "history expansion requires approval",
        "tilde expansion requires approval",
        "brace expansion requires approval",
        "background job requires approval",
    }
)


@dataclass(frozen=True, slots=True)
class ShellClass:
    """Whether a command is confidently read-only, and the risk if it is not."""

    allowlisted: bool
    risk: Risk
    reason: str
    write_capable: bool


def classify_shell(command: str, *, workspace: Path | None = None) -> ShellClass:
    """Classify ``command``. Unknown or unparsed syntax is not allowlisted."""
    text = command.strip()
    if not text:
        return ShellClass(False, Risk.READ, "empty shell command requires approval", True)
    segments, problem = _segments(text)
    if (
        problem == ""
        and segments is not None
        and all(_allowlisted_segment(segment, workspace) for segment in segments)
        and _label(text)[0] == Risk.READ
    ):
        return ShellClass(True, Risk.READ, "", False)
    risk, reason = _label(text)
    if problem:
        meta = Risk.DESTRUCTIVE if problem in _METACHAR_RISK else Risk.READ
        risk, reason = _prefer(risk, reason, meta, problem)
    if not reason:
        reason = "command is not on the read-only allowlist"
    if risk == Risk.READ and _INTERPRETER.search(text):
        risk = Risk.DESTRUCTIVE
        if reason == "command is not on the read-only allowlist":
            reason = "interpreter invocation requires approval"
    return ShellClass(False, risk, reason, True)


def _label(command: str) -> tuple[Risk, str]:
    risk = Risk.READ
    reason = ""
    if _matches(_DESTRUCTIVE, command):
        risk, reason = _prefer(
            risk,
            reason,
            Risk.DESTRUCTIVE,
            "command looks destructive (delete, overwrite, or interpreter)",
        )
    if _matches(_SPEND, command):
        risk, reason = _prefer(risk, reason, Risk.SPEND, "command looks like a payment")
    if _matches(_SHARE, command):
        risk, reason = _prefer(
            risk, reason, Risk.SHARE, "command looks like it shares access"
        )
    if _matches(_SEND, command):
        risk, reason = _prefer(risk, reason, Risk.SEND, "command looks like it sends data")
    return risk, reason


def _prefer(left: Risk, left_reason: str, right: Risk, right_reason: str) -> tuple[Risk, str]:
    if _RANK[right] > _RANK[left]:
        return right, right_reason
    return left, left_reason


def _matches(patterns: tuple[re.Pattern[str], ...], command: str) -> bool:
    return any(pattern.search(command) for pattern in patterns)


def _segments(command: str) -> tuple[list[str] | None, str]:
    """Split on unquoted separators. A syntax we do not understand is an error."""
    segments: list[str] = []
    buf: list[str] = []
    index = 0
    length = len(command)
    while index < length:
        char = command[index]
        if char == "'":
            buf.append(char)
            index += 1
            while index < length and command[index] != "'":
                buf.append(command[index])
                index += 1
            if index >= length:
                return None, "unbalanced quotes; shell command requires approval"
            buf.append("'")
            index += 1
            continue
        if char == '"':
            buf.append(char)
            index += 1
            while index < length and command[index] != '"':
                if command[index] == "\\" and index + 1 < length:
                    nxt = command[index + 1]
                    if nxt in "$`\"\\":
                        return None, "expansion inside quotes requires approval"
                    buf.append(command[index])
                    buf.append(nxt)
                    index += 2
                    continue
                if command[index] in "$`":
                    return None, "expansion inside quotes requires approval"
                buf.append(command[index])
                index += 1
            if index >= length:
                return None, "unbalanced quotes; shell command requires approval"
            buf.append('"')
            index += 1
            continue
        if char == "\\":
            if index + 1 >= length:
                return None, "trailing escape; shell command requires approval"
            buf.append(char)
            buf.append(command[index + 1])
            index += 2
            continue
        if char in "$`":
            return None, "parameter or command substitution requires approval"
        if char in "><":
            return None, "redirection requires approval"
        if char == "!" and _word_start(command, index):
            return None, "history expansion requires approval"
        if char == "~" and _word_start(command, index):
            return None, "tilde expansion requires approval"
        if char in "{}":
            return None, "brace expansion requires approval"
        if char == "#" and _word_start(command, index):
            while index < length and command[index] != "\n":
                index += 1
            continue
        if char in {"\n", ";"}:
            segments.append("".join(buf))
            buf = []
            index += 1
            continue
        if char == "&":
            if index + 1 < length and command[index + 1] == "&":
                segments.append("".join(buf))
                buf = []
                index += 2
                continue
            return None, "background job requires approval"
        if char == "|":
            if index + 1 < length and command[index + 1] == "|":
                segments.append("".join(buf))
                buf = []
                index += 2
                continue
            segments.append("".join(buf))
            buf = []
            index += 1
            continue
        buf.append(char)
        index += 1
    segments.append("".join(buf))
    cleaned = [part.strip() for part in segments]
    if not cleaned or any(not part for part in cleaned):
        return None, "empty shell command requires approval"
    return cleaned, ""


def _word_start(command: str, index: int) -> bool:
    if index == 0:
        return True
    return command[index - 1].isspace() or command[index - 1] in ";&|("


def _allowlisted_segment(segment: str, workspace: Path | None) -> bool:
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        return False
    if not tokens:
        return False
    command = tokens[0]
    if "/" in command or command.startswith("."):
        return False
    if command == "ls":
        return _ls(tokens, workspace)
    if command == "cat":
        return _reader(tokens, workspace, flags=False)
    if command in {"head", "tail"}:
        return _head_tail(tokens, workspace)
    if command == "git":
        return _git(tokens, workspace)
    if command in {"pytest", "py.test"}:
        return _pytest(tokens[1:], workspace)
    if (
        command in {"python", "python3"}
        and len(tokens) >= 3
        and tokens[1] == "-m"
        and tokens[2] == "pytest"
    ):
        return _pytest(tokens[3:], workspace)
    return False


def _ls(tokens: list[str], workspace: Path | None) -> bool:
    for arg in tokens[1:]:
        if arg.startswith("-"):
            if arg not in _LS_LONG and _LS_SHORT.fullmatch(arg) is None:
                return False
            continue
        if not _in_workspace(arg, workspace):
            return False
    return True


def _reader(tokens: list[str], workspace: Path | None, *, flags: bool) -> bool:
    del flags
    if len(tokens) == 1:
        return True
    for arg in tokens[1:]:
        if arg.startswith("-") or not _concrete_read_operand(arg, workspace):
            return False
    return True


def _head_tail(tokens: list[str], workspace: Path | None) -> bool:
    index = 1
    while index < len(tokens):
        arg = tokens[index]
        if arg in {"-n", "-c"}:
            if index + 1 >= len(tokens) or re.fullmatch(r"\d+", tokens[index + 1]) is None:
                return False
            index += 2
            continue
        if re.fullmatch(r"-[nc]\d+", arg) or re.fullmatch(r"-\d+", arg):
            index += 1
            continue
        if arg.startswith("-") or not _concrete_read_operand(arg, workspace):
            return False
        index += 1
    return True


def _git(tokens: list[str], workspace: Path | None) -> bool:
    if len(tokens) < 2:
        return False
    index = 1
    while index < len(tokens) and tokens[index].startswith("-"):
        if tokens[index] != "--no-pager":
            return False
        index += 1
    if index >= len(tokens):
        return False
    sub = tokens[index]
    index += 1
    if sub not in {"status", "diff", "log"}:
        return False
    allowed = {"status": _GIT_STATUS, "diff": _GIT_DIFF, "log": _GIT_LOG}[sub]
    summary = False
    pathspecs: list[str] = []
    saw_nonfile = False
    while index < len(tokens):
        arg = tokens[index]
        if arg == "--":
            index += 1
            while index < len(tokens):
                operand = tokens[index]
                if not _safe_git_operand(operand, workspace):
                    return False
                if sub == "diff" and not _is_explicit_safe_file(operand, workspace):
                    # After ``--`` every operand is a pathspec, including a
                    # directory. Summary flags do not relax that.
                    return False
                if sub == "diff":
                    pathspecs.append(operand)
                index += 1
            break
        if arg.startswith("-"):
            if arg in {"-p", "--patch"}:
                return False
            if arg in _SUMMARY_FLAGS:
                summary = True
            if arg in allowed:
                index += 1
                continue
            if sub == "log" and re.fullmatch(r"-\d+", arg):
                index += 1
                continue
            if sub == "log" and arg in {"-n", "--max-count"}:
                if index + 1 >= len(tokens) or re.fullmatch(r"\d+", tokens[index + 1]) is None:
                    return False
                index += 2
                continue
            if (
                sub == "log"
                and arg.startswith("--max-count=")
                and arg.split("=", 1)[1].isdigit()
            ):
                index += 1
                continue
            if sub == "diff" and (
                re.fullmatch(r"-U\d+", arg) or re.fullmatch(r"--unified=\d+", arg)
            ):
                index += 1
                continue
            if sub == "log" and arg.startswith("--pretty=") and _safe_value(arg.split("=", 1)[1]):
                index += 1
                continue
            if sub == "log" and arg in {"--since", "--until", "--author", "--grep"}:
                if index + 1 >= len(tokens) or not _safe_value(tokens[index + 1]):
                    return False
                index += 2
                continue
            prefixes = ("--since", "--until", "--author", "--grep")
            if sub == "log" and any(arg.startswith(prefix + "=") for prefix in prefixes):
                if not _safe_value(arg.split("=", 1)[1]):
                    return False
                index += 1
                continue
            if sub == "status" and arg in {"-u", "--untracked-files"}:
                if index + 1 < len(tokens) and tokens[index + 1] in {"no", "normal", "all"}:
                    index += 2
                    continue
                index += 1
                continue
            return False
        if not _safe_git_operand(arg, workspace):
            return False
        if sub == "diff":
            if _is_explicit_safe_file(arg, workspace):
                pathspecs.append(arg)
            elif _operand_exists_as_nonfile(arg, workspace):
                # A directory, ``.``, or trailing slash is a pathspec. Skipping
                # it lets ``git diff note.txt config`` print the directory.
                saw_nonfile = True
        index += 1
    if sub != "diff":
        return True
    if saw_nonfile and not summary:
        return False
    if not pathspecs:
        return summary
    return all(_is_explicit_safe_file(item, workspace) for item in pathspecs)


def _pytest(args: list[str], workspace: Path | None) -> bool:
    if "--collect-only" not in args and "--co" not in args:
        return False
    for arg in args:
        if arg in _PYTEST_FLAGS:
            continue
        if arg.startswith("-") or not _in_workspace(arg, workspace):
            return False
    return True


def _safe_value(value: str) -> bool:
    if any(char in value for char in "$`!{}<>|&;\\"):
        return False
    if value.startswith("/") or value.startswith("~") or value.startswith("-"):
        return False
    return ".." not in Path(value).parts


def _concrete_read_operand(arg: str, workspace: Path | None) -> bool:
    """True for one workspace path. Globs are expanded by the shell later."""
    if _has_glob(arg) or _operand_is_secret(arg, workspace):
        return False
    return _in_workspace(arg, workspace)


def _safe_git_operand(arg: str, workspace: Path | None) -> bool:
    if not arg or any(char in arg for char in "$`!{}<>|&;\\"):
        return False
    if _has_glob(arg):
        return False
    if arg.startswith("~") or "/../" in arg or arg.startswith("../") or arg == "..":
        return False
    if arg.endswith("/.."):
        return False
    if _is_rev_path(arg) or _rejected_pathspec_magic(arg):
        return False
    if _operand_is_secret(arg, workspace):
        return False
    if arg.startswith("/"):
        return _in_workspace(arg, workspace)
    return True


def _has_glob(token: str) -> bool:
    return any(char in token for char in "*?[")


def _is_rev_path(token: str) -> bool:
    """True for ``HEAD:path`` style operands. The whole string is not one filename."""
    return ":" in token and not token.startswith(":")


def _rejected_pathspec_magic(token: str) -> bool:
    """Exclude and stacked magic change which files git reads."""
    if not token.startswith(":"):
        return False
    return not _single_safe_magic(token)


def _single_safe_magic(token: str) -> bool:
    if len(token) < 2:
        return False
    rest = token[1:]
    if rest.startswith("("):
        close = rest.find(")")
        if close < 0:
            return False
        words = [word for word in rest[1:close].split(",") if word]
        path = rest[close + 1 :]
        if len(words) != 1 or words[0] not in _SAFE_PATHSPEC_MAGIC:
            return False
        return bool(path) and not _has_glob(path) and ":" not in path
    if rest[0] in "!^":
        return False
    if rest.startswith("/"):
        path = rest[1:]
        return bool(path) and not _has_glob(path) and ":" not in path
    return False


def _operand_exists_as_nonfile(arg: str, workspace: Path | None) -> bool:
    """True when ``arg`` is on disk and is not a regular file.

    Missing names stay revisions (``v1.0``, ``origin/main``). A directory,
    ``.``, ``./``, or a trailing slash is a pathspec git will expand.
    """
    if workspace is None or not _safe_git_operand(arg, workspace):
        return False
    body = _concrete_path(arg)
    if not body or ".." in Path(body).parts:
        return False
    path = Path(body)
    candidate = path if path.is_absolute() else workspace / path
    try:
        if candidate.is_file():
            return False
        return candidate.exists()
    except OSError:
        return False


def _is_explicit_safe_file(arg: str, workspace: Path | None) -> bool:
    """True only when ``arg`` is an existing regular file in the worktree.

    A missing name is a revision (``v1.0``, ``origin/main``) or a path that
    git can still expand from the index. Neither is an allowlisted file.
    """
    if workspace is None or not _safe_git_operand(arg, workspace):
        return False
    body = _concrete_path(arg)
    if body is None or body in {".", "..", "./"} or body.endswith("/"):
        return False
    path = Path(body)
    if ".." in path.parts:
        return False
    candidate = path if path.is_absolute() else workspace / path
    try:
        return candidate.is_file()
    except OSError:
        return False


def _concrete_path(token: str) -> str | None:
    if not token.startswith(":"):
        return token
    if len(token) < 2:
        return None
    rest = token[1:]
    if rest.startswith("("):
        close = rest.find(")")
        if close < 0:
            return None
        return rest[close + 1 :]
    if rest.startswith("/"):
        return rest[1:]
    return None


def _operand_is_secret(token: str, workspace: Path | None) -> bool:
    """True when an operand matches the shared secret denylist.

    Git pathspecs may carry a magic signature (``:(literal)name`` or ``:/name``).
    The signature is stripped and the path is checked with
    :func:`praxis_prime.policy.boundary.is_secret_path`.
    """
    for body in _pathspec_bodies(token):
        if _path_is_secret(body, workspace):
            return True
    return False


def _pathspec_bodies(token: str) -> tuple[str, ...]:
    bodies = [token]
    if not token.startswith(":") or len(token) == 1:
        return (token,)
    rest = token[1:]
    if rest.startswith("("):
        close = rest.find(")")
        if close == -1:
            return (token,)
        rest = rest[close + 1 :]
    else:
        rest = rest.lstrip("!/^")
    if rest and rest != token:
        bodies.append(rest)
    return tuple(bodies)


def _path_is_secret(token: str, workspace: Path | None) -> bool:
    path = Path(token)
    targets = [path]
    if workspace is not None and not path.is_absolute():
        targets.append(workspace / path)
    for target in targets:
        if is_secret_path(target):
            return True
        for part in target.parts:
            if part in {"", ".", ".."}:
                continue
            if is_secret_path(Path(part)):
                return True
    return False


def _in_workspace(token: str, workspace: Path | None) -> bool:
    if not token or token.startswith("-") or "\x00" in token:
        return False
    path = Path(token)
    if workspace is None:
        return not path.is_absolute() and ".." not in path.parts
    root = workspace.resolve()
    candidate = path if path.is_absolute() else root / path
    try:
        resolved = candidate.resolve()
    except OSError:
        return False
    try:
        resolved.relative_to(root)
    except ValueError:
        return False
    return True
