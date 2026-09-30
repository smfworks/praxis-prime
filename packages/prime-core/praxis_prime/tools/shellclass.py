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
beside those files asks unless a summary flag is present. An operand that
starts with ``:`` is a pathspec, allowlisted only when it is an existing
non-secret file. A repo whose git config (including a linked worktree's
common dir and ``config.worktree``) sets a diff driver, a filter,
``core.fsmonitor``, ``extensions.worktreeConfig``, or ``core.attributesFile``
asks, as does an unreadable or oversized config, a ``.gitmodules`` file, or a
``modules`` directory under the git dir. ``info/attributes`` and
``.gitattributes`` (including ``HEAD:.gitattributes`` when ``--attr-source``
is available) that assign ``diff=`` or ``filter=`` are not allowlisted.
Secret filenames use
:func:`praxis_prime.policy.boundary.is_secret_path`, including git pathspecs.
Globs, ``rev:path``, case-folding magic, and exclude or stacked pathspec
magic are not allowlisted.
"""

from __future__ import annotations

import os
import re
import shlex
import stat
import subprocess
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
# Command-line config that wins over .git/config for the forms -c can name.
# fsmonitor, external diff, and hooks still need the repo-config check below:
# a diff driver or filter is not cleared by one -c key.
_GIT_CONFIG_LOCKS = (
    "core.fsmonitor=false",
    "core.hooksPath=/dev/null",
    "diff.external=",
    "core.pager=cat",
    "core.quotePath=true",
    "diff.noprefix=false",
    "diff.relative=false",
    # Submodule git does not inherit -c or --attr-source. Skipping submodules
    # keeps a nested clean filter from running during status or diff.
    "diff.ignoreSubmodules=all",
)
_GIT_FALSE_VALUES = frozenset({"", "0", "false", "no", "off"})
_CONFIG_MAX_BYTES = 1_000_000
_GIT_VERSION = re.compile(r"(\d+)\.(\d+)")
_attr_source_support: bool | None = None
_CONFIG_SECTION = re.compile(
    r'^\[\s*([A-Za-z0-9-]+)(?:\s+"([^"]*)")?\s*\]\s*(?:[#;].*)?$'
)
_SEPARATORS = frozenset({"&&", "||", "|", ";"})
_SAFE_PATHSPEC_MAGIC = frozenset({"literal", "top"})
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
class GitProbe:
    """A read-only ``--name-only`` check for one content-showing git command.

    ``approved`` is the explicit safe-file set the classifier accepted.
    ``command`` asks git which paths that command would show.
    """

    command: str
    approved: frozenset[str]


@dataclass(frozen=True, slots=True)
class ShellClass:
    """Whether a command is confidently read-only, and the risk if it is not."""

    allowlisted: bool
    risk: Risk
    reason: str
    write_capable: bool
    probes: tuple[GitProbe, ...] = ()


@dataclass(frozen=True, slots=True)
class _GitView:
    allowed: bool
    probe: GitProbe | None = None


def classify_shell(command: str, *, workspace: Path | None = None) -> ShellClass:
    """Classify ``command``. Unknown or unparsed syntax is not allowlisted."""
    text = command.strip()
    if not text:
        return ShellClass(False, Risk.READ, "empty shell command requires approval", True)
    segments, problem = _segments(text)
    if problem == "" and segments is not None and _label(text)[0] == Risk.READ:
        decisions = [_allowlisted_segment(segment, workspace) for segment in segments]
        if all(allowed for allowed, _probe in decisions):
            probes = tuple(probe for _allowed, probe in decisions if probe is not None)
            return ShellClass(True, Risk.READ, "", False, probes)
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


def _allowlisted_segment(segment: str, workspace: Path | None) -> tuple[bool, GitProbe | None]:
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        return False, None
    if not tokens:
        return False, None
    command = tokens[0]
    if "/" in command or command.startswith("."):
        return False, None
    if command == "ls":
        return _ls(tokens, workspace), None
    if command == "cat":
        return _reader(tokens, workspace, flags=False), None
    if command in {"head", "tail"}:
        return _head_tail(tokens, workspace), None
    if command == "git":
        decision = _git(tokens, workspace)
        return decision.allowed, decision.probe
    if command in {"pytest", "py.test"}:
        return _pytest(tokens[1:], workspace), None
    if (
        command in {"python", "python3"}
        and len(tokens) >= 3
        and tokens[1] == "-m"
        and tokens[2] == "pytest"
    ):
        return _pytest(tokens[3:], workspace), None
    return False, None


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


def _git(tokens: list[str], workspace: Path | None) -> _GitView:
    if len(tokens) < 2:
        return _GitView(False)
    index = 1
    while index < len(tokens) and tokens[index].startswith("-"):
        if tokens[index] != "--no-pager":
            return _GitView(False)
        index += 1
    if index >= len(tokens):
        return _GitView(False)
    sub = tokens[index]
    index += 1
    if sub not in {"status", "diff", "log"}:
        return _GitView(False)
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
                    return _GitView(False)
                if operand.startswith(":") or sub == "diff":
                    # After ``--`` every diff operand is a pathspec. A leading
                    # ``:`` is a pathspec for every subcommand, never a revision.
                    if not _is_explicit_safe_file(operand, workspace):
                        return _GitView(False)
                if sub == "diff":
                    pathspecs.append(operand)
                index += 1
            break
        if arg.startswith("-"):
            if arg in {"-p", "--patch"}:
                return _GitView(False)
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
                    return _GitView(False)
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
                    return _GitView(False)
                index += 2
                continue
            prefixes = ("--since", "--until", "--author", "--grep")
            if sub == "log" and any(arg.startswith(prefix + "=") for prefix in prefixes):
                if not _safe_value(arg.split("=", 1)[1]):
                    return _GitView(False)
                index += 1
                continue
            if sub == "status" and arg in {"-u", "--untracked-files"}:
                if index + 1 < len(tokens) and tokens[index + 1] in {"no", "normal", "all"}:
                    index += 2
                    continue
                index += 1
                continue
            return _GitView(False)
        if arg.startswith(":"):
            if not _is_explicit_safe_file(arg, workspace):
                return _GitView(False)
            if sub == "diff":
                pathspecs.append(arg)
            index += 1
            continue
        if not _safe_git_operand(arg, workspace):
            return _GitView(False)
        if sub == "diff":
            if _is_explicit_safe_file(arg, workspace):
                pathspecs.append(arg)
            elif _operand_exists_as_nonfile(arg, workspace):
                # A directory, ``.``, or trailing slash is a pathspec. Skipping
                # it lets ``git diff note.txt config`` print the directory.
                saw_nonfile = True
        index += 1
    if sub != "diff":
        return _allow_git(True, workspace, sub)
    if saw_nonfile and not summary:
        return _GitView(False)
    if not pathspecs:
        return _allow_git(summary, workspace, sub)
    if not all(_is_explicit_safe_file(item, workspace) for item in pathspecs):
        return _GitView(False)
    if summary:
        return _allow_git(True, workspace, sub)
    probe = build_name_only_command(shlex.join(tokens))
    if probe is None:
        return _GitView(False)
    approved = frozenset(_normalized_path(item, workspace) for item in pathspecs)
    return _allow_git(True, workspace, sub, GitProbe(probe, approved))


def _allow_git(
    allowed: bool,
    workspace: Path | None,
    sub: str,
    probe: GitProbe | None = None,
) -> _GitView:
    if not allowed:
        return _GitView(False)
    if workspace is not None and _repo_git_is_unsafe(workspace, sub):
        return _GitView(False)
    return _GitView(True, probe)


def _git_supports_attr_source() -> bool:
    """True when this git accepts ``--attr-source`` (2.40 and newer)."""
    global _attr_source_support
    if _attr_source_support is not None:
        return _attr_source_support
    supported = False
    try:
        proc = subprocess.run(
            ["git", "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        match = _GIT_VERSION.search(proc.stdout)
        if match is not None:
            supported = (int(match.group(1)), int(match.group(2))) >= (2, 40)
    except (OSError, subprocess.TimeoutExpired):
        supported = False
    _attr_source_support = supported
    return supported


def _git_config_args() -> list[str]:
    args: list[str] = []
    for item in _GIT_CONFIG_LOCKS:
        args.extend(["-c", item])
    if _git_supports_attr_source():
        # HEAD's tree replaces worktree .gitattributes. core.attributesFile
        # still applies on top of that, so point it at /dev/null too.
        # Git older than 2.40 rejects --attr-source; leave those pins off.
        args.extend(["-c", "core.attributesFile=/dev/null", "--attr-source=HEAD"])
    return args


def harden_git_tokens(tokens: list[str]) -> list[str]:
    """Prefix an allowlisted git invocation so repo config cannot run a program."""
    if not tokens or tokens[0] != "git":
        return list(tokens)
    index = 1
    while index < len(tokens) and tokens[index].startswith("-") and tokens[index] != "--":
        index += 1
    locks = _git_config_args()
    if index >= len(tokens):
        return ["git", *locks, *tokens[1:]]
    sub = tokens[index]
    rebuilt = ["git", *locks, *tokens[1:index], sub]
    if sub in {"status", "diff"}:
        rebuilt.append("--ignore-submodules=all")
    if sub in {"diff", "log", "show"}:
        rebuilt.extend(["--no-ext-diff", "--no-textconv"])
    rebuilt.extend(tokens[index + 1 :])
    return rebuilt


def command_for_sandbox(command: str) -> str:
    """Rewrite allowlisted git segments. Other commands are unchanged."""
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return command
    out: list[str] = []
    index = 0
    while index < len(tokens):
        if tokens[index] in _SEPARATORS:
            out.append(tokens[index])
            index += 1
            continue
        if tokens[index] != "git":
            while index < len(tokens) and tokens[index] not in _SEPARATORS:
                out.append(tokens[index])
                index += 1
            continue
        start = index
        index += 1
        while index < len(tokens) and tokens[index] not in _SEPARATORS:
            index += 1
        out.extend(harden_git_tokens(tokens[start:index]))
    return shlex.join(out)


def _repo_git_is_unsafe(workspace: Path, sub: str) -> bool:
    """True when repo config or attributes can still run a program.

    ``-c`` cannot clear every diff driver or filter. An include is refused
    outright: the file it pulls in is not auto-approved either. Linked
    worktrees keep the shared config in the ``commondir``.
    """
    if _git_config_is_hostile(workspace):
        return True
    if _submodules_present(workspace):
        return True
    if sub in {"diff", "log", "show"} and (
        _attributes_assign_driver(workspace) or _head_attributes_assign_driver(workspace)
    ):
        return True
    return False


@dataclass(frozen=True, slots=True)
class _GitLayout:
    """Git directories a checkout will read, plus a fail-closed flag."""

    dirs: tuple[Path, ...] = ()
    hostile: bool = False


def _git_layout(workspace: Path) -> _GitLayout:
    """Resolve the worktree git dir and, when linked, its common dir."""
    git = workspace / ".git"
    try:
        if not os.path.lexists(git):
            return _GitLayout()
        if git.is_dir():
            gitdir = git
        elif git.is_file():
            pointed = _gitdir_from_pointer(workspace, git)
            if pointed is None:
                return _GitLayout(hostile=True)
            gitdir = pointed
        else:
            return _GitLayout(hostile=True)
    except OSError:
        return _GitLayout(hostile=True)
    try:
        if not gitdir.is_dir():
            return _GitLayout(hostile=True)
    except OSError:
        return _GitLayout(hostile=True)
    common, bad = _common_dir(gitdir)
    if bad:
        return _GitLayout(dirs=(gitdir,), hostile=True)
    dirs = [gitdir]
    if common is not None:
        try:
            if not common.is_dir():
                return _GitLayout(dirs=(gitdir,), hostile=True)
            if common.resolve() != gitdir.resolve():
                dirs.append(common)
        except OSError:
            return _GitLayout(dirs=(gitdir,), hostile=True)
    return _GitLayout(dirs=tuple(dirs))


def _gitdir_from_pointer(workspace: Path, git_file: Path) -> Path | None:
    try:
        if git_file.stat().st_size > _CONFIG_MAX_BYTES:
            return None
        text = git_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if not line.startswith("gitdir:"):
            continue
        raw = line.split(":", 1)[1].strip()
        if not raw:
            return None
        gitdir = Path(raw)
        if not gitdir.is_absolute():
            gitdir = workspace / gitdir
        return gitdir
    return None


def _common_dir(gitdir: Path) -> tuple[Path | None, bool]:
    """Return ``(common, hostile)``. A missing file means ``gitdir`` is common."""
    pointer = gitdir / "commondir"
    try:
        if not os.path.lexists(pointer):
            return None, False
        if pointer.stat().st_size > _CONFIG_MAX_BYTES:
            return None, True
        lines = [
            line.strip()
            for line in pointer.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
    except OSError:
        return None, True
    if len(lines) != 1:
        return None, True
    target = Path(lines[0])
    if not target.is_absolute():
        target = gitdir / target
    return target, False


def _git_config_is_hostile(workspace: Path) -> bool:
    layout = _git_layout(workspace)
    if layout.hostile:
        return True
    seen: set[str] = set()
    for directory in layout.dirs:
        if _exists_or_unreadable(directory / "config.worktree"):
            return True
        if _config_file_is_hostile(directory / "config", seen, 0):
            return True
    return False


def _submodules_present(workspace: Path) -> bool:
    """True when this checkout has a submodule git can enter.

    A submodule process does not inherit the parent's ``-c`` pins, so any
    sign of one asks. ``.gitmodules`` may be absent while ``modules/`` remains.
    """
    if _exists_or_unreadable(workspace / ".gitmodules"):
        return True
    layout = _git_layout(workspace)
    if layout.hostile:
        return True
    for directory in layout.dirs:
        if _exists_or_unreadable(directory / "modules"):
            return True
    return False


def _exists_or_unreadable(path: Path) -> bool:
    """True when ``path`` exists or cannot be statted. Missing is false."""
    try:
        path.stat()
    except FileNotFoundError:
        return os.path.lexists(path)
    except OSError:
        return True
    return True


def _config_file_is_hostile(path: Path, seen: set[str], depth: int) -> bool:
    if depth > 8:
        return True
    try:
        key = str(path.resolve())
    except OSError:
        return True
    if key in seen:
        return True
    seen.add(key)
    try:
        info = path.stat()
    except FileNotFoundError:
        return os.path.lexists(path)
    except OSError:
        return True
    if not stat.S_ISREG(info.st_mode) or info.st_size > _CONFIG_MAX_BYTES:
        return True
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            parsed = _config_section(line)
            if parsed is None:
                return True
            section, _subsection = parsed
            if section in {"include", "includeif"}:
                return True
            continue
        if line.endswith("\\"):
            return True
        name, _, value = line.partition("=")
        name = name.strip().lower()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if _config_key_is_hostile(section, name, value):
            return True
    return False


def _config_section(line: str) -> tuple[str, str] | None:
    match = _CONFIG_SECTION.match(line.strip())
    if match is None:
        return None
    return match.group(1).lower(), match.group(2) or ""


def _config_key_is_hostile(section: str, key: str, value: str) -> bool:
    if section in {"include", "includeif"}:
        return True
    if section == "filter" and key:
        return True
    if section == "extensions" and key == "worktreeconfig":
        return True
    if section == "core" and key == "attributesfile" and value != "":
        return True
    lowered = value.lower()
    if section == "core" and key == "fsmonitor":
        return lowered not in _GIT_FALSE_VALUES
    if section == "diff" and key in {"external", "command", "textconv"}:
        return lowered not in _GIT_FALSE_VALUES
    return False


def _attributes_assign_driver(workspace: Path) -> bool:
    layout = _git_layout(workspace)
    if layout.hostile:
        return True
    for directory in layout.dirs:
        info = directory / "info" / "attributes"
        if _exists_or_unreadable(info) and _file_assigns_driver(info):
            return True
    seen = 0
    try:
        for path in workspace.rglob(".gitattributes"):
            if ".git" in path.parts:
                continue
            seen += 1
            if seen > 500 or _file_assigns_driver(path):
                return True
    except OSError:
        return True
    return False


def _file_assigns_driver(path: Path) -> bool:
    try:
        info = path.stat()
    except FileNotFoundError:
        return os.path.lexists(path)
    except OSError:
        return True
    if not stat.S_ISREG(info.st_mode) or info.st_size > _CONFIG_MAX_BYTES:
        return True
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True
    return any(_attribute_line_assigns_driver(line) for line in text.splitlines())


def _attribute_line_assigns_driver(line: str) -> bool:
    text = line.strip()
    if not text or text.startswith("#"):
        return False
    try:
        parts = shlex.split(text, posix=True)
    except ValueError:
        return True
    for part in parts[1:]:
        for prefix in ("diff=", "filter="):
            if part.startswith(prefix) and part[len(prefix) :]:
                return True
    return False


def _head_attributes_assign_driver(workspace: Path) -> bool:
    """True when ``HEAD:.gitattributes`` assigns a diff or filter driver.

    ``--attr-source=HEAD`` reads those blobs instead of the worktree files.
    Git older than 2.40 does not take that option, so this scan stays off.
    """
    if not _git_supports_attr_source():
        return False
    listed = _run_git(workspace, ["ls-tree", "-r", "-z", "--name-only", "HEAD"])
    if listed is None:
        return True
    if listed.returncode != 0:
        err = listed.stderr.decode("utf-8", "replace").lower()
        missing = (
            "invalid object name",
            "not a git repository",
            "not a git dir",
            "ambiguous argument",
        )
        return not any(phrase in err for phrase in missing)
    if len(listed.stdout) > 5_000_000:
        return True
    names = [part.decode("utf-8", "replace") for part in listed.stdout.split(b"\0") if part]
    attrs = [name for name in names if name == ".gitattributes" or name.endswith("/.gitattributes")]
    if len(attrs) > 500:
        return True
    if not attrs:
        return False
    spec = b"".join(f"HEAD:{name}\n".encode() for name in attrs)
    blobs = _run_git(workspace, ["cat-file", "--batch"], stdin=spec)
    if blobs is None or blobs.returncode != 0 or not blobs.stdout:
        return True
    return _batch_assigns_driver(blobs.stdout)


def _run_git(
    workspace: Path,
    args: list[str],
    stdin: bytes | None = None,
) -> subprocess.CompletedProcess[bytes] | None:
    try:
        return subprocess.run(
            ["git", *_git_config_args(), *args],
            cwd=workspace,
            check=False,
            capture_output=True,
            input=stdin,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _batch_assigns_driver(payload: bytes) -> bool:
    """Parse ``git cat-file --batch`` and scan each blob for a driver."""
    pos = 0
    while pos < len(payload):
        newline = payload.find(b"\n", pos)
        if newline < 0:
            return True
        header = payload[pos:newline]
        pos = newline + 1
        if header.endswith(b" missing"):
            continue
        parts = header.split()
        if len(parts) < 3 or parts[1] != b"blob":
            return True
        try:
            size = int(parts[2])
        except ValueError:
            return True
        if size > _CONFIG_MAX_BYTES:
            return True
        body = payload[pos : pos + size]
        if len(body) != size:
            return True
        pos += size
        if payload[pos : pos + 1] == b"\n":
            pos += 1
        text = body.decode("utf-8", "replace")
        if any(_attribute_line_assigns_driver(line) for line in text.splitlines()):
            return True
    return False


def build_name_only_command(segment: str) -> str | None:
    """Return ``git <sub> --name-only`` for a content diff, log, or show.

    Summary commands (``--stat``, ``--name-only``, ``--name-status``) and
    ``git log`` without ``-p`` are not content commands. The returned command
    keeps revisions, pathspecs, and ``--cached`` so git decides the path list.
    """
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        return None
    if not tokens or tokens[0] != "git":
        return None
    index = 1
    while index < len(tokens) and tokens[index].startswith("-"):
        if tokens[index] != "--no-pager":
            return None
        index += 1
    if index >= len(tokens):
        return None
    sub = tokens[index]
    index += 1
    if sub not in {"diff", "log", "show"}:
        return None
    cached = False
    patch = False
    summary = False
    positionals: list[str] = []
    while index < len(tokens):
        arg = tokens[index]
        if arg == "--":
            positionals.append("--")
            positionals.extend(tokens[index + 1 :])
            break
        if arg in {"-p", "--patch"}:
            patch = True
        if arg in _SUMMARY_FLAGS:
            summary = True
        if arg in {"--cached", "--staged"}:
            cached = True
        if not arg.startswith("-"):
            positionals.append(arg)
        index += 1
    if sub == "log":
        content = patch
    elif summary and not patch:
        content = False
    else:
        content = True
    if not content:
        return None
    parts = [
        "git",
        *_git_config_args(),
        "--no-optional-locks",
        sub,
    ]
    if sub == "diff":
        parts.append("--ignore-submodules=all")
    parts.extend(
        [
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            "-z",
        ]
    )
    if cached:
        parts.append("--cached")
    parts.extend(positionals)
    return shlex.join(parts)


def listed_paths_are_approved(
    paths: list[str],
    approved: frozenset[str],
    workspace: Path,
) -> bool:
    """True when every path git listed is an approved non-secret file."""
    for raw in paths:
        name = raw.strip().replace("\\", "/")
        if name.startswith("./"):
            name = name[2:]
        if not name or name.endswith("/") or name in {".", ".."}:
            return False
        if _path_is_secret(name, workspace) or name not in approved:
            return False
    return True


def _normalized_path(arg: str, workspace: Path | None) -> str:
    body = _concrete_path(arg) or arg
    path = Path(body)
    if workspace is not None and path.is_absolute():
        try:
            path = path.resolve().relative_to(workspace.resolve())
        except (OSError, ValueError):
            return body
    text = path.as_posix()
    if text.startswith("./"):
        text = text[2:]
    return text


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
        # lexists is true for a dangling symlink. exists() would follow it
        # and treat the broken link as a missing revision.
        return os.path.lexists(candidate)
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
