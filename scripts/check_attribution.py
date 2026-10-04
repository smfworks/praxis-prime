#!/usr/bin/env python3
"""SMF Works attribution check (stdlib only).

Runs on pull_request events. It reads the PR body and labels from the event
payload ($GITHUB_EVENT_PATH), never from the API, and diffs the PR with git.

Fails when:
  * the PR body has no "Sources" section, or it is empty;
  * Sources lists something other than "none" but CREDITS.md was not changed;
  * a LICENSE / NOTICE / COPYING file is deleted, renamed away or emptied unless the PR has license-removal-ok;
  * non-example lines are removed from CREDITS.md and the PR lacks the label credits-edit-ok.
Warns (does not fail) when:
  * an added file starts a line with a copyright or SPDX header that CREDITS.md doesn't cover;
  * a link listed in Sources doesn't appear in CREDITS.md;
  * a LICENSE / NOTICE / COPYING file is removed with the license-removal-ok label.

Local use:
  python3 check_attribution.py --event event.json --repo path/to/clone
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter

OVERRIDE_LABEL = "credits-edit-ok"
EXAMPLE_MARKER = "**EXAMPLE"  # marker used by the EXAMPLE row in CREDITS.md.template
LICENSE_REMOVAL_OVERRIDE = "license-removal-ok"
LICENSE_NAME_RE = re.compile(r"^(licen[cs]e|notice|copying)([.\-_].*)?$", re.IGNORECASE)
SOURCES_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s*sources\b.*$", re.IGNORECASE)
ANY_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
URL_RE = re.compile(r"https?://[^\s<>()\[\]`'\"|]+")
# Header lines only: the keyword must start the line, after optional comment or
# quote marks (#, //, /*, *, <!--, --, ;, %, """). Prose or string literals that
# mention "copyright" mid-line are not headers.
HEADER_PREFIX = r"^[\s#/*;!%<>{}()\-\"'.]*"
SPDX_COPYRIGHT_RE = re.compile(HEADER_PREFIX + r"SPDX-FileCopyrightText:\s*(.+)", re.IGNORECASE)
COPYRIGHT_RE = re.compile(HEADER_PREFIX + r"copyright\b\s*(?:\(c\)|©)?\s*(.+)", re.IGNORECASE)
SPDX_LICENSE_RE = re.compile(HEADER_PREFIX + r"SPDX-License-Identifier:\s*([A-Za-z0-9.+\-() ]+)")
HEADER_LINES = 40          # how far into a new file we look for headers
MAX_READ = 256 * 1024      # bytes read per file


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[tuple[str, str | None]] = []

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str, path: str | None = None) -> None:
        self.warnings.append((msg, path))


# ---------------------------------------------------------------- git helpers
def git(repo: str, *args: str) -> bytes:
    res = subprocess.run(["git", "-C", repo, *args], capture_output=True)
    if res.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {res.stderr.decode(errors='replace').strip()}")
    return res.stdout


def file_at(repo: str, rev: str, path: str) -> bytes | None:
    try:
        return git(repo, "cat-file", "blob", f"{rev}:{path}")[:MAX_READ]
    except RuntimeError:
        return None


def changed_files(repo: str, base: str, head: str) -> list[tuple[str, str, str | None]]:
    """Return (status letter, path, old path for renames/copies)."""
    out = git(repo, "diff", "--name-status", "-z", "-M", base, head).decode("utf-8", "replace")
    parts = [p for p in out.split("\0") if p != ""]
    result, i = [], 0
    while i < len(parts):
        status = parts[i][0]
        if status in "RC":
            result.append((status, parts[i + 2], parts[i + 1]))
            i += 3
        else:
            result.append((status, parts[i + 1], None))
            i += 2
    return result


def is_license_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return bool(LICENSE_NAME_RE.match(name)) or path.startswith("LICENSES/")


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:8192]


# ---------------------------------------------------------------- PR body
def extract_sources(body: str) -> str | None:
    """Text under the Sources heading (comments stripped), or None if no heading."""
    lines = HTML_COMMENT_RE.sub("", body.replace("\r\n", "\n")).split("\n")
    for i, line in enumerate(lines):
        if SOURCES_HEADING_RE.match(line):
            section = []
            for nxt in lines[i + 1:]:
                if ANY_HEADING_RE.match(nxt):
                    break
                section.append(nxt)
            return "\n".join(section).strip()
    return None


def meaningful_lines(text: str) -> list[str]:
    out = []
    for line in text.split("\n"):
        line = re.sub(r"^\s*(?:[-*+]|\d+[.)])\s*(?:\[[ xX]\]\s*)?", "", line).strip()
        if line:
            out.append(line)
    return out


def is_none(lines: list[str]) -> bool:
    return len(lines) == 1 and lines[0].strip(" .`*_").lower() == "none"


# ---------------------------------------------------------------- headers
def clean_holder(raw: str) -> str:
    s = raw.strip().lstrip(":").strip()
    s = re.sub(r"(\*/|-->|#}|%>)\s*$", "", s)            # trailing comment closers
    s = re.sub(r"^(?:\(c\)|©)\s*", "", s, flags=re.IGNORECASE)
    s = re.sub(r"^\d{4}(?:\s*[-–,]\s*\d{4})*\s*,?\s*", "", s)  # years
    s = re.sub(r"<[^>]*>", "", s)                          # emails
    s = re.sub(r"all rights reserved\.?", "", s, flags=re.IGNORECASE)
    return s.strip(" .,;:*#/-").strip()


def find_headers(text: str) -> tuple[list[str], list[str]]:
    holders, licenses = [], []
    for line in text.split("\n")[:HEADER_LINES]:
        m = SPDX_COPYRIGHT_RE.search(line) or COPYRIGHT_RE.search(line)
        if m:
            holder = clean_holder(m.group(1))
            # skip prose like "copyright notice" / "copyright holders" with no year or name
            if holder and not re.match(r"^(notice|holder|law|and|the above|owner)", holder, re.I):
                holders.append(holder)
        m = SPDX_LICENSE_RE.search(line)
        if m:
            licenses.append(m.group(1).strip())
    return holders, licenses


def credited_paths(credits_text: str) -> list[str]:
    paths = []
    for token in re.findall(r"`([^`\n]+)`", credits_text):
        token = token.strip().lstrip("./").rstrip("*")
        if token:
            paths.append(token)
    return paths


def path_is_credited(path: str, credits_text: str, paths: list[str]) -> bool:
    return path in credits_text or any(path == p or path.startswith(p.rstrip("/") + "/") for p in paths)


# ---------------------------------------------------------------- main checks
def run(event: dict, repo: str, credits_file: str, own_holders: list[str], own_spdx: list[str],
        base_override: str | None = None, head_override: str | None = None) -> Report:
    rep = Report()
    pr = event.get("pull_request")
    if not pr:
        rep.error("This check only runs on pull_request events (no pull_request in the event payload).")
        return rep

    body = pr.get("body") or ""
    labels = {(lbl.get("name") or "") for lbl in pr.get("labels") or []}
    base = base_override or pr["base"]["sha"]
    head = head_override or pr["head"]["sha"]

    try:
        merge_base = git(repo, "merge-base", base, head).decode().strip()
        files = changed_files(repo, merge_base, head)
    except RuntimeError as exc:
        rep.error(f"Couldn't compute the PR diff ({exc}). Is the checkout using fetch-depth: 0?")
        return rep

    changed_paths = {p for _, p, _ in files} | {o for _, _, o in files if o}
    credits_changed = credits_file in changed_paths
    credits_bytes = file_at(repo, head, credits_file) or b""
    credits_text = credits_bytes.decode("utf-8", "replace")
    credits_lower = credits_text.lower()

    # 1. Sources section present and filled in
    sources = extract_sources(body)
    src_lines: list[str] = []
    if sources is None:
        rep.error('The PR description has no "## Sources" section. Add one, and write "none" if nothing was reused.')
    else:
        src_lines = meaningful_lines(sources)
        if not src_lines:
            rep.error('The "Sources" section is empty. List what was reused, or write "none".')

    # 2. Sources listed -> CREDITS.md must change
    if src_lines and not is_none(src_lines):
        if not credits_changed:
            rep.error(f"Sources lists reused work, but {credits_file} wasn't changed in this PR. "
                      f"Add an entry for each source.")
        for url in URL_RE.findall(sources or ""):
            url = url.rstrip(".,;:")
            if url.lower() not in credits_lower:
                rep.warn(f"Sources mentions {url}, but it isn't in {credits_file}. Do the two match?")

    # 3. License / notice files kept intact
    def license_removal(message: str) -> None:
        if LICENSE_REMOVAL_OVERRIDE in labels:
            rep.warn(f"{message} Allowed by the '{LICENSE_REMOVAL_OVERRIDE}' label for removal of bundled "
                     "third-party code and its license.")
        else:
            rep.error(message)

    for status, path, old in files:
        if status == "D" and is_license_file(path):
            license_removal(f"{path} is deleted. Please keep LICENSE, NOTICE and COPYING files.")
        elif status == "R" and old and is_license_file(old) and not is_license_file(path):
            license_removal(f"{old} was renamed to {path}, which no longer looks like a license/notice file.")
        if status != "D" and is_license_file(path):
            data = file_at(repo, head, path)
            if data is not None and not data.strip():
                license_removal(f"{path} is empty in this PR. Please keep its contents.")

    # 4. Lines removed from CREDITS.md need the override label
    if credits_changed:
        diff = git(repo, "diff", "-U0", "--no-color", merge_base, head, "--", credits_file).decode("utf-8", "replace")
        removed, added = Counter(), Counter()
        for line in diff.split("\n"):
            if line.startswith("---") or line.startswith("+++"):
                continue
            if line.startswith("-") and line[1:].strip():
                removed[line[1:].strip()] += 1
            elif line.startswith("+") and line[1:].strip():
                added[line[1:].strip()] += 1
        really_removed = removed - added   # lines that were only moved don't count
        really_removed = Counter({line: count for line, count in really_removed.items()
                                  if EXAMPLE_MARKER not in line})
        if really_removed:
            n = sum(really_removed.values())
            if OVERRIDE_LABEL in labels:
                rep.warn(f"{n} line(s) removed or changed in {credits_file}; allowed by the '{OVERRIDE_LABEL}' label.")
            else:
                rep.error(f"{n} line(s) removed or changed in {credits_file}. Existing credits should stay. "
                          f"If this is intentional, a maintainer can add the '{OVERRIDE_LABEL}' label.")

    # 5. Warn on foreign copyright / SPDX headers in added files
    own = [h.lower() for h in own_holders if h]
    own_ids = {s.lower() for s in own_spdx if s}
    cpaths = credited_paths(credits_text)
    for status, path, _ in files:
        if status not in "AC" or path == credits_file or is_license_file(path):
            continue
        data = file_at(repo, head, path)
        if not data or is_binary(data):
            continue
        if path_is_credited(path, credits_text, cpaths):
            continue
        holders, licenses = find_headers(data.decode("utf-8", "replace"))
        foreign = [h for h in holders
                   if not any(o in h.lower() for o in own) and h.lower() not in credits_lower]
        if foreign:
            rep.warn(f"{path} is a new file with a copyright header for '{foreign[0]}', "
                     f"which isn't in {credits_file}. If it came from elsewhere, please credit it.", path)
        elif licenses and not holders and not any(l.lower() in own_ids for l in licenses):
            rep.warn(f"{path} is a new file with SPDX-License-Identifier '{licenses[0]}' and isn't listed "
                     f"in {credits_file}. If it came from another project, please credit it.", path)
    return rep


def _gha_data(value: str) -> str:
    """Escape a workflow-command message so a file name can't fake an annotation."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _gha_prop(value: str) -> str:
    """Escape a workflow-command property value (e.g. file=)."""
    return _gha_data(value).replace(":", "%3A").replace(",", "%2C")


def emit(rep: Report) -> None:
    gha = os.environ.get("GITHUB_ACTIONS") == "true"
    for msg, path in rep.warnings:
        if gha:
            print(f"::warning{' file=' + _gha_prop(path) if path else ''}::{_gha_data(msg)}")
        else:
            print(f"WARNING: {msg}")
    for msg in rep.errors:
        print(f"::error::{_gha_data(msg)}" if gha else f"ERROR: {msg}")
    verdict = "failed" if rep.errors else "passed"
    print(f"Attribution check {verdict}: {len(rep.errors)} error(s), {len(rep.warnings)} warning(s).")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"### Attribution check {verdict}\n\n")
            for msg in rep.errors:
                fh.write(f"- ❌ {msg}\n")
            for msg, _ in rep.warnings:
                fh.write(f"- ⚠️ {msg}\n")
            if not rep.errors and not rep.warnings:
                fh.write("Everything looks properly credited. Thank you!\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--event", default=os.environ.get("GITHUB_EVENT_PATH"), help="event payload JSON")
    ap.add_argument("--repo", default=".", help="path to the PR checkout (full history)")
    ap.add_argument("--credits-file", default=os.environ.get("CREDITS_FILE", "CREDITS.md"))
    ap.add_argument("--base", help="override base SHA (testing)")
    ap.add_argument("--head", help="override head SHA (testing)")
    args = ap.parse_args(argv)
    if not args.event:
        print("ERROR: no event payload (set GITHUB_EVENT_PATH or pass --event).")
        return 2
    with open(args.event, encoding="utf-8") as fh:
        event = json.load(fh)
    split = lambda v: [x.strip() for x in (v or "").split(",") if x.strip()]
    rep = run(event, args.repo, args.credits_file,
              split(os.environ.get("OWN_COPYRIGHT_HOLDERS", "Michael Gannotti,SMF Works,smfworks")),
              split(os.environ.get("OWN_SPDX_IDS", "")),
              args.base, args.head)
    emit(rep)
    return 1 if rep.errors else 0


if __name__ == "__main__":
    sys.exit(main())
