"""Read a SMF Praxis home directory without changing it.

``praxis.db`` is opened with the SQLite URI ``mode=ro&immutable=1`` when no
``praxis.db-wal`` file is present. A WAL file is copied aside with the
database and that copy is opened ``mode=ro`` without ``immutable=1``, so
frames that exist only in the WAL are visible. The source directory is not
written. If an open fails, the main file is copied to a temp path and the
copy is read. Nothing under the source directory is created, replaced, or
chmodded.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import urllib.parse
from collections.abc import Iterator
from pathlib import Path

from praxis_prime.statfile import StatKind, lstat_kind

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_READ_CHUNK = 1024 * 1024


class SourceError(ValueError):
    """The Praxis home directory cannot be read."""


def quote_ident(name: str) -> str:
    """Quote a SQLite identifier. Names that are not plain words are refused."""
    if not _IDENT.fullmatch(name):
        raise SourceError("unexpected sql name")
    return '"' + name + '"'


def file_sha256(path: Path) -> str:
    """Hash a regular file. The open does not follow a final symlink."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SourceError(f"could not read {Path(path).name}") from exc
    digest = hashlib.sha256()
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SourceError(f"refusing non-file {Path(path).name}")
        while True:
            chunk = os.read(descriptor, _READ_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    except SourceError:
        raise
    except OSError as exc:
        raise SourceError(f"could not read {Path(path).name}") from exc
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def read_regular_text(path: Path, *, limit: int) -> str:
    """Read up to ``limit`` bytes from a regular file without following a symlink."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SourceError(f"could not read {Path(path).name}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SourceError(f"refusing non-file {Path(path).name}")
        blob = os.read(descriptor, limit + 1)
    except OSError as exc:
        raise SourceError(f"could not read {Path(path).name}") from exc
    finally:
        os.close(descriptor)
    if len(blob) > limit:
        raise SourceError(f"{Path(path).name} is too large")
    return blob.decode("utf-8", errors="replace")


def source_fingerprint(root: Path) -> tuple[tuple[str, int, int, int, str], ...]:
    """Bytes and mtimes under ``root``, without following symlinks.

    Each row is ``(relative path, mode, mtime_ns, size, sha256)``. Directories
    and non-files have an empty hash. A later import must leave this equal.
    """
    base = Path(root)
    rows: list[tuple[str, int, int, int, str]] = []

    def walk(directory: Path) -> None:
        info = os.lstat(directory)
        rel = "" if directory == base else directory.relative_to(base).as_posix()
        rows.append((rel, info.st_mode, info.st_mtime_ns, info.st_size, ""))
        try:
            children = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise SourceError(f"could not list {directory.name}") from exc
        for child in children:
            path = Path(child.path)
            st = os.lstat(path)
            if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                walk(path)
                continue
            digest = ""
            if stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                digest = file_sha256(path)
            rows.append(
                (path.relative_to(base).as_posix(), st.st_mode, st.st_mtime_ns, st.st_size, digest)
            )

    if lstat_kind(base) is not StatKind.DIR:
        raise SourceError("praxis source is not a directory")
    walk(base)
    return tuple(rows)


class PraxisDB:
    """A streaming, query-only connection to ``praxis.db``."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.sha256 = ""
        self._conn: sqlite3.Connection | None = None
        self._temp: Path | None = None
        self._snapshot: Path | None = None

    def __enter__(self) -> PraxisDB:
        if lstat_kind(self.path) is not StatKind.FILE:
            raise SourceError("praxis.db is not a regular file")
        self.sha256 = file_sha256(self.path)
        self._conn, self._snapshot = _open_readonly(self.path)
        if self._conn is None:
            self._temp = _copy_aside(self.path)
            self._conn, extra = _open_readonly(self._temp)
            if extra is not None:
                self._snapshot = extra
        if self._conn is None:
            raise SourceError("could not open praxis.db read-only")
        return self

    def __exit__(self, *exc: object) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        if self._snapshot is not None:
            shutil.rmtree(self._snapshot, ignore_errors=True)
            self._snapshot = None
        if self._temp is not None:
            self._temp.unlink(missing_ok=True)
            self._temp = None

    def table_names(self) -> list[str]:
        conn = self._require()
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall()
        return [str(row[0]) for row in rows]

    def columns(self, table: str) -> set[str]:
        conn = self._require()
        rows = conn.execute(f"PRAGMA table_info({quote_ident(table)})").fetchall()
        return {str(row[1]) for row in rows}

    def count(self, table: str) -> int:
        conn = self._require()
        row = conn.execute(f"SELECT COUNT(*) FROM {quote_ident(table)}").fetchone()
        return int(row[0]) if row is not None else 0

    def stream(self, table: str, columns: list[str], *, batch: int = 200) -> Iterator[sqlite3.Row]:
        """Yield rows without loading the table. ``columns`` must already exist."""
        if not columns:
            return
        conn = self._require()
        selected = ", ".join(quote_ident(name) for name in columns)
        cursor = conn.execute(f"SELECT {selected} FROM {quote_ident(table)}")
        while True:
            rows = cursor.fetchmany(batch)
            if not rows:
                return
            yield from rows

    def _require(self) -> sqlite3.Connection:
        if self._conn is None:
            raise SourceError("praxis.db is not open")
        return self._conn


def _open_readonly(path: Path) -> tuple[sqlite3.Connection | None, Path | None]:
    """Open ``path`` without writing next to it.

    A sibling ``-wal`` file is copied with the database into a temp directory
    and opened without ``immutable=1``. Opening the source that way can create
    ``-shm`` beside it. The returned directory, when set, owns that copy.
    """
    wal = Path(f"{path}-wal")
    if lstat_kind(wal) is StatKind.FILE:
        conn, directory = _open_wal_snapshot(path)
        if conn is not None:
            return conn, directory
    return _connect_readonly(path, immutable=True), None


def _connect_readonly(path: Path, *, immutable: bool) -> sqlite3.Connection | None:
    quoted = urllib.parse.quote(str(Path(path).resolve()), safe="/")
    query = "mode=ro&immutable=1" if immutable else "mode=ro"
    uri = f"file:{quoted}?{query}"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return None
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("SELECT 1")
    except sqlite3.Error:
        conn.close()
        return None
    return conn


def _open_wal_snapshot(path: Path) -> tuple[sqlite3.Connection | None, Path | None]:
    """Copy the database and its WAL, then open the copy read-only."""
    directory = Path(tempfile.mkdtemp(prefix="praxis-db-"))
    dest = directory / path.name
    try:
        shutil.copyfile(path, dest)
        shutil.copyfile(Path(f"{path}-wal"), directory / f"{path.name}-wal")
    except OSError:
        shutil.rmtree(directory, ignore_errors=True)
        return None, None
    conn = _connect_readonly(dest, immutable=False)
    if conn is None:
        shutil.rmtree(directory, ignore_errors=True)
        return None, None
    return conn, directory


def _copy_aside(path: Path) -> Path:
    """Copy ``path`` to a temp file. The source is only read."""
    handle = tempfile.NamedTemporaryFile(prefix="praxis-db-", suffix=".db", delete=False)
    handle.close()
    dest = Path(handle.name)
    try:
        shutil.copyfile(path, dest)
    except OSError as exc:
        dest.unlink(missing_ok=True)
        raise SourceError("could not copy praxis.db for reading") from exc
    return dest
