"""Routines: missed runs, file watches, webhook auth, and a denied approval."""

from __future__ import annotations

import json
import os
import shutil
import socket
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tests.fakes import ScriptedProvider

from praxis_prime.approvals.queue import ApprovalQueue
from praxis_prime.audit.log import AuditLog
from praxis_prime.cli import main
from praxis_prime.clock import dump_time, load_time
from praxis_prime.gateway.server import GatewayServer
from praxis_prime.host import Host
from praxis_prime.router.types import AssistantFinal, ToolCall
from praxis_prime.runtime import build_runtime
from praxis_prime.scheduler.cron import ScheduleError
from praxis_prime.scheduler.runner import execute_routine
from praxis_prime.scheduler.service import RoutineScheduler
from praxis_prime.scheduler.store import Routine, RoutineRun, RoutineStore
from praxis_prime.scheduler.watch import (
    _DIRTY_CAP,
    _IN_IGNORED,
    _IN_Q_OVERFLOW,
    DirectoryWatcher,
    _Event,
    file_token,
)
from praxis_prime.state import StateDB
from praxis_prime.tools.registry import Risk, Tool, ToolContext, ToolRegistry


class Clock:
    def __init__(self, moment: datetime) -> None:
        self.now = moment

    def __call__(self) -> datetime:
        return self.now


def test_missed_run_skips_or_catches_up_once(tmp_path: Path):
    clock = Clock(datetime(2026, 3, 2, 16, 0, tzinfo=UTC))
    db = StateDB(tmp_path / "prime.db")
    store = RoutineStore(db, clock=clock)
    skipped = _add(store, "skip-me", missed="skip")
    caught = _add(store, "catch-me", missed="once")
    past = dump_time(clock.now - timedelta(days=3))
    db.conn.execute("UPDATE routines SET next_fire_at = ?", (past,))
    db.conn.commit()
    ran: list[str] = []
    scheduler = RoutineScheduler(store, _recorder(store, ran), clock=clock, audit=AuditLog(db))
    try:
        notes = scheduler.tick()
    finally:
        scheduler.join()
    assert f"skip {skipped.id}" in notes
    assert f"run {caught.id}" in notes
    assert ran == [caught.id]
    assert store.history(skipped.id)[0].outcome == "skipped"
    assert store.history(caught.id)[0].outcome == "ok"
    assert load_time(store.get(caught.id).next_fire_at) > clock.now
    ran.clear()
    scheduler._saw_tick = True
    assert scheduler.tick() == []
    assert ran == []
    assert db and AuditLog(db).verify()


def test_minimum_interval_and_a_live_file_change(tmp_path: Path):
    clock = Clock(datetime.now(UTC))
    db = StateDB(tmp_path / "prime.db")
    store = RoutineStore(db, clock=clock)
    with_too_soon = _add(store, "soon", missed="skip")
    moment = dump_time(clock.now - timedelta(seconds=30))
    db.conn.execute(
        "UPDATE routines SET next_fire_at = ?, last_fire_at = ? WHERE id = ?",
        (moment, moment, with_too_soon.id),
    )
    db.conn.commit()
    ran: list[str] = []
    watcher = DirectoryWatcher()
    watcher.backend = "poll"
    scheduler = RoutineScheduler(
        store,
        _recorder(store, ran),
        watcher=watcher,
        clock=clock,
    )
    path = tmp_path / "notes.md"
    path.write_text("one")
    try:
        assert scheduler.tick() == []
        store.set_paused(with_too_soon.id, True)
        watched = store.add(
            name="notes",
            prompt="Summarize the file.",
            trigger_kind="file",
            trigger_expr=str(path),
            timezone_name="UTC",
            missed_policy="once",
            watch_token=file_token(path),
        )
        assert scheduler.tick() == []
        path.write_text("two-two")
        os.utime(path, None)
        assert scheduler.tick() == [f"run {watched.id}"]
        assert ran == [watched.id]
        path.write_text("three-three-three")
        os.utime(path, None)
        assert scheduler.tick() == []
        assert store.get(watched.id).watch_token != file_token(path)
        clock.now += timedelta(minutes=2)
        assert scheduler.tick() == [f"run {watched.id}"]
        assert store.get(watched.id).watch_token == file_token(path)
    finally:
        scheduler.join()
    with_db = StateDB(tmp_path / "other.db")
    try:
        try:
            RoutineStore(with_db).add(
                name="fast",
                prompt="no",
                trigger_kind="interval",
                trigger_expr="30s",
                timezone_name="UTC",
                min_interval_seconds=30,
            )
            raise AssertionError("30s must be rejected")
        except ScheduleError as exc:
            assert "1 minute" in str(exc)
    finally:
        with_db.close()
        db.close()


def test_file_change_while_down_can_be_skipped(tmp_path: Path):
    clock = Clock(datetime.now(UTC))
    path = tmp_path / "old.md"
    path.write_text("stale")
    os.utime(path, (time.time() - 7200, time.time() - 7200))
    db = StateDB(tmp_path / "prime.db")
    store = RoutineStore(db, clock=clock)
    routine = store.add(
        name="old",
        prompt="look",
        trigger_kind="file",
        trigger_expr=str(path),
        timezone_name="UTC",
        missed_policy="skip",
        watch_token="f:0:0",
    )
    watcher = DirectoryWatcher()
    watcher.backend = "poll"
    ran: list[str] = []
    scheduler = RoutineScheduler(store, _recorder(store, ran), watcher=watcher, clock=clock)
    try:
        assert scheduler.tick() == [f"skip {routine.id}"]
        assert ran == []
        assert store.history(routine.id)[0].outcome == "skipped"
    finally:
        scheduler.join()
        db.close()


def test_dirty_set_is_bounded_and_overflow_stats(tmp_path: Path):
    path = tmp_path / "live.txt"
    path.write_text("same")
    watcher = DirectoryWatcher()
    try:
        seen = watcher.observe(path, "", startup=True)
        token = seen.token
        for index in range(_DIRTY_CAP + 5):
            watcher._mark_dirty(str(tmp_path / f"noise-{index}"))
        assert watcher._overflow is False
        assert watcher._dirty == set()

        for index in range(_DIRTY_CAP + 5):
            key = f"/tmp/cap-{index}"
            watcher._watched.add(key)
            watcher._mark_dirty(key)
        assert watcher._overflow
        assert len(watcher._dirty) <= _DIRTY_CAP

        watcher._watched.clear()
        watcher._dirty.clear()
        seen = watcher.observe(path, token, startup=False)
        assert seen.token == file_token(path)
        assert seen.token_changed is False
        assert seen.overflowed is True
        seen = watcher.observe(path, seen.token, startup=False)
        assert seen.token_changed is False
        assert seen.dirty is False
        assert seen.overflowed is False
    finally:
        watcher.close()


def test_replaced_directory_is_watched_again(tmp_path: Path):
    current = tmp_path / "current"
    theme = current / "theme"
    theme.mkdir(parents=True)
    target = theme / "live.txt"
    target.write_text("one")
    watcher = DirectoryWatcher()
    try:
        seen = watcher.observe(target, "", startup=True)
        assert seen.token_changed
        token = seen.token
        stamp = target.stat()
        shutil.rmtree(theme)
        incoming = current / "incoming"
        incoming.mkdir()
        rewritten = incoming / "live.txt"
        if watcher.backend == "inotify":
            rewritten.write_text("two")
            os.utime(rewritten, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        else:
            rewritten.write_text("two\n")
        incoming.rename(theme)
        replaced = theme / "live.txt"
        if watcher.backend == "inotify":
            assert file_token(replaced) == token
        seen = watcher.observe(replaced, token, startup=False)
        if watcher.backend == "inotify":
            assert seen.token_changed is False
            assert seen.dirty or seen.overflowed
        else:
            assert seen.token_changed
        token = seen.token
        if watcher.backend != "inotify":
            return
        assert str(theme) in watcher._armed
        assert str(current) in watcher._armed
        watcher._dirty.clear()
        replaced.write_text("three")
        watcher._drain()
        assert str(replaced) in watcher._dirty
    finally:
        watcher.close()


def test_repointed_symlink_is_noticed(tmp_path: Path):
    current = tmp_path / "current"
    current.mkdir()
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    (first / "live.txt").write_text("one")
    (second / "live.txt").write_text("two")
    link = current / "theme"
    link.symlink_to(first, target_is_directory=True)
    watcher = DirectoryWatcher()
    try:
        seen = watcher.observe(link / "live.txt", "", startup=True)
        assert seen.token_changed
        token = seen.token
        stamp = (first / "live.txt").stat()
        link.unlink()
        link.symlink_to(second, target_is_directory=True)
        if watcher.backend == "inotify":
            os.utime(second / "live.txt", ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            assert file_token(link / "live.txt") == token
        else:
            (second / "live.txt").write_text("two\n")
        seen = watcher.observe(link / "live.txt", token, startup=False)
        if watcher.backend == "inotify":
            assert seen.token_changed is False
            assert seen.dirty or seen.overflowed
        else:
            assert seen.token_changed
        if watcher.backend != "inotify":
            return
        watcher._dirty.clear()
        (second / "live.txt").write_text("three")
        watcher._drain()
        assert str(link / "live.txt") in watcher._dirty
    finally:
        watcher.close()


def test_kernel_queue_overflow_is_dirty(tmp_path: Path):
    path = tmp_path / "live.txt"
    path.write_text("same")
    watcher = DirectoryWatcher()
    try:
        watcher._watched.add(str(path))
        watcher._apply(_Event(-1, _IN_Q_OVERFLOW, None, ""))
        assert watcher._overflow
        assert watcher._dirty == set()
        seen = watcher.observe(path, "stale", startup=False)
        assert seen.token_changed
        assert seen.overflowed
        assert seen.token == file_token(path)
        assert watcher._overflow is False
        ignored = tmp_path / "theme"
        ignored.mkdir()
        watcher._armed.add(str(ignored))
        watcher._wd_path[7] = ignored
        watcher._watched.add(str(ignored / "live.txt"))
        watcher._apply(_Event(7, _IN_IGNORED, ignored, ""))
        assert str(ignored) not in watcher._armed
        assert 7 not in watcher._wd_path
        assert str(ignored / "live.txt") in watcher._dirty
    finally:
        watcher.close()


def _kernel_watch_ids(fd: int) -> set[int]:
    """Watch descriptors from ``/proc/self/fdinfo``. The kernel prints them in hex."""
    text = Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="utf-8")
    found: set[int] = set()
    for line in text.splitlines():
        if not line.startswith("inotify wd:"):
            continue
        found.add(int(line.split()[1].split(":", 1)[1], 16))
    return found


def test_watch_map_stays_exact_after_many_switches(tmp_path: Path):
    current = tmp_path / "current"
    theme = current / "theme"
    theme.mkdir(parents=True)
    target = theme / "live.txt"
    target.write_text("one")
    watcher = DirectoryWatcher()
    try:
        seen = watcher.observe(target, "", startup=True)
        assert seen.token_changed
        token = seen.token
        counts: list[int] = []
        for index in range(8):
            stamp = target.stat()
            body = target.read_text(encoding="utf-8")
            theme.rename(current / f"aside-{index}")
            theme.mkdir()
            target = theme / "live.txt"
            if watcher.backend == "inotify":
                target.write_text(body, encoding="utf-8")
                os.utime(target, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
                assert file_token(target) == token
            else:
                target.write_text(body + "x", encoding="utf-8")
            seen = watcher.observe(target, token, startup=False)
            if watcher.backend == "inotify":
                assert seen.token_changed is False
                assert seen.dirty or seen.overflowed
            else:
                assert seen.token_changed
            token = seen.token
            paths = [str(path) for path in watcher._wd_path.values()]
            assert len(paths) == len(set(paths))
            assert set(paths) == watcher._armed
            if watcher.backend == "inotify":
                assert watcher._armed == {str(theme), str(current)}
                assert watcher._fd is not None
                assert set(watcher._wd_path) == _kernel_watch_ids(watcher._fd)
            else:
                assert watcher._armed == set()
            counts.append(len(watcher._wd_path))
        assert counts == [counts[0]] * len(counts)
    finally:
        watcher.close()


def test_inotify_or_poll_sees_a_write(tmp_path: Path):
    path = tmp_path / "live.txt"
    path.write_text("before")
    watcher = DirectoryWatcher()
    try:
        seen = watcher.observe(path, "", startup=True)
        assert seen.token_changed
        path.write_text("after")
        seen = watcher.observe(path, seen.token, startup=False)
        assert seen.token_changed
        assert watcher.backend in {"inotify", "poll"}
    finally:
        watcher.close()


def test_unrelated_churn_does_not_fire_a_file_routine(tmp_path: Path):
    watched = tmp_path / "watched"
    watched.mkdir()
    path = watched / "live.txt"
    path.write_text("same")
    db, scheduler, routine, ran = _file_watch(tmp_path, path)
    try:
        assert scheduler.tick() == []
        for index in range(1030):
            (watched / f"noise-{index}").write_text("x")
        assert scheduler.tick() == []
        for index in range(1100):
            churn = tmp_path / f"churn-{index}"
            churn.write_text("x")
            churn.unlink()
        assert scheduler.tick() == []
        assert ran == []
        assert scheduler.store.get(routine.id).watch_token == file_token(path)
        assert scheduler.watcher._overflow is False
        assert not any("noise-" in key or "churn-" in key for key in scheduler.watcher._dirty)
    finally:
        scheduler.join()
        db.close()


def test_overflow_cap_does_not_fire_a_file_routine(tmp_path: Path):
    path = tmp_path / "live.txt"
    path.write_text("same")
    db, scheduler, routine, ran = _file_watch(tmp_path, path)
    try:
        assert scheduler.tick() == []
        watcher = scheduler.watcher
        for index in range(_DIRTY_CAP + 5):
            key = f"/tmp/cap-{index}"
            watcher._watched.add(key)
            watcher._mark_dirty(key)
        assert watcher._overflow is True
        assert scheduler.tick() == []
        assert ran == []
        assert scheduler.store.get(routine.id).watch_token == file_token(path)
    finally:
        scheduler.join()
        db.close()


def test_chmod_does_not_fire_a_file_routine(tmp_path: Path):
    path = tmp_path / "live.txt"
    path.write_text("same")
    os.chmod(path, 0o644)
    db, scheduler, routine, ran = _file_watch(tmp_path, path)
    try:
        assert scheduler.tick() == []
        os.chmod(path, 0o600)
        assert file_token(path) == scheduler.store.get(routine.id).watch_token
        assert scheduler.tick() == []
        assert ran == []
    finally:
        scheduler.join()
        db.close()


def test_identical_same_mtime_rewrite_does_not_fire_a_file_routine(tmp_path: Path):
    path = tmp_path / "live.txt"
    path.write_text("same")
    db, scheduler, routine, ran = _file_watch(tmp_path, path)
    try:
        assert scheduler.tick() == []
        stamp = path.stat()
        path.write_bytes(path.read_bytes())
        os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        assert file_token(path) == scheduler.store.get(routine.id).watch_token
        assert scheduler.tick() == []
        assert ran == []
    finally:
        scheduler.join()
        db.close()


def test_real_content_change_fires_a_file_routine(tmp_path: Path):
    path = tmp_path / "live.txt"
    path.write_text("same")
    db, scheduler, routine, ran = _file_watch(tmp_path, path)
    try:
        assert scheduler.tick() == []
        path.write_text("changed-body")
        assert scheduler.tick() == [f"run {routine.id}"]
        assert ran == [routine.id]
        assert scheduler.store.get(routine.id).watch_token == file_token(path)
    finally:
        scheduler.join()
        db.close()


def test_webhook_needs_the_gateway_token_and_respects_pause(tmp_path: Path):
    clock = Clock(datetime(2026, 4, 1, 12, 0, tzinfo=UTC))
    runtime = build_runtime(
        model="ollama:qwen3:32b",
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=tmp_path / "prime.db",
        cwd=tmp_path,
        providers={"ollama": ScriptedProvider([AssistantFinal(content="unused")])},
    )
    store = RoutineStore(runtime.db, clock=clock)
    routine = store.add(
        name="hook",
        prompt="Handle it.",
        trigger_kind="webhook",
        trigger_expr="webhook",
        timezone_name="UTC",
    )
    ran: list[str] = []
    scheduler = RoutineScheduler(store, _recorder(store, ran), clock=clock, audit=runtime.audit)
    queue = ApprovalQueue(ttl=1)
    host = Host(runtime, queue)
    server = GatewayServer(
        host="127.0.0.1",
        port=0,
        token="test-token",
        agent=host,
        approvals=queue,
    )
    server.routine_fire = scheduler.fire_http
    server.start()
    try:
        status, body = _http(server.bound_port, "POST", f"/v1/routines/{routine.id}/fire")
        assert status == 401
        assert body["ok"] is False
        assert ran == []
        status, _body = _http(
            server.bound_port,
            "POST",
            f"/v1/routines/{routine.id}/fire",
            token="wrong-token",
        )
        assert status == 401
        status, body = _http(
            server.bound_port,
            "POST",
            "/v1/routines/rt_deadbeef/fire",
            token="test-token",
        )
        assert status == 404
        status, body = _http(
            server.bound_port,
            "POST",
            f"/v1/routines/{routine.id}/fire",
            token="test-token",
        )
        assert status == 200
        assert body["ok"] is True
        assert ran == [routine.id]
        status, body = _http(
            server.bound_port,
            "POST",
            f"/v1/routines/{routine.id}/fire",
            token="test-token",
        )
        assert status == 429
        store.set_paused(routine.id, True)
        clock.now += timedelta(minutes=2)
        status, body = _http(
            server.bound_port,
            "POST",
            f"/v1/routines/{routine.id}/fire",
            token="test-token",
        )
        assert status == 409
        assert runtime.audit.verify()
    finally:
        scheduler.join()
        server.shutdown()
        host.close()


def test_always_ask_is_queued_and_denied_on_timeout(tmp_path: Path):
    ran: list[str] = []
    pending: list[dict[str, object]] = []

    def execute(arguments: dict[str, object], context: ToolContext) -> str:
        del arguments, context
        ran.append("sent")
        return "sent"

    registry = ToolRegistry()
    registry.register(
        Tool(
            name="send_note",
            description="Send a note.",
            parameters={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
            risk=Risk.SEND,
            execute=execute,
        )
    )
    provider = ScriptedProvider(
        [
            AssistantFinal(
                content="",
                tool_calls=(ToolCall(id="c1", name="send_note", arguments={"text": "hi"}),),
            ),
            AssistantFinal(content="could not send"),
        ]
    )
    queue = ApprovalQueue(ttl=0.05, on_pending=pending.append)
    runtime = build_runtime(
        model="ollama:qwen3:32b",
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=tmp_path / "prime.db",
        cwd=tmp_path,
        approver=queue.authorize,
        providers={"ollama": provider},
        registry=registry,
    )
    store = RoutineStore(runtime.db)
    routine = store.add(
        name="send",
        prompt="Send the note.",
        trigger_kind="webhook",
        trigger_expr="webhook",
        timezone_name="UTC",
        deliver="telegram",
    )
    delivered: list[str] = []
    try:
        run = execute_routine(
            runtime,
            routine,
            trigger="webhook",
            store=store,
            deliver=delivered.append,
        )
        assert run.outcome == "denied"
        assert ran == []
        assert pending and pending[0]["tool"] == "send_note"
        assert pending[0]["risk"] == "SEND"
        assert delivered == ["could not send"]
        assert store.history(routine.id)[0].outcome == "denied"
        kinds = [
            str(row["kind"])
            for row in runtime.db.conn.execute("SELECT kind FROM audit_events").fetchall()
        ]
        assert "routine_run" in kinds
        assert "approval" in kinds
        approval = runtime.db.conn.execute(
            "SELECT payload_json FROM audit_events WHERE kind = 'approval'"
        ).fetchone()
        assert json.loads(str(approval["payload_json"]))["actor"] == "timeout"
        assert runtime.audit.verify()
    finally:
        runtime.close()


def test_budget_stops_before_the_model_and_telegram_gets_a_redacted_summary(tmp_path: Path):
    provider = ScriptedProvider([AssistantFinal(content="token=sk-testfakevalue12345678 done")])
    runtime = build_runtime(
        model="ollama:qwen3:32b",
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=tmp_path / "prime.db",
        cwd=tmp_path,
        providers={"ollama": provider},
    )
    store = RoutineStore(runtime.db)
    capped = store.add(
        name="capped",
        prompt="Spend.",
        trigger_kind="interval",
        trigger_expr="15m",
        timezone_name="UTC",
        max_usd=0.5,
        max_iterations=20,
    )
    delivered: list[str] = []
    try:
        blocked = execute_routine(
            runtime,
            capped,
            trigger="schedule",
            store=store,
            usd_per_iteration=1.0,
            deliver=delivered.append,
        )
        assert blocked.outcome == "budget"
        assert provider.requests == []
        okay = store.add(
            name="brief",
            prompt="Say hello.",
            trigger_kind="webhook",
            trigger_expr="webhook",
            timezone_name="UTC",
            deliver="telegram",
        )
        run = execute_routine(
            runtime,
            okay,
            trigger="manual",
            store=store,
            deliver=delivered.append,
        )
        assert run.outcome == "ok"
        assert delivered
        assert "sk-" not in delivered[0]
        assert "[redacted]" in delivered[0]
        assert runtime.audit.verify()
    finally:
        runtime.close()


def test_routines_cli_lists_pauses_and_keeps_history(tmp_path: Path, capsys):
    data = tmp_path / "data"
    cfg = tmp_path / "cfg"
    data.mkdir()
    cfg.mkdir()
    base = ["--data-dir", str(data), "--config-dir", str(cfg)]
    assert (
        main(
            [
                "routines",
                "add",
                "--name",
                "morning",
                "--prompt",
                "Draft the brief.",
                "--cron",
                "0 8 * * *",
                *base,
            ]
        )
        == 0
    )
    routine_id = capsys.readouterr().out.strip()
    assert routine_id.startswith("rt_")
    assert main(["routines", "list", *base]) == 0
    assert routine_id in capsys.readouterr().out
    assert main(["routines", "pause", routine_id, *base]) == 0
    assert main(["routines", "history", routine_id, *base]) == 0
    assert "no runs" in capsys.readouterr().out
    refused = main(
        ["routines", "add", "--name", "fast", "--prompt", "no", "--every", "30s", *base]
    )
    assert refused == 1
    assert "1 minute" in capsys.readouterr().err


def _file_watch(tmp_path: Path, path: Path):
    clock = Clock(datetime(2026, 6, 1, 12, 0, tzinfo=UTC))
    db = StateDB(tmp_path / "prime.db")
    store = RoutineStore(db, clock=clock)
    routine = store.add(
        name="notes",
        prompt="Look at the file.",
        trigger_kind="file",
        trigger_expr=str(path),
        timezone_name="UTC",
        missed_policy="once",
        watch_token=file_token(path),
    )
    ran: list[str] = []
    scheduler = RoutineScheduler(store, _recorder(store, ran), clock=clock)
    return db, scheduler, routine, ran


def _add(store: RoutineStore, name: str, *, missed: str) -> Routine:
    return store.add(
        name=name,
        prompt="Check in.",
        trigger_kind="cron",
        trigger_expr="0 8 * * *",
        timezone_name="America/New_York",
        missed_policy=missed,
    )


def _recorder(store: RoutineStore, ran: list[str]):
    def runner(routine: Routine, trigger: str) -> RoutineRun:
        ran.append(routine.id)
        run = RoutineRun(
            id=f"rn_{len(ran):08d}",
            routine_id=routine.id,
            session_id="",
            started_at=dump_time(store.clock()),
            finished_at=dump_time(store.clock()),
            outcome="ok",
            summary="ok",
            trigger=trigger,
        )
        store.add_run(run)
        return run

    return runner


def _http(
    port: int,
    method: str,
    path: str,
    *,
    token: str | None = None,
) -> tuple[int, dict[str, object]]:
    headers = [
        f"{method} {path} HTTP/1.1",
        "Host: 127.0.0.1",
        "Content-Type: application/json",
        "Content-Length: 2",
        "Connection: close",
    ]
    if token is not None:
        headers.append(f"Authorization: Bearer {token}")
    raw = ("\r\n".join(headers) + "\r\n\r\n{}").encode("ascii")
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(raw)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split()[1])
    parsed = json.loads(body.decode("utf-8"))
    assert isinstance(parsed, dict)
    return status, parsed
