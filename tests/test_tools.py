"""Built-in tools and the bubblewrap command line."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from praxis_prime.sandbox.bwrap import build_bwrap_argv, scrub_env
from praxis_prime.tools.builtin import execute_list_dir, execute_read_file, execute_web_fetch
from praxis_prime.tools.registry import ToolContext
from praxis_prime.tools.shell import classify_command, execute_shell


def _ctx(tmp_path, *, host_approved: bool = False) -> ToolContext:
    return ToolContext(
        cwd=str(tmp_path),
        cancelled=lambda: False,
        host_shell_approved=host_approved,
    )


def test_read_file_and_list_dir(tmp_path):
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    listed = execute_list_dir({"path": "."}, _ctx(tmp_path))
    assert "note.txt" in listed
    assert "sub/" in listed
    text = execute_read_file({"path": "note.txt"}, _ctx(tmp_path))
    assert text == "alpha\n"


def test_read_file_refuses_secrets(tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("API_KEY=super-secret-token\n", encoding="utf-8")
    try:
        execute_read_file({"path": str(secret)}, _ctx(tmp_path))
    except ValueError as exc:
        assert "secret" in str(exc)
    else:
        raise AssertionError("secret file was read")
    assert "super-secret-token" not in str(secret)


def test_web_fetch_reads_a_local_server_and_blocks_bad_urls():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"page body"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        text = execute_web_fetch({"url": f"http://127.0.0.1:{port}/hello"}, _ctx("."))
    finally:
        server.shutdown()
    assert "page body" in text
    for url in ("file:///etc/passwd", "http://169.254.169.254/latest", "ftp://example.com"):
        try:
            execute_web_fetch({"url": url}, _ctx("."))
        except ValueError:
            continue
        raise AssertionError(f"allowed {url}")


def test_unsandboxed_shell_does_not_run_without_approval(monkeypatch, tmp_path):
    calls: list[str] = []

    def host(command, cwd, cancelled, timeout=30, env=None):
        del cwd, cancelled, timeout, env
        calls.append(command)
        return "should-not-run"

    monkeypatch.setattr("praxis_prime.tools.shell.bwrap_available", lambda: False)
    monkeypatch.setattr("praxis_prime.tools.shell.run_host_shell", host)
    prepared = classify_command("echo hi", sandbox_ready=False)
    assert prepared.force_approval is True
    try:
        execute_shell({"command": "echo hi"}, _ctx(tmp_path, host_approved=False))
    except RuntimeError as exc:
        assert "not run" in str(exc)
    else:
        raise AssertionError("host shell ran")
    assert calls == []


def test_approved_host_shell_runs_and_bwrap_failure_does_not_fall_back(monkeypatch, tmp_path):
    calls: list[str] = []

    def host(command, cwd, cancelled, timeout=30, env=None):
        del cwd, cancelled, timeout, env
        calls.append(command)
        return "ok"

    monkeypatch.setattr("praxis_prime.tools.shell.bwrap_available", lambda: False)
    monkeypatch.setattr("praxis_prime.tools.shell.run_host_shell", host)
    assert execute_shell({"command": "echo hi"}, _ctx(tmp_path, host_approved=True)) == "ok"
    assert calls == ["echo hi"]

    def explode(command, cwd, cancelled, timeout=30, env=None):
        del command, cwd, cancelled, timeout, env
        raise RuntimeError("sandbox down")

    monkeypatch.setattr("praxis_prime.tools.shell.bwrap_available", lambda: True)
    monkeypatch.setattr("praxis_prime.tools.shell.run_bwrap", explode)
    monkeypatch.setattr("praxis_prime.tools.shell.run_host_shell", host)
    try:
        execute_shell({"command": "echo hi"}, _ctx(tmp_path, host_approved=True))
    except RuntimeError as exc:
        assert "sandbox down" in str(exc)
    else:
        raise AssertionError("bwrap failure was ignored")
    assert calls == ["echo hi"]


def test_bwrap_argv_drops_network_and_env_scrub_drops_keys(tmp_path):
    argv = build_bwrap_argv("echo hi", tmp_path)
    assert argv[0] == "bwrap"
    assert "--unshare-all" in argv
    assert "--clearenv" in argv
    assert "echo hi" in argv
    cleaned = scrub_env(
        {
            "PATH": "/usr/bin",
            "OPENAI_API_KEY": "sk-test",
            "PRAXIS_PRIME_MODEL": "ollama:qwen",
            "HOME": "/tmp/work",
        }
    )
    assert cleaned["PATH"] == "/usr/bin"
    assert "OPENAI_API_KEY" not in cleaned
    assert "PRAXIS_PRIME_MODEL" not in cleaned


def test_overwrite_redirect_is_destructive():
    assert classify_command("echo hi > out.txt", sandbox_ready=True).risk.value == "DESTRUCTIVE"
    assert classify_command("echo hi >> out.txt", sandbox_ready=True).risk.value == "READ"
