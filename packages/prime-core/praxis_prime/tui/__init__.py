"""Terminal interface for Praxis Prime.

``praxis-prime tui`` and ``pprime tui`` both enter here. The process is a
gateway client: loopback WebSocket frames plus HTTP GET with the daemon's
bearer token. It does not open ``prime.db``.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

from praxis_prime.gateway.client import Endpoint, GatewayError
from praxis_prime.tui.gateway import NOT_RUNNING, TuiGateway, resolve_profile
from praxis_prime.tui.sessions import SessionBook

Reader = Callable[[], str]
Writer = Callable[[str], None]


def run_tui(
    *,
    plain: bool = False,
    profile: str = "",
    session: str = "",
    discover: Callable[[], Endpoint | None] | None = None,
    read_line: Reader | None = None,
    write: Writer | None = None,
) -> int:
    """Attach to ``praxis-primed`` and run the full-screen UI, or ``--plain``."""
    if discover is None:
        from praxis_prime.gateway.discover import discover as default_discover

        endpoint = default_discover()
    else:
        endpoint = discover()
    if endpoint is None:
        sys.stderr.write(NOT_RUNNING)
        return 1
    try:
        gateway = TuiGateway.connect(endpoint, profile=profile)
    except (OSError, GatewayError, TimeoutError) as exc:
        print(f"praxis-prime tui: {exc}", file=sys.stderr)
        return 1
    try:
        gateway.profile = resolve_profile(gateway.http, profile)
        if plain:
            from praxis_prime.tui.plain import run_plain

            return run_plain(
                gateway=gateway,
                sessions=SessionBook(session),
                read_line=read_line or input,
                write=write or _write_stdout,
                port=endpoint.port,
            )
        from praxis_prime.tui.app import PraxisApp

        PraxisApp(gateway, profile=gateway.profile, session=session).run()
        return 0
    finally:
        gateway.close()


def _write_stdout(text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()
