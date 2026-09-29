"""``praxis-primed`` daemon stub.

The process prints a message and exits. It does not open a socket, bind
127.0.0.1:18790, or read secrets.

TODO: ARCHITECTURE §3.1, §4, and §26.
"""

from __future__ import annotations

import argparse

from praxis_prime import __version__
from praxis_prime.paths import config_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="praxis-primed",
        description="Praxis Prime daemon (pre-alpha stub). Does not listen.",
    )
    parser.add_argument("--version", action="store_true", help="Print the version and exit.")
    parser.add_argument(
        "--config",
        default=None,
        help="Config file path. Recorded in the stub message. Not loaded.",
    )
    args = parser.parse_args(argv)
    if args.version:
        print(f"praxis-primed {__version__}")
        return 0
    config_path = args.config or str(config_dir() / "config.toml")
    print("praxis-primed: pre-alpha stub. The gateway is not running.")
    print("TODO: ARCHITECTURE §3.1, §4, and §26.")
    print(f"config: {config_path}")
    return 0
