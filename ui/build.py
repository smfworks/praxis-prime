"""Legacy static shell copy. The served UI is the Vite SPA in ui/dist.

Kept only so older notes that mention ``python3 ui/build.py`` fail safely.
"""

from __future__ import annotations

import sys


def main() -> None:
    print(
        "ui/build.py no longer writes ui/dist. Use npm run build for the React SPA.",
        file=sys.stderr,
    )
    raise SystemExit(1)


if __name__ == "__main__":
    main()
