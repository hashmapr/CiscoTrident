"""``python -m trident`` entry point."""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from .cli import main as cli_main
    except ImportError as exc:  # pragma: no cover
        print(
            "TRIDENT dependencies are missing. Install them with:\n"
            "  pip install -e .\n"
            f"\nOriginal error: {exc}",
            file=sys.stderr,
        )
        return 1
    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
