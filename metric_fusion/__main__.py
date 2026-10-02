"""Command-line entry point: python -m metric_fusion request.json"""

from __future__ import annotations

import json
import sys

from .core import process


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m metric_fusion request.json", file=sys.stderr)
        return 2

    try:
        with open(argv[0], "r", encoding="utf-8") as f:
            request = json.load(f)
    except json.JSONDecodeError:
        print("invalid JSON", file=sys.stderr)
        return 2
    except (OSError, UnicodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        result = process(request)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    sys.stdout.write(json.dumps(result, ensure_ascii=False))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
