"""命令行入口：python -m metric_fusion request.json"""

import json
import sys

from .core import process


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m metric_fusion request.json", file=sys.stderr)
        return 2

    try:
        with open(argv[0], "r", encoding="utf-8") as f:
            request = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        if isinstance(exc, json.JSONDecodeError):
            print("invalid JSON", file=sys.stderr)
        else:
            print(str(exc), file=sys.stderr)
        return 2

    try:
        result = process(request)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
