"""Command-line entry point.

Legacy file mode::

    python -m metric_fusion request.json > result.json

Stateful HTTP mode (in-memory, no extra files)::

    python -m metric_fusion --serve [--host 127.0.0.1] [--port 8080]
"""

from __future__ import annotations

import json
import sys

from .core import process


def _run_file(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8") as f:
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


def _run_serve(argv: list[str]) -> int:
    host = "127.0.0.1"
    port = 8080
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--host" and index + 1 < len(argv):
            host = argv[index + 1]
            index += 2
        elif token == "--port" and index + 1 < len(argv):
            try:
                port = int(argv[index + 1])
            except ValueError:
                print("invalid port", file=sys.stderr)
                return 2
            index += 2
        else:
            print("usage: python -m metric_fusion --serve [--host H] [--port P]",
                  file=sys.stderr)
            return 2

    from .server import serve

    httpd = serve(host=host, port=port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--serve":
        return _run_serve(argv[1:])
    if len(argv) != 1:
        print("usage: python -m metric_fusion request.json", file=sys.stderr)
        print("       python -m metric_fusion --serve [--host H] [--port P]",
              file=sys.stderr)
        return 2
    return _run_file(argv[0])


if __name__ == "__main__":
    sys.exit(main())
