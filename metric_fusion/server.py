"""HTTP entry point: python -m metric_fusion.server [options]

Exposes the stateful metric-batch API and the legacy stateless entry over
HTTP. All state is in-memory; nothing is written to disk.
"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from .core import (
    BatchError,
    EventTimestampError,
    MaintenanceWindowError,
    MetricBatchService,
    RuleConfigurationError,
    process,
)

RETRACT_PREFIX = "/v1/metric_batches/"
RETRACT_SUFFIX = "/retract"
LATE_METRICS_PATH = "/v1/late_metrics"
WINDOW_RULES_PATH = "/v1/window_suppression_rules"
WINDOW_SUPPRESSIONS_PATH = "/v1/window_suppressions"
SUPPRESSION_AUDIT_PATH = "/v1/suppression_audit"
MAINTENANCE_WINDOWS_PATH = "/v1/maintenance_windows"


def _send_json(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _send_error(handler: BaseHTTPRequestHandler, status: int, code: str, message: str) -> None:
    _send_json(handler, status, {"code": code, "message": message})


def _make_handler(service: MetricBatchService, lock: threading.Lock):
    class Handler(BaseHTTPRequestHandler):
        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                return json.loads(raw.decode("utf-8") or "null")
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise BatchError(400, "invalid_request", "invalid JSON")

        def _handle_batch(self) -> None:
            try:
                with lock:
                    result = service.apply_batch(self._read_json())
            except BatchError as exc:
                _send_error(self, exc.status, exc.code, str(exc))
            except RuleConfigurationError as exc:
                _send_error(self, 400, "rule_configuration_error", str(exc))
            except MaintenanceWindowError as exc:
                _send_error(self, 400, "invalid_maintenance_window", str(exc))
            except ValueError as exc:  # legacy path validation errors
                _send_error(self, 400, "invalid_request", str(exc))
            else:
                _send_json(self, 200, result)

        def _handle_late_metrics(self) -> None:
            try:
                with lock:
                    result = service.submit_late_metrics(self._read_json())
            except BatchError as exc:
                _send_error(self, exc.status, exc.code, str(exc))
            else:
                _send_json(self, 200, result)

        def _handle_window_rules(self) -> None:
            try:
                body = self._read_json()
                rules = body.get("rules") if isinstance(body, dict) else body
                with lock:
                    service.set_window_suppression_rules(rules)
            except BatchError as exc:
                _send_error(self, exc.status, exc.code, str(exc))
            except RuleConfigurationError as exc:
                _send_error(self, 400, "rule_configuration_error", str(exc))
            else:
                _send_json(self, 200, {"status": "ok"})

        def _handle_maintenance_windows(self) -> None:
            try:
                body = self._read_json()
                windows = body.get("maintenance_windows") if isinstance(body, dict) else body
                with lock:
                    service.set_maintenance_windows(windows)
            except BatchError as exc:
                _send_error(self, exc.status, exc.code, str(exc))
            except MaintenanceWindowError as exc:
                _send_error(self, 400, "invalid_maintenance_window", str(exc))
            else:
                _send_json(self, 200, {"status": "ok"})

        def _retract_batch_id(self, path: str) -> str | None:
            """Extract a batch_id from the retract path, or None if malformed.

            The accepted shape is exactly
            ``/v1/metric_batches/{batch_id}/retract`` with a single non-empty
            path segment as the id; percent-encoding is decoded.
            """
            if not (path.startswith(RETRACT_PREFIX) and path.endswith(RETRACT_SUFFIX)):
                return None
            middle = path[len(RETRACT_PREFIX):-len(RETRACT_SUFFIX)]
            if middle == "" or "/" in middle:
                return None
            return unquote(middle)

        def _handle_retract(self, batch_id: str) -> None:
            # A request body is optional; if present it must be recognizable
            # JSON rather than an opaque payload.
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            if raw.strip():
                try:
                    parsed = json.loads(raw.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    _send_error(
                        self,
                        400,
                        "metric_batch_retract_invalid",
                        "invalid request",
                    )
                    return
                # Query-time source failover is never accepted by batch
                # operations: only query_series reads source_priority.
                if isinstance(parsed, dict) and "source_priority" in parsed:
                    _send_error(
                        self,
                        400,
                        "metric_batch_retract_invalid",
                        "invalid source_priority",
                    )
                    return
            try:
                with lock:
                    result = service.retract_batch(batch_id)
            except BatchError as exc:
                _send_error(self, exc.status, exc.code, str(exc))
            else:
                _send_json(self, 200, result)

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            path = urlsplit(self.path).path
            if path == "/v1/metric_batches":
                self._handle_batch()
            elif path == LATE_METRICS_PATH:
                self._handle_late_metrics()
            elif path == WINDOW_RULES_PATH:
                self._handle_window_rules()
            elif path == MAINTENANCE_WINDOWS_PATH:
                self._handle_maintenance_windows()
            elif path.startswith(RETRACT_PREFIX):
                batch_id = self._retract_batch_id(path)
                if batch_id is None:
                    _send_error(
                        self,
                        400,
                        "metric_batch_retract_invalid",
                        "invalid batch_id",
                    )
                else:
                    self._handle_retract(batch_id)
            elif self.path == "/process":
                try:
                    result = process(self._read_json())
                except BatchError as exc:
                    _send_error(self, exc.status, exc.code, str(exc))
                except RuleConfigurationError as exc:
                    _send_error(self, 400, "rule_configuration_error", str(exc))
                except EventTimestampError as exc:
                    _send_error(self, 400, "event_timestamp_error", str(exc))
                except MaintenanceWindowError as exc:
                    _send_error(self, 400, "invalid_maintenance_window", str(exc))
                except ValueError as exc:
                    _send_error(self, 400, "invalid_request", str(exc))
                else:
                    _send_json(self, 200, result)
            elif self.path == "/v1/query":
                try:
                    body = self._read_json()
                    if not isinstance(body, dict):
                        raise ValueError("invalid request")
                    with lock:
                        series = service.query_series(
                            name=body.get("name"),
                            labels=body.get("labels"),
                            start_ms=body.get("start_ms"),
                            end_ms=body.get("end_ms"),
                            aggregations=body.get("aggregations"),
                            source_quorum=body.get("source_quorum"),
                            source_weights=body.get("source_weights"),
                            source_priority=body.get("source_priority"),
                            gap_fill=body.get("gap_fill"),
                            downsample_overrides=body.get("downsample_overrides"),
                            source_outliers=body.get("source_outliers"),
                            source_lag_tolerance_ms=body.get("source_lag_tolerance_ms"),
                        )
                except BatchError as exc:
                    _send_error(self, exc.status, exc.code, str(exc))
                except ValueError as exc:
                    _send_error(self, 400, "invalid_request", str(exc))
                else:
                    _send_json(self, 200, {"series": series})
            else:
                _send_error(self, 404, "not_found", "not found")

        def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
            path = urlsplit(self.path).path
            if path == WINDOW_RULES_PATH:
                self._handle_window_rules()
            elif path == MAINTENANCE_WINDOWS_PATH:
                self._handle_maintenance_windows()
            else:
                _send_error(self, 404, "not_found", "not found")

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            split = urlsplit(self.path)
            if split.path == WINDOW_SUPPRESSIONS_PATH:
                params = parse_qs(split.query)
                now_raw = params.get("now_ms", [None])[0]
                try:
                    now_ms = float(now_raw) if now_raw is not None else None
                except ValueError:
                    _send_error(
                        self, 400, "event_timestamp_error", "unsortable event timestamp"
                    )
                    return
                try:
                    with lock:
                        states = service.query_suppression_states(
                            rule_id=params.get("rule_id", [None])[0],
                            source=params.get("source", [None])[0],
                            now_ms=now_ms,
                        )
                except EventTimestampError as exc:
                    _send_error(self, 400, "event_timestamp_error", str(exc))
                else:
                    _send_json(self, 200, {"suppression_states": states})
            elif self.path == "/v1/alerts":
                with lock:
                    _send_json(self, 200, service.query_alerts())
            elif split.path == SUPPRESSION_AUDIT_PATH:
                # Read-only: the audit is re-adjudicated like GET /v1/alerts
                # but changes neither alerts, series nor configuration state.
                with lock:
                    _send_json(
                        self, 200, {"suppression_audit": service.query_suppression_audit()}
                    )
            elif self.path == "/v1/series":
                with lock:
                    _send_json(self, 200, {"series": service.query_series()})
            else:
                _send_error(self, 404, "not_found", "not found")

        def log_message(self, *args) -> None:  # keep the server quiet by default
            pass

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m metric_fusion.server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--downsample-ms", type=int, default=None)
    parser.add_argument("--suppression-ms", type=int, default=0)
    args = parser.parse_args(argv)

    service = MetricBatchService(
        downsample_ms=args.downsample_ms, suppression_ms=args.suppression_ms
    )
    server = ThreadingHTTPServer(
        (args.host, args.port), _make_handler(service, threading.Lock())
    )
    print(f"serving on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
