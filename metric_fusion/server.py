"""Minimal stdlib HTTP adapter for the stateful batch API.

Routes:

* ``POST /batches``          apply one batch (idempotent via ``batch_id``)
* ``GET  /series``           query corrected downsampling windows
* ``GET  /alerts``           query current alert suppression outcomes

Batch-domain rejections use their pinned statuses and codes:

* ``409 metric_batch_conflict``
* ``400 metric_batch_range_invalid``
* ``422 metric_window_unresolved``

The server holds one in-memory :class:`~metric_fusion.core.MetricStore`; no
extra files are written.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .core import BatchError, MetricStore


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def create_handler(store: MetricStore) -> type[BaseHTTPRequestHandler]:
    class BatchHTTPHandler(BaseHTTPRequestHandler):
        server_version = "MetricFusion/1"

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
            return

        def _read_json(self) -> Any:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                _json_response(self, 400, {"code": "invalid_request"})
                return None
            if length < 0:
                _json_response(self, 400, {"code": "invalid_request"})
                return None
            raw = self.rfile.read(length) if length else b""
            try:
                return json.loads(raw.decode("utf-8")) if raw else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                _json_response(self, 400, {"code": "invalid_json"})
                return None

        def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
            path = urlparse(self.path).path
            if path != "/batches":
                _json_response(self, 404, {"code": "not_found"})
                return
            request = self._read_json()
            if request is None:
                return
            try:
                receipt = store.apply_batch(request)
            except BatchError as exc:
                _json_response(self, exc.http_status, {"code": exc.code})
                return
            except ValueError as exc:
                _json_response(self, 400, {"code": "invalid_request", "message": str(exc)})
                return
            _json_response(self, 200, receipt)

        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            if parsed.path == "/series":
                self._handle_series(params)
            elif parsed.path == "/alerts":
                _json_response(self, 200, {"alerts": store.query_alerts()})
            else:
                _json_response(self, 404, {"code": "not_found"})

        def _handle_series(self, params: dict) -> None:
            name = params.get("name", [None])[0]
            try:
                start_ms = _parse_int_param(params.get("start_ms", [None])[0])
                end_ms = _parse_int_param(params.get("end_ms", [None])[0])
            except ValueError:
                _json_response(self, 400, {"code": "invalid_timestamp_ms"})
                return
            labels = None
            raw_labels = params.get("labels", [None])[0]
            if raw_labels is not None:
                try:
                    labels = json.loads(raw_labels)
                except json.JSONDecodeError:
                    _json_response(self, 400, {"code": "invalid_selector"})
                    return
            try:
                series = store.query_series(
                    name=name, labels=labels, start_ms=start_ms, end_ms=end_ms
                )
            except ValueError as exc:
                _json_response(self, 400, {"code": "invalid_request", "message": str(exc)})
                return
            _json_response(self, 200, {"series": series})

    return BatchHTTPHandler


def _parse_int_param(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid timestamp_ms") from exc


def build_default_store() -> MetricStore:
    """Build the process store from METRIC_FUSION_* environment variables."""
    import os

    def _int_env(key: str) -> int | None:
        raw = os.environ.get(key)
        if raw is None or raw == "":
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    downsample_ms = _int_env("METRIC_FUSION_DOWNSAMPLE_MS")
    suppression_ms = _int_env("METRIC_FUSION_SUPPRESSION_MS")
    kwargs: dict = {}
    if downsample_ms is not None:
        kwargs["downsample_ms"] = downsample_ms
    if suppression_ms is not None:
        kwargs["suppression_ms"] = suppression_ms
    return MetricStore(**kwargs)


def serve(
    host: str = "127.0.0.1",
    port: int = 8080,
    store: MetricStore | None = None,
) -> ThreadingHTTPServer:
    store = build_default_store() if store is None else store
    httpd = ThreadingHTTPServer((host, port), create_handler(store))
    httpd.metric_store = store  # type: ignore[attr-defined]
    return httpd
