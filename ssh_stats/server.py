"""HTTP request handler for Prometheus metrics and JSON API."""

import json
import logging
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from .constants import DEFAULT_API_LIMIT, DEFAULT_REFRESH_INTERVAL
from .metrics import registry
from .parser import SSHLogParser
from .utils import parse_iso_timestamp

logger = logging.getLogger("ssh_stats")


class MetricsHandler(BaseHTTPRequestHandler):
    parser: SSHLogParser
    enable_json_api = True
    cors_allowed_origins: tuple[str, ...] = ()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query, keep_blank_values=False)
        path = parsed.path

        try:
            if path == "/metrics":
                self._serve_metrics()
            elif path.startswith("/api/") and not self.enable_json_api:
                self._serve_error(403, "JSON API is disabled")
            elif path == "/api/sessions/active":
                self._serve_json(self.parser.api_sessions_active())
            elif path == "/api/sessions/history":
                self._serve_json(
                    self.parser.api_sessions_history(
                        limit=self._get_limit(query),
                        start_time=self._get_datetime_param(query, "from"),
                        end_time=self._get_datetime_param(query, "to"),
                    )
                )
            elif path == "/api/failed":
                self._serve_json(
                    self.parser.api_failed_attempts(
                        limit=self._get_limit(query),
                        start_time=self._get_datetime_param(query, "from"),
                        end_time=self._get_datetime_param(query, "to"),
                    )
                )
            elif path == "/api/summary":
                self._serve_json(self.parser.api_summary())
            elif path == "/api/heatmap":
                self._serve_json(
                    self.parser.api_heatmap(
                        start_time=self._get_datetime_param(query, "from"),
                        end_time=self._get_datetime_param(query, "to"),
                    )
                )
            elif path == "/api/users/status":
                self._serve_json(self.parser.api_users_status())
            elif path == "/health":
                self._serve_json(self.parser.health_status())
            else:
                self._serve_error(404, "Not found")
        except ValueError as exc:
            self._serve_error(400, str(exc))

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._set_cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _get_single_query_value(
        self, query: dict[str, list[str]], name: str
    ) -> Optional[str]:
        values = query.get(name, [])
        if not values:
            return None
        return values[-1]

    def _get_limit(self, query: dict[str, list[str]]) -> int:
        raw_limit = self._get_single_query_value(query, "limit")
        if raw_limit is None:
            return DEFAULT_API_LIMIT

        try:
            limit = int(raw_limit)
        except ValueError as exc:
            raise ValueError("Query parameter 'limit' must be an integer") from exc

        if limit <= 0:
            raise ValueError("Query parameter 'limit' must be greater than zero")
        return min(limit, self.parser.max_history)

    def _get_datetime_param(
        self, query: dict[str, list[str]], name: str
    ) -> Optional[datetime]:
        raw_value = self._get_single_query_value(query, name)
        if raw_value is None:
            return None

        try:
            return parse_iso_timestamp(raw_value)
        except ValueError as exc:
            raise ValueError(
                f"Query parameter '{name}' must be an ISO-8601 timestamp"
            ) from exc

    def _serve_metrics(self) -> None:
        output = generate_latest(registry)
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPE_LATEST)
        self.send_header("Content-Length", str(len(output)))
        self.end_headers()
        self.wfile.write(output)

    def _set_cors_headers(self) -> None:
        origin = self.headers.get("Origin")
        if not self.cors_allowed_origins:
            return
        if "*" in self.cors_allowed_origins:
            self.send_header("Access-Control-Allow-Origin", "*")
            return
        if origin and origin in self.cors_allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _serve_json(self, data: Any) -> None:
        body = json.dumps(data, default=str).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _serve_error(self, status_code: int, message: str) -> None:
        body = json.dumps({"error": message}).encode()
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.debug("HTTP %s", fmt % args)


def periodic_refresh(
    parser: SSHLogParser,
    stop_event: threading.Event,
    interval: float = DEFAULT_REFRESH_INTERVAL,
) -> None:
    """Periodically refresh active session and user-online gauges from `who`."""
    while not stop_event.is_set():
        try:
            parser.refresh_runtime_state()
            parser.refresh_heatmap_gauge()
        except Exception:
            logger.exception("Error refreshing runtime state")
            parser._set_health_check(
                "who_refresh",
                "degraded",
                "Periodic runtime refresh raised an unexpected exception.",
            )
        stop_event.wait(interval)
