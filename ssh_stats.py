#!/usr/bin/env python3
"""SSH log parser that exposes Prometheus metrics and a JSON API for Grafana."""

import argparse
import gzip
import json
import logging
import os
import re
import signal
import subprocess
import threading
import time
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

logger = logging.getLogger("ssh_stats")

APP_VERSION = "1.0.0"
DEFAULT_PORT = 9122
DEFAULT_LISTEN_ADDRESS = "127.0.0.1"
DEFAULT_LOG_DIR = "/var/log"
DEFAULT_LOG_FILE = "auth.log"
DEFAULT_POLL_INTERVAL = 1.0
DEFAULT_REFRESH_INTERVAL = 30.0
DEFAULT_API_LIMIT = 200
DEFAULT_MAX_HISTORY = 5000
MAX_PENDING_ACCEPTS = 4096
MAX_INVALID_USER_CACHE = 4096
WHO_TIMEOUT_SECONDS = 5
DEFAULT_METRICS_LABEL_MODE = "bounded"
DEFAULT_METRICS_MAX_USERS = 200
DEFAULT_METRICS_MAX_SOURCE_IPS = 500
DEFAULT_METRICS_MAX_AUTH_METHODS = 32
OVERFLOW_LABEL = "__other__"


# ---------------------------------------------------------------------------
# Regex patterns for auth.log lines
# ---------------------------------------------------------------------------

# Syslog timestamp: "Mar  8 00:17:01"
SYSLOG_TS = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+")
WHO_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
WHO_MONTH_RE = re.compile(r"^[A-Z][a-z]{2}$")
WHO_DAY_RE = re.compile(r"^\d{1,2}$")
WHO_TIME_RE = re.compile(r"^\d{2}:\d{2}$")

ACCEPTED_RE = re.compile(
    r"sshd\[(\d+)\]:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)
SESSION_OPENED_RE = re.compile(
    r"sshd\[(\d+)\]:\s+pam_unix\(sshd:session\):\s+session opened for user\s+(\S+?)[\s(]"
)
SESSION_CLOSED_RE = re.compile(
    r"sshd\[(\d+)\]:\s+pam_unix\(sshd:session\):\s+session closed for user\s+(\S+)"
)
FAILED_PASSWORD_RE = re.compile(
    r"sshd\[(\d+)\]:\s+Failed password for\s+(invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)
INVALID_USER_RE = re.compile(r"sshd\[(\d+)\]:\s+Invalid user\s+(\S+)\s+from\s+(\S+)")
CONNECTION_CLOSED_PREAUTH_RE = re.compile(
    r"sshd\[(\d+)\]:\s+Connection closed by\s+(\S+)\s+port\s+(\d+)\s+\[preauth\]"
)
PORT_FORWARD_ERROR_RE = re.compile(
    r"sshd\[(\d+)\]:\s+error:\s+connect_to\s+(\S+)\s+port\s+(\d+):\s+failed"
)
MAX_AUTH_RE = re.compile(
    r"sshd\[(\d+)\]:\s+maximum authentication attempts exceeded for\s+"
    r"(invalid user\s+)?(\S+)\s+from\s+(\S+)"
)


def parse_syslog_timestamp(line: str) -> Optional[datetime]:
    """Extract a datetime from a syslog-format line. Assumes current year."""
    match = SYSLOG_TS.match(line)
    if not match:
        return None

    ts_str = match.group(1)
    now = datetime.now()
    try:
        dt = datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(year=now.year)
        if dt > now + timedelta(days=1):
            dt = dt.replace(year=now.year - 1)
        return dt
    except ValueError:
        return None


def parse_iso_timestamp(value: str) -> datetime:
    """Parse API timestamps and normalize them to naive local datetimes."""
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is not None:
        return dt.astimezone().replace(tzinfo=None)
    return dt


def parse_env_bool(name: str, default: bool = False) -> bool:
    """Interpret common truthy environment variable values."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_env_csv(name: str) -> list[str]:
    """Split a comma-separated environment variable into a clean list."""
    value = os.environ.get(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def now_utc_iso() -> str:
    """Return a compact UTC timestamp for health payloads."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Session tracker
# ---------------------------------------------------------------------------


class SessionInfo:
    __slots__ = (
        "pid",
        "user",
        "source_ip",
        "auth_method",
        "port",
        "login_time",
        "logout_time",
        "duration_seconds",
    )

    def __init__(
        self,
        pid: str,
        user: str,
        source_ip: str = "",
        auth_method: str = "",
        port: str = "",
        login_time: Optional[datetime] = None,
    ):
        self.pid = pid
        self.user = user
        self.source_ip = source_ip
        self.auth_method = auth_method
        self.port = port
        self.login_time = login_time
        self.logout_time: Optional[datetime] = None
        self.duration_seconds: Optional[float] = None

    def close(self, logout_time: datetime) -> None:
        self.logout_time = logout_time
        if self.login_time:
            self.duration_seconds = (logout_time - self.login_time).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "user": self.user,
            "source_ip": self.source_ip,
            "auth_method": self.auth_method,
            "port": self.port,
            "login_time": self.login_time.isoformat() if self.login_time else None,
            "logout_time": self.logout_time.isoformat() if self.logout_time else None,
            "duration_seconds": self.duration_seconds,
        }


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

registry = CollectorRegistry()

LOGIN_COUNTER = Counter(
    "ssh_logins_total",
    "Total successful SSH logins",
    ["user", "source_ip", "auth_method"],
    registry=registry,
)
LOGOUT_COUNTER = Counter(
    "ssh_logouts_total",
    "Total SSH logouts",
    ["user"],
    registry=registry,
)
FAILED_LOGIN_COUNTER = Counter(
    "ssh_failed_logins_total",
    "Total failed SSH login attempts",
    ["user", "source_ip"],
    registry=registry,
)
INVALID_USER_COUNTER = Counter(
    "ssh_invalid_user_attempts_total",
    "Total SSH attempts with invalid usernames",
    ["user", "source_ip"],
    registry=registry,
)
ACTIVE_SESSIONS_GAUGE = Gauge(
    "ssh_active_sessions",
    "Currently active SSH sessions",
    ["user", "source_ip"],
    registry=registry,
)
UNIQUE_USERS_GAUGE = Gauge(
    "ssh_unique_users_total",
    "Number of distinct SSH users seen",
    registry=registry,
)
SESSION_DURATION_HIST = Histogram(
    "ssh_session_duration_seconds",
    "Duration of completed SSH sessions in seconds",
    ["user"],
    buckets=(60, 300, 900, 1800, 3600, 7200, 14400, 28800, 86400, float("inf")),
    registry=registry,
)
ERROR_COUNTER = Counter(
    "ssh_errors_total",
    "Total SSH-related errors",
    ["error_type"],
    registry=registry,
)
PREAUTH_CLOSE_COUNTER = Counter(
    "ssh_preauth_connection_closed_total",
    "Connections closed before authentication completed",
    ["source_ip"],
    registry=registry,
)
LOGIN_HEATMAP_GAUGE = Gauge(
    "ssh_login_heatmap",
    "Login count by day of week and hour of day",
    ["day_of_week", "hour"],
    registry=registry,
)
USER_ONLINE_GAUGE = Gauge(
    "ssh_user_online",
    "Whether a user is currently online (1) or offline (0)",
    ["user"],
    registry=registry,
)


# ---------------------------------------------------------------------------
# Core parser / state machine
# ---------------------------------------------------------------------------


class SSHLogParser:
    DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

    def __init__(
        self,
        log_dir: str = DEFAULT_LOG_DIR,
        log_file: str = DEFAULT_LOG_FILE,
        max_history: int = DEFAULT_MAX_HISTORY,
        metrics_label_mode: str = DEFAULT_METRICS_LABEL_MODE,
        metrics_max_users: int = DEFAULT_METRICS_MAX_USERS,
        metrics_max_source_ips: int = DEFAULT_METRICS_MAX_SOURCE_IPS,
        metrics_max_auth_methods: int = DEFAULT_METRICS_MAX_AUTH_METHODS,
    ):
        self.log_dir = Path(log_dir)
        self.log_file = log_file
        self.max_history = max_history
        self.metrics_label_mode = metrics_label_mode
        self.metrics_max_users = metrics_max_users
        self.metrics_max_source_ips = metrics_max_source_ips
        self.metrics_max_auth_methods = metrics_max_auth_methods

        self._lock = threading.RLock()
        self._metrics_lock = threading.Lock()

        self.open_sessions: dict[str, SessionInfo] = {}
        self._pending_accepts: OrderedDict[str, dict[str, str]] = OrderedDict()
        self._pending_invalid_users: OrderedDict[str, dict[str, Any]] = OrderedDict()

        self.session_history: list[SessionInfo] = []
        self.unique_users: set[str] = set()
        self.failed_attempts: list[dict[str, Any]] = []
        self.login_heatmap: list[list[int]] = [[0] * 24 for _ in range(7)]
        self.login_events: list[datetime] = []
        self._active_sessions: list[dict[str, str]] = []

        self._active_session_labels: set[tuple[str, str]] = set()
        self._user_online_labels: set[str] = set()
        self._metric_users: set[str] = set()
        self._metric_source_ips: set[str] = set()
        self._metric_auth_methods: set[str] = set()
        self._health_checks: dict[str, dict[str, str]] = {}
        self._set_health_check(
            "log_access",
            "degraded",
            "Startup has not verified SSH log readability yet.",
        )
        self._set_health_check(
            "tailing",
            "degraded",
            "Live log tail has not started yet.",
        )
        self._set_health_check(
            "who_refresh",
            "degraded",
            "Active-session refresh has not completed yet.",
        )

    # -- Internal helpers --------------------------------------------------

    def _trim_list(self, items: list[Any]) -> None:
        if len(items) > self.max_history:
            del items[:-self.max_history]

    def _set_health_check(self, name: str, status: str, detail: str) -> None:
        with self._lock:
            self._health_checks[name] = {
                "status": status,
                "detail": detail,
                "updated_at": now_utc_iso(),
            }

    def health_status(self) -> dict[str, Any]:
        with self._lock:
            checks = {name: dict(value) for name, value in self._health_checks.items()}

        status = "ok" if all(check["status"] == "ok" for check in checks.values()) else "degraded"
        return {
            "status": status,
            "version": APP_VERSION,
            "checks": checks,
        }

    def _bounded_metric_label(self, seen: set[str], limit: int, value: str) -> str:
        if self.metrics_label_mode == "full":
            return value
        if value in seen:
            return value
        if len(seen) < limit:
            seen.add(value)
            return value
        return OVERFLOW_LABEL

    def _metric_user_source_labels(self, user: str, source_ip: str) -> tuple[str, str]:
        with self._metrics_lock:
            return (
                self._bounded_metric_label(self._metric_users, self.metrics_max_users, user),
                self._bounded_metric_label(
                    self._metric_source_ips,
                    self.metrics_max_source_ips,
                    source_ip,
                ),
            )

    def _metric_login_labels(
        self, user: str, source_ip: str, auth_method: str
    ) -> tuple[str, str, str]:
        with self._metrics_lock:
            return (
                self._bounded_metric_label(self._metric_users, self.metrics_max_users, user),
                self._bounded_metric_label(
                    self._metric_source_ips,
                    self.metrics_max_source_ips,
                    source_ip,
                ),
                self._bounded_metric_label(
                    self._metric_auth_methods,
                    self.metrics_max_auth_methods,
                    auth_method,
                ),
            )

    def _metric_user_label(self, user: str) -> str:
        with self._metrics_lock:
            return self._bounded_metric_label(
                self._metric_users,
                self.metrics_max_users,
                user,
            )

    def _metric_source_ip_label(self, source_ip: str) -> str:
        with self._metrics_lock:
            return self._bounded_metric_label(
                self._metric_source_ips,
                self.metrics_max_source_ips,
                source_ip,
            )

    def _record_unique_user(self, user: str) -> None:
        with self._lock:
            self.unique_users.add(user)
            unique_count = len(self.unique_users)
        UNIQUE_USERS_GAUGE.set(unique_count)

    def _remember_pending_invalid_user(
        self,
        pid: str,
        user: str,
        source_ip: str,
        event: dict[str, Any],
    ) -> None:
        with self._lock:
            self._pending_invalid_users[pid] = {
                "user": user,
                "source_ip": source_ip,
                "event": event,
            }
            self._pending_invalid_users.move_to_end(pid)
            while len(self._pending_invalid_users) > MAX_INVALID_USER_CACHE:
                self._pending_invalid_users.popitem(last=False)

    def _consume_pending_invalid_user(
        self,
        pid: str,
        user: str,
        source_ip: str,
        port: str = "",
    ) -> bool:
        with self._lock:
            existing = self._pending_invalid_users.get(pid)
            if existing and existing["user"] == user and existing["source_ip"] == source_ip:
                if port and not existing["event"].get("port"):
                    existing["event"]["port"] = port
                del self._pending_invalid_users[pid]
                return True
        return False

    def _append_failed_attempt(
        self,
        timestamp: Optional[datetime],
        user: str,
        source_ip: str,
        port: str,
        event_type: str,
    ) -> dict[str, Any]:
        event = {
            "timestamp": timestamp.isoformat() if timestamp else None,
            "user": user,
            "source_ip": source_ip,
            "port": port,
            "type": event_type,
        }
        with self._lock:
            self.failed_attempts.append(event)
            self._trim_list(self.failed_attempts)
        return event

    def _session_event_time(self, session: SessionInfo) -> Optional[datetime]:
        return session.logout_time or session.login_time

    def _filter_records_by_time(
        self,
        records: list[Any],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        timestamp_getter,
    ) -> list[Any]:
        if start_time is None and end_time is None:
            return records

        filtered: list[Any] = []
        for record in records:
            timestamp = timestamp_getter(record)
            if timestamp is None:
                continue
            if start_time is not None and timestamp < start_time:
                continue
            if end_time is not None and timestamp > end_time:
                continue
            filtered.append(record)
        return filtered

    def _filter_sessions(
        self,
        sessions: list[SessionInfo],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> list[SessionInfo]:
        return self._filter_records_by_time(
            sessions,
            start_time,
            end_time,
            self._session_event_time,
        )

    def _filter_failed_attempts(
        self,
        attempts: list[dict[str, Any]],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> list[dict[str, Any]]:
        def get_timestamp(record: dict[str, Any]) -> Optional[datetime]:
            raw_timestamp = record.get("timestamp")
            if not raw_timestamp:
                return None
            try:
                return parse_iso_timestamp(raw_timestamp)
            except ValueError:
                return None

        return self._filter_records_by_time(
            attempts,
            start_time,
            end_time,
            get_timestamp,
        )

    def _log_files_sorted(self) -> list[Path]:
        """Return rotated log files oldest-first so counters accumulate correctly."""
        files: list[Path] = []
        prefix = f"{self.log_file}."

        try:
            candidates = list(self.log_dir.iterdir())
        except OSError as exc:
            logger.warning("Cannot list %s: %s", self.log_dir, exc)
            self._set_health_check(
                "log_access",
                "degraded",
                f"Cannot list {self.log_dir}: {exc}",
            )
            return []

        for path in candidates:
            if path.name == self.log_file or path.name.startswith(prefix):
                files.append(path)

        def sort_key(path: Path) -> tuple[int]:
            name = path.name
            if name == self.log_file:
                return (0,)

            suffix = name.replace(prefix, "", 1).replace(".gz", "")
            try:
                return (int(suffix),)
            except ValueError:
                return (999,)

        files.sort(key=sort_key, reverse=True)
        return files

    def _parse_who_line(self, line: str) -> Optional[dict[str, str]]:
        parts = line.split()
        if len(parts) < 4:
            return None

        source = ""
        source_start_idx = len(parts)
        if len(parts) >= 5:
            if parts[-1].endswith(")"):
                for idx in range(4, len(parts)):
                    if parts[idx].startswith("("):
                        source = " ".join(parts[idx:]).strip("()")
                        source_start_idx = idx
                        break
            elif (
                WHO_ISO_DATE_RE.match(parts[2])
                and len(parts) >= 5
                and WHO_TIME_RE.match(parts[3])
            ):
                # `who --ips` commonly emits a bare trailing host/IP instead of `(host)`.
                source = parts[4]
                source_start_idx = 4
            elif (
                len(parts) >= 6
                and WHO_MONTH_RE.match(parts[2])
                and WHO_DAY_RE.match(parts[3])
                and WHO_TIME_RE.match(parts[4])
            ):
                source = parts[5]
                source_start_idx = 5

        login_time_parts = parts[2:source_start_idx]
        if not login_time_parts:
            return None

        return {
            "user": parts[0],
            "tty": parts[1],
            "login_time": " ".join(login_time_parts),
            "source": source,
        }

    def _is_remote_session(self, source: str) -> bool:
        return bool(source) and not source.startswith("tmux") and not re.fullmatch(
            r":\d+(?:\.\d+)?", source
        )

    def _run_who(self) -> list[dict[str, str]]:
        for command in (["who", "--ips"], ["who"]):
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=WHO_TIMEOUT_SECONDS,
                    check=False,
                )
            except (subprocess.SubprocessError, FileNotFoundError):
                continue

            if result.returncode != 0:
                logger.debug("Command failed: %s", " ".join(command))
                continue

            sessions: list[dict[str, str]] = []
            for line in result.stdout.splitlines():
                parsed = self._parse_who_line(line)
                if parsed and self._is_remote_session(parsed["source"]):
                    sessions.append(parsed)
            self._set_health_check(
                "who_refresh",
                "ok",
                f"Collected {len(sessions)} active session(s) with {' '.join(command)}.",
            )
            return sessions

        self._set_health_check(
            "who_refresh",
            "degraded",
            "Unable to refresh active sessions from the `who` command.",
        )
        return []

    # -- Parsing -----------------------------------------------------------

    def parse_line(self, line: str) -> None:
        """Parse a single auth.log line and update state + metrics."""
        if "sshd[" not in line:
            return

        timestamp = parse_syslog_timestamp(line)

        match = ACCEPTED_RE.search(line)
        if match:
            pid, auth_method, user, source_ip, port = match.groups()
            with self._lock:
                self._pending_accepts[pid] = {
                    "auth_method": auth_method,
                    "source_ip": source_ip,
                    "port": port,
                }
                self._pending_accepts.move_to_end(pid)
                while len(self._pending_accepts) > MAX_PENDING_ACCEPTS:
                    self._pending_accepts.popitem(last=False)
                if timestamp:
                    self.login_events.append(timestamp)
                    self._trim_list(self.login_events)
                    self.login_heatmap[timestamp.weekday()][timestamp.hour] += 1
            metric_user, metric_source_ip, metric_auth_method = self._metric_login_labels(
                user,
                source_ip,
                auth_method,
            )
            LOGIN_COUNTER.labels(
                user=metric_user,
                source_ip=metric_source_ip,
                auth_method=metric_auth_method,
            ).inc()
            self._record_unique_user(user)
            return

        match = SESSION_OPENED_RE.search(line)
        if match:
            pid, user = match.groups()
            with self._lock:
                accept_info = self._pending_accepts.pop(pid, {})
                self.open_sessions[pid] = SessionInfo(
                    pid=pid,
                    user=user,
                    source_ip=accept_info.get("source_ip", ""),
                    auth_method=accept_info.get("auth_method", ""),
                    port=accept_info.get("port", ""),
                    login_time=timestamp,
                )
            self._record_unique_user(user)
            return

        match = SESSION_CLOSED_RE.search(line)
        if match:
            pid, user = match.groups()
            with self._lock:
                session = self.open_sessions.pop(pid, None)
            if session:
                session.close(timestamp or datetime.now())
                if session.duration_seconds is not None and session.duration_seconds >= 0:
                    SESSION_DURATION_HIST.labels(
                        user=self._metric_user_label(session.user)
                    ).observe(
                        session.duration_seconds
                    )
                with self._lock:
                    self.session_history.append(session)
                    self._trim_list(self.session_history)
            LOGOUT_COUNTER.labels(user=self._metric_user_label(user)).inc()
            return

        match = INVALID_USER_RE.search(line)
        if match:
            pid, user, source_ip = match.groups()
            if self._consume_pending_invalid_user(pid, user, source_ip):
                return

            metric_user, metric_source_ip = self._metric_user_source_labels(user, source_ip)
            FAILED_LOGIN_COUNTER.labels(user=metric_user, source_ip=metric_source_ip).inc()
            INVALID_USER_COUNTER.labels(user=metric_user, source_ip=metric_source_ip).inc()
            event = self._append_failed_attempt(
                timestamp=timestamp,
                user=user,
                source_ip=source_ip,
                port="",
                event_type="invalid_user",
            )
            self._remember_pending_invalid_user(pid, user, source_ip, event)
            return

        match = FAILED_PASSWORD_RE.search(line)
        if match:
            pid, invalid_user_flag, user, source_ip, port = match.groups()
            event_type = "invalid_user" if invalid_user_flag else "failed_password"
            if invalid_user_flag and self._consume_pending_invalid_user(
                pid, user, source_ip, port=port
            ):
                return

            metric_user, metric_source_ip = self._metric_user_source_labels(user, source_ip)
            FAILED_LOGIN_COUNTER.labels(user=metric_user, source_ip=metric_source_ip).inc()
            if invalid_user_flag:
                INVALID_USER_COUNTER.labels(user=metric_user, source_ip=metric_source_ip).inc()
            event = self._append_failed_attempt(
                timestamp=timestamp,
                user=user,
                source_ip=source_ip,
                port=port,
                event_type=event_type,
            )
            if invalid_user_flag:
                self._remember_pending_invalid_user(pid, user, source_ip, event)
            return

        match = CONNECTION_CLOSED_PREAUTH_RE.search(line)
        if match:
            _, source_ip, _ = match.groups()
            PREAUTH_CLOSE_COUNTER.labels(
                source_ip=self._metric_source_ip_label(source_ip)
            ).inc()
            return

        match = PORT_FORWARD_ERROR_RE.search(line)
        if match:
            ERROR_COUNTER.labels(error_type="port_forward_failed").inc()
            return

        match = MAX_AUTH_RE.search(line)
        if match:
            _, invalid_user_flag, user, source_ip = match.groups()
            ERROR_COUNTER.labels(error_type="max_auth_exceeded").inc()
            metric_user, metric_source_ip = self._metric_user_source_labels(user, source_ip)
            FAILED_LOGIN_COUNTER.labels(user=metric_user, source_ip=metric_source_ip).inc()
            if invalid_user_flag:
                INVALID_USER_COUNTER.labels(user=metric_user, source_ip=metric_source_ip).inc()
            self._append_failed_attempt(
                timestamp=timestamp,
                user=user,
                source_ip=source_ip,
                port="",
                event_type="max_auth_exceeded",
            )
            return

    # -- Bulk loading ------------------------------------------------------

    def load_existing_logs(self) -> tuple[Optional[int], int]:
        """Parse rotated logs and return the current-file checkpoint."""
        files = self._log_files_sorted()
        total_lines = 0
        checkpoint_inode: Optional[int] = None
        checkpoint_offset = 0
        failed_files: list[str] = []

        for path in files:
            logger.info("Parsing %s", path)
            opener = gzip.open if path.suffix == ".gz" else open
            try:
                with opener(path, "rt", errors="replace") as handle:
                    for line in handle:
                        self.parse_line(line)
                        total_lines += 1

                    if path.name == self.log_file and path.suffix != ".gz":
                        stat_result = path.stat()
                        checkpoint_offset = stat_result.st_size
                        checkpoint_inode = stat_result.st_ino
            except (OSError, EOFError) as exc:
                logger.warning("Could not read %s: %s", path, exc)
                failed_files.append(f"{path}: {exc}")

        logger.info("Parsed %d lines from %d files", total_lines, len(files))
        if not files:
            self._set_health_check(
                "log_access",
                "degraded",
                f"No readable SSH log files matched {self.log_dir / self.log_file}.",
            )
        elif failed_files:
            self._set_health_check(
                "log_access",
                "degraded",
                failed_files[0],
            )
        else:
            self._set_health_check(
                "log_access",
                "ok",
                f"Parsed {total_lines} line(s) from {len(files)} log file(s).",
            )
        return checkpoint_inode, checkpoint_offset

    # -- Live tailing ------------------------------------------------------

    def tail_log(
        self,
        stop_event: threading.Event,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        start_inode: Optional[int] = None,
        start_offset: int = 0,
    ) -> None:
        """Tail the current auth log, resuming from a startup checkpoint."""
        log_path = self.log_dir / self.log_file
        handle: Optional[Any] = None
        inode: Optional[int] = None
        initial_open = True
        prefix_signature = b""

        def read_prefix_signature() -> bytes:
            try:
                with open(log_path, "rb") as prefix_handle:
                    return prefix_handle.read(256)
            except OSError:
                return b""

        def open_log() -> None:
            nonlocal handle, inode, initial_open, prefix_signature
            try:
                new_handle = open(log_path, errors="replace")
                new_inode = os.fstat(new_handle.fileno()).st_ino
                prefix_signature = read_prefix_signature()

                if initial_open:
                    if start_inode is None:
                        new_handle.seek(0, os.SEEK_END)
                    elif new_inode == start_inode:
                        new_handle.seek(start_offset)
                    else:
                        new_handle.seek(0)
                else:
                    new_handle.seek(0)

                handle = new_handle
                inode = new_inode
                initial_open = False
                logger.info("Opened %s (inode %s)", log_path, inode)
                self._set_health_check("tailing", "ok", f"Streaming {log_path}.")
            except OSError as exc:
                logger.warning("Cannot open %s: %s", log_path, exc)
                try:
                    new_handle.close()  # type: ignore[possibly-undefined]
                except Exception:
                    pass
                handle = None
                inode = None
                self._set_health_check(
                    "tailing",
                    "degraded",
                    f"Cannot open {log_path}: {exc}",
                )

        open_log()

        while not stop_event.is_set():
            if handle is None:
                open_log()
                stop_event.wait(poll_interval)
                continue

            try:
                stat_result = os.stat(log_path)
                current_inode = stat_result.st_ino
                current_size = stat_result.st_size
            except OSError:
                current_inode = None
                current_size = None

            if current_inode != inode:
                logger.info("Log rotated (inode changed), reopening")
                for line in handle:
                    self.parse_line(line)
                handle.close()
                open_log()
            elif handle and current_size is not None and current_size < handle.tell():
                logger.info("Log truncated in place, reopening")
                handle.close()
                open_log()
            elif handle and handle.tell() > 0 and read_prefix_signature() != prefix_signature:
                logger.info("Log content replaced in place, reopening")
                handle.close()
                open_log()

            if handle:
                for line in handle:
                    self.parse_line(line)

            stop_event.wait(poll_interval)

        if handle:
            handle.close()

    # -- Active session refresh via `who` ----------------------------------

    def refresh_runtime_state(self) -> None:
        """Refresh active-session and online-user gauges from `who`."""
        sessions = self._run_who()
        active_counts: dict[tuple[str, str], int] = defaultdict(int)

        with self._lock:
            self._active_sessions = [dict(session) for session in sessions]
            known_users = set(self.unique_users)

        with self._metrics_lock:
            active_user_labels: set[str] = set()
            for session in sessions:
                metric_user = self._bounded_metric_label(
                    self._metric_users,
                    self.metrics_max_users,
                    session["user"],
                )
                metric_source_ip = self._bounded_metric_label(
                    self._metric_source_ips,
                    self.metrics_max_source_ips,
                    session["source"],
                )
                active_counts[(metric_user, metric_source_ip)] += 1
                active_user_labels.add(metric_user)

            current_labels = set(active_counts)
            for user, source_ip in self._active_session_labels - current_labels:
                ACTIVE_SESSIONS_GAUGE.labels(user=user, source_ip=source_ip).set(0)
            for (user, source_ip), count in active_counts.items():
                ACTIVE_SESSIONS_GAUGE.labels(user=user, source_ip=source_ip).set(count)
            self._active_session_labels = current_labels

            known_user_labels = {
                self._bounded_metric_label(
                    self._metric_users,
                    self.metrics_max_users,
                    user,
                )
                for user in known_users
            }
            online_users = known_user_labels | self._user_online_labels | active_user_labels
            for user in online_users:
                USER_ONLINE_GAUGE.labels(user=user).set(1 if user in active_user_labels else 0)
            self._user_online_labels = online_users

    # -- Heatmap gauge sync ------------------------------------------------

    def refresh_heatmap_gauge(self) -> None:
        """Push the heatmap counts into the Prometheus gauge."""
        with self._lock:
            heatmap_snapshot = [row[:] for row in self.login_heatmap]

        for day_idx, day_name in enumerate(self.DAY_NAMES):
            for hour in range(24):
                LOGIN_HEATMAP_GAUGE.labels(
                    day_of_week=day_name,
                    hour=str(hour).zfill(2),
                ).set(heatmap_snapshot[day_idx][hour])

    # -- JSON API data builders --------------------------------------------

    def api_sessions_active(self) -> list[dict[str, str]]:
        with self._lock:
            return [dict(session) for session in self._active_sessions]

    def api_sessions_history(
        self,
        limit: int = DEFAULT_API_LIMIT,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            history = list(self.session_history)

        filtered = self._filter_sessions(history, start_time, end_time)
        recent = filtered[-limit:]
        return [session.to_dict() for session in reversed(recent)]

    def api_failed_attempts(
        self,
        limit: int = DEFAULT_API_LIMIT,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            failed_attempts = list(self.failed_attempts)

        filtered = self._filter_failed_attempts(failed_attempts, start_time, end_time)
        return list(reversed(filtered[-limit:]))

    def api_summary(self) -> dict[str, Any]:
        with self._lock:
            history = list(self.session_history)
            failed_attempts = list(self.failed_attempts)
            unique_users = sorted(self.unique_users)
            active_sessions = [dict(session) for session in self._active_sessions]

        login_counts: dict[str, int] = defaultdict(int)
        ip_counts: dict[str, int] = defaultdict(int)
        durations: list[float] = []

        for session in history:
            login_counts[session.user] += 1
            if session.source_ip:
                ip_counts[session.source_ip] += 1
            if session.duration_seconds is not None:
                durations.append(session.duration_seconds)

        average_duration = sum(durations) / len(durations) if durations else 0
        top_source_ips = dict(
            sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)[:20]
        )

        return {
            "total_sessions": len(history),
            "total_failed_attempts": len(failed_attempts),
            "unique_users": unique_users,
            "unique_user_count": len(unique_users),
            "logins_per_user": dict(login_counts),
            "top_source_ips": top_source_ips,
            "average_session_duration_seconds": round(average_duration, 1),
            "active_sessions": active_sessions,
        }

    def api_heatmap(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> list[dict[str, Any]]:
        """Return login heatmap as rows (one per day), columns are hours 00-23."""
        with self._lock:
            if start_time is None and end_time is None:
                heatmap_snapshot = [row[:] for row in self.login_heatmap]
            else:
                heatmap_snapshot = [row[:] for row in [[0] * 24 for _ in range(7)]]
                for login_time in self._filter_records_by_time(
                    list(self.login_events),
                    start_time,
                    end_time,
                    lambda timestamp: timestamp,
                ):
                    heatmap_snapshot[login_time.weekday()][login_time.hour] += 1

        rows: list[dict[str, Any]] = []
        for day_idx, day_name in enumerate(self.DAY_NAMES):
            row: dict[str, Any] = {"day": day_name}
            for hour in range(24):
                row[str(hour).zfill(2)] = heatmap_snapshot[day_idx][hour]
            rows.append(row)
        return rows

    def api_users_status(self) -> list[dict[str, Any]]:
        """Return each known user with their online/offline status and session count."""
        with self._lock:
            active_sessions = [dict(session) for session in self._active_sessions]
            all_users = sorted(
                self.unique_users | {session["user"] for session in active_sessions}
            )

        user_sessions: dict[str, list[dict[str, str]]] = defaultdict(list)
        for session in active_sessions:
            user_sessions[session["user"]].append(session)

        result: list[dict[str, Any]] = []
        for user in all_users:
            sessions = user_sessions.get(user, [])
            sources = sorted({session["source"] for session in sessions if session["source"]})
            result.append(
                {
                    "user": user,
                    "status": "Online" if sessions else "Offline",
                    "sessions": len(sessions),
                    "sources": ", ".join(sources),
                }
            )
        return result


# ---------------------------------------------------------------------------
# HTTP request handler (Prometheus metrics + JSON API)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Periodic active-session refresh thread
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SSH log stats exporter for Prometheus/Grafana"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {APP_VERSION}",
    )
    parser.add_argument(
        "--listen-address",
        default=os.environ.get("SSH_STATS_LISTEN_ADDRESS", DEFAULT_LISTEN_ADDRESS),
        help=(
            "IP address to bind the HTTP server to "
            f"(default: {DEFAULT_LISTEN_ADDRESS})"
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SSH_STATS_PORT", str(DEFAULT_PORT))),
        help=f"HTTP port for metrics and API (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--log-dir",
        default=os.environ.get("SSH_STATS_LOG_DIR", DEFAULT_LOG_DIR),
        help=f"Directory containing SSH auth logs (default: {DEFAULT_LOG_DIR})",
    )
    parser.add_argument(
        "--log-file",
        default=os.environ.get("SSH_STATS_LOG_FILE", DEFAULT_LOG_FILE),
        help=f"Current SSH auth log filename inside --log-dir (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("SSH_STATS_LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=float(os.environ.get("SSH_STATS_POLL_INTERVAL", str(DEFAULT_POLL_INTERVAL))),
        help=f"Log file poll interval in seconds (default: {DEFAULT_POLL_INTERVAL})",
    )
    parser.add_argument(
        "--refresh-interval",
        type=float,
        default=float(
            os.environ.get(
                "SSH_STATS_REFRESH_INTERVAL",
                str(DEFAULT_REFRESH_INTERVAL),
            )
        ),
        help=(
            "Active session and gauge refresh interval in seconds "
            f"(default: {DEFAULT_REFRESH_INTERVAL})"
        ),
    )
    parser.add_argument(
        "--max-history",
        type=int,
        default=int(os.environ.get("SSH_STATS_MAX_HISTORY", str(DEFAULT_MAX_HISTORY))),
        help=(
            "Maximum in-memory history retained for sessions, failed attempts, "
            f"and heatmap events (default: {DEFAULT_MAX_HISTORY})"
        ),
    )
    parser.add_argument(
        "--metrics-label-mode",
        choices=["bounded", "full"],
        default=os.environ.get(
            "SSH_STATS_METRICS_LABEL_MODE",
            DEFAULT_METRICS_LABEL_MODE,
        ),
        help=(
            "Use bounded metric labels to cap cardinality, or full labels to "
            "preserve every observed user/source/auth method (default: bounded)"
        ),
    )
    parser.add_argument(
        "--metrics-max-users",
        type=int,
        default=int(
            os.environ.get(
                "SSH_STATS_METRICS_MAX_USERS",
                str(DEFAULT_METRICS_MAX_USERS),
            )
        ),
        help=(
            "Maximum distinct metric user labels in bounded mode "
            f"(default: {DEFAULT_METRICS_MAX_USERS})"
        ),
    )
    parser.add_argument(
        "--metrics-max-source-ips",
        type=int,
        default=int(
            os.environ.get(
                "SSH_STATS_METRICS_MAX_SOURCE_IPS",
                str(DEFAULT_METRICS_MAX_SOURCE_IPS),
            )
        ),
        help=(
            "Maximum distinct metric source_ip labels in bounded mode "
            f"(default: {DEFAULT_METRICS_MAX_SOURCE_IPS})"
        ),
    )
    parser.add_argument(
        "--metrics-max-auth-methods",
        type=int,
        default=int(
            os.environ.get(
                "SSH_STATS_METRICS_MAX_AUTH_METHODS",
                str(DEFAULT_METRICS_MAX_AUTH_METHODS),
            )
        ),
        help=(
            "Maximum distinct metric auth_method labels in bounded mode "
            f"(default: {DEFAULT_METRICS_MAX_AUTH_METHODS})"
        ),
    )
    parser.add_argument(
        "--disable-json-api",
        action="store_true",
        default=parse_env_bool("SSH_STATS_DISABLE_JSON_API"),
        help="Disable JSON API endpoints and expose only /metrics and /health",
    )
    parser.add_argument(
        "--cors-allow-origin",
        action="append",
        dest="cors_allow_origins",
        default=parse_env_csv("SSH_STATS_CORS_ALLOW_ORIGINS"),
        help=(
            "Allowed browser origin for JSON API responses. Repeat the flag or "
            "set SSH_STATS_CORS_ALLOW_ORIGINS as a comma-separated list. "
            "Omit it for no CORS headers."
        ),
    )
    return parser


def main(argv: Optional[list[str]] = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.port <= 0 or args.port > 65535:
        parser.error("--port must be between 1 and 65535")
    if args.poll_interval <= 0:
        parser.error("--poll-interval must be greater than zero")
    if args.refresh_interval <= 0:
        parser.error("--refresh-interval must be greater than zero")
    if args.max_history <= 0:
        parser.error("--max-history must be greater than zero")
    if args.metrics_max_users <= 0:
        parser.error("--metrics-max-users must be greater than zero")
    if args.metrics_max_source_ips <= 0:
        parser.error("--metrics-max-source-ips must be greater than zero")
    if args.metrics_max_auth_methods <= 0:
        parser.error("--metrics-max-auth-methods must be greater than zero")

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    ssh_parser = SSHLogParser(
        log_dir=args.log_dir,
        log_file=args.log_file,
        max_history=args.max_history,
        metrics_label_mode=args.metrics_label_mode,
        metrics_max_users=args.metrics_max_users,
        metrics_max_source_ips=args.metrics_max_source_ips,
        metrics_max_auth_methods=args.metrics_max_auth_methods,
    )
    logger.info("Loading existing log files from %s", args.log_dir)
    start_inode, start_offset = ssh_parser.load_existing_logs()
    ssh_parser.refresh_runtime_state()
    ssh_parser.refresh_heatmap_gauge()
    summary = ssh_parser.api_summary()
    logger.info(
        "Startup complete: %d unique users, %d sessions in history",
        len(summary["unique_users"]),
        summary["total_sessions"],
    )

    stop_event = threading.Event()

    MetricsHandler.parser = ssh_parser
    MetricsHandler.enable_json_api = not args.disable_json_api
    MetricsHandler.cors_allowed_origins = tuple(dict.fromkeys(args.cors_allow_origins))
    server = ThreadingHTTPServer((args.listen_address, args.port), MetricsHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    logger.info(
        "HTTP server listening on %s:%d (json_api=%s, metrics_label_mode=%s)",
        args.listen_address,
        args.port,
        not args.disable_json_api,
        args.metrics_label_mode,
    )

    tail_thread = threading.Thread(
        target=ssh_parser.tail_log,
        args=(stop_event, args.poll_interval, start_inode, start_offset),
        daemon=True,
    )
    tail_thread.start()

    refresh_thread = threading.Thread(
        target=periodic_refresh,
        args=(ssh_parser, stop_event, args.refresh_interval),
        daemon=True,
    )
    refresh_thread.start()

    def _shutdown(signum: int, _frame: object) -> None:
        logger.info("Received signal %d, shutting down...", signum)
        stop_event.set()
        server.shutdown()

    signal.signal(signal.SIGTERM, _shutdown)

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        stop_event.set()
        server.shutdown()
    finally:
        server.server_close()
        tail_thread.join(timeout=5)
        refresh_thread.join(timeout=5)


if __name__ == "__main__":
    main()
