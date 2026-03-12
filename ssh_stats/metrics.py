"""Prometheus metric definitions for SSH stats."""

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
)

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
