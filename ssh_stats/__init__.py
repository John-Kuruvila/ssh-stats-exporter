"""SSH log parser that exposes Prometheus metrics and a JSON API for Grafana."""

from .cli import build_arg_parser, main
from .metrics import (
    ACTIVE_SESSIONS_GAUGE,
    ERROR_COUNTER,
    FAILED_LOGIN_COUNTER,
    INVALID_USER_COUNTER,
    LOGIN_COUNTER,
    LOGIN_HEATMAP_GAUGE,
    LOGOUT_COUNTER,
    PREAUTH_CLOSE_COUNTER,
    SESSION_DURATION_HIST,
    UNIQUE_USERS_GAUGE,
    USER_ONLINE_GAUGE,
    registry,
)
from .models import SessionInfo
from .parser import SSHLogParser
from .server import MetricsHandler, periodic_refresh
from .utils import parse_iso_timestamp

__all__ = [
    "ACTIVE_SESSIONS_GAUGE",
    "ERROR_COUNTER",
    "FAILED_LOGIN_COUNTER",
    "INVALID_USER_COUNTER",
    "LOGIN_COUNTER",
    "LOGIN_HEATMAP_GAUGE",
    "LOGOUT_COUNTER",
    "MetricsHandler",
    "PREAUTH_CLOSE_COUNTER",
    "SESSION_DURATION_HIST",
    "SSHLogParser",
    "SessionInfo",
    "UNIQUE_USERS_GAUGE",
    "USER_ONLINE_GAUGE",
    "build_arg_parser",
    "main",
    "parse_iso_timestamp",
    "periodic_refresh",
    "registry",
]
