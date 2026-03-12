"""Utility functions for timestamp parsing and environment variable handling."""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from .constants import SYSLOG_TS


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
