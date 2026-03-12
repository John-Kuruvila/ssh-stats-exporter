"""Data models for SSH session tracking."""

from datetime import datetime
from typing import Any, Optional


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
