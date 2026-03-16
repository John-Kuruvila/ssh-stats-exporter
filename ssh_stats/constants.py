"""Constants, defaults, and regex patterns for SSH log parsing."""

import re

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
DEFAULT_HOSTNAME_LOOKUP_TIMEOUT = 0.25
DEFAULT_HOSTNAME_CACHE_TTL = 3600.0
DEFAULT_HOSTNAME_NEGATIVE_TTL = 300.0
OVERFLOW_LABEL = "__other__"

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
