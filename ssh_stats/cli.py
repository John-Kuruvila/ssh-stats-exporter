"""Command-line interface and application entry point."""

import argparse
import logging
import os
import signal
import threading
import time
from http.server import ThreadingHTTPServer
from typing import Optional

from .constants import (
    APP_VERSION,
    DEFAULT_HOSTNAME_CACHE_TTL,
    DEFAULT_HOSTNAME_LOOKUP_TIMEOUT,
    DEFAULT_HOSTNAME_NEGATIVE_TTL,
    DEFAULT_LISTEN_ADDRESS,
    DEFAULT_LOG_DIR,
    DEFAULT_LOG_FILE,
    DEFAULT_MAX_HISTORY,
    DEFAULT_METRICS_LABEL_MODE,
    DEFAULT_METRICS_MAX_AUTH_METHODS,
    DEFAULT_METRICS_MAX_SOURCE_IPS,
    DEFAULT_METRICS_MAX_USERS,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_PORT,
    DEFAULT_REFRESH_INTERVAL,
)
from .parser import SSHLogParser
from .server import MetricsHandler, periodic_refresh
from .utils import parse_env_bool, parse_env_csv

logger = logging.getLogger("ssh_stats")


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
        "--hostname-lookup-timeout",
        type=float,
        default=float(
            os.environ.get(
                "SSH_STATS_HOSTNAME_LOOKUP_TIMEOUT",
                str(DEFAULT_HOSTNAME_LOOKUP_TIMEOUT),
            )
        ),
        help=(
            "Maximum seconds to wait for a reverse-DNS lookup before falling back "
            f"to the IP (default: {DEFAULT_HOSTNAME_LOOKUP_TIMEOUT})"
        ),
    )
    parser.add_argument(
        "--hostname-cache-ttl",
        type=float,
        default=float(
            os.environ.get(
                "SSH_STATS_HOSTNAME_CACHE_TTL",
                str(DEFAULT_HOSTNAME_CACHE_TTL),
            )
        ),
        help=(
            "Seconds to cache successful reverse-DNS lookups "
            f"(default: {DEFAULT_HOSTNAME_CACHE_TTL})"
        ),
    )
    parser.add_argument(
        "--hostname-negative-ttl",
        type=float,
        default=float(
            os.environ.get(
                "SSH_STATS_HOSTNAME_NEGATIVE_TTL",
                str(DEFAULT_HOSTNAME_NEGATIVE_TTL),
            )
        ),
        help=(
            "Seconds to cache failed reverse-DNS lookups "
            f"(default: {DEFAULT_HOSTNAME_NEGATIVE_TTL})"
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
    if args.hostname_lookup_timeout < 0:
        parser.error("--hostname-lookup-timeout must be zero or greater")
    if args.hostname_cache_ttl < 0:
        parser.error("--hostname-cache-ttl must be zero or greater")
    if args.hostname_negative_ttl < 0:
        parser.error("--hostname-negative-ttl must be zero or greater")

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
        hostname_lookup_timeout=args.hostname_lookup_timeout,
        hostname_cache_ttl=args.hostname_cache_ttl,
        hostname_negative_ttl=args.hostname_negative_ttl,
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
