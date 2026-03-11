import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from ssh_stats import (
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
    MetricsHandler,
    SSHLogParser,
    build_arg_parser,
    generate_latest,
    parse_iso_timestamp,
    registry,
)


class SSHStatsParserTests(unittest.TestCase):
    def setUp(self) -> None:
        for metric in (
            LOGIN_COUNTER,
            LOGOUT_COUNTER,
            FAILED_LOGIN_COUNTER,
            INVALID_USER_COUNTER,
            ACTIVE_SESSIONS_GAUGE,
            SESSION_DURATION_HIST,
            ERROR_COUNTER,
            PREAUTH_CLOSE_COUNTER,
            LOGIN_HEATMAP_GAUGE,
            USER_ONLINE_GAUGE,
        ):
            metric._metrics.clear()
        UNIQUE_USERS_GAUGE.set(0)
        MetricsHandler.enable_json_api = True
        MetricsHandler.cors_allowed_origins = ()

    def test_keyboard_interactive_auth_method_is_parsed(self) -> None:
        parser = SSHLogParser()

        parser.parse_line(
            "Mar  8 00:17:01 host sshd[123]: Accepted keyboard-interactive/pam "
            "for alice from 10.0.0.1 port 2222 ssh2"
        )
        parser.parse_line(
            "Mar  8 00:17:02 host sshd[123]: pam_unix(sshd:session): session opened "
            "for user alice(uid=1000) by (uid=0)"
        )

        self.assertEqual(parser.open_sessions["123"].auth_method, "keyboard-interactive/pam")

    def test_invalid_user_is_deduplicated_and_port_is_preserved(self) -> None:
        parser = SSHLogParser()

        parser.parse_line(
            "Mar  8 00:17:01 host sshd[123]: Invalid user ghost from 10.0.0.1"
        )
        parser.parse_line(
            "Mar  8 00:17:01 host sshd[123]: Failed password for invalid user ghost "
            "from 10.0.0.1 port 2222 ssh2"
        )

        failed_attempts = parser.api_failed_attempts(limit=10)
        self.assertEqual(len(failed_attempts), 1)
        self.assertEqual(failed_attempts[0]["type"], "invalid_user")
        self.assertEqual(failed_attempts[0]["port"], "2222")

    def test_invalid_user_is_deduplicated_when_lines_arrive_in_reverse_order(self) -> None:
        parser = SSHLogParser()

        parser.parse_line(
            "Mar  8 00:17:01 host sshd[123]: Failed password for invalid user ghost "
            "from 10.0.0.1 port 2222 ssh2"
        )
        parser.parse_line(
            "Mar  8 00:17:01 host sshd[123]: Invalid user ghost from 10.0.0.1"
        )

        failed_attempts = parser.api_failed_attempts(limit=10)
        self.assertEqual(len(failed_attempts), 1)
        self.assertEqual(failed_attempts[0]["type"], "invalid_user")
        self.assertEqual(failed_attempts[0]["port"], "2222")

    def test_failed_attempt_filters_respect_time_range_and_limit(self) -> None:
        parser = SSHLogParser()
        parser.failed_attempts = [
            {
                "timestamp": "2026-03-01T00:00:00",
                "user": "old",
                "source_ip": "10.0.0.1",
                "port": "22",
                "type": "failed_password",
            },
            {
                "timestamp": "2026-03-05T12:00:00",
                "user": "mid",
                "source_ip": "10.0.0.2",
                "port": "22",
                "type": "invalid_user",
            },
            {
                "timestamp": "2026-03-09T12:00:00",
                "user": "new",
                "source_ip": "10.0.0.3",
                "port": "22",
                "type": "max_auth_exceeded",
            },
        ]

        filtered = parser.api_failed_attempts(
            limit=1,
            start_time=parse_iso_timestamp("2026-03-04T00:00:00"),
            end_time=parse_iso_timestamp("2026-03-10T00:00:00"),
        )

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["user"], "new")

    def test_max_auth_invalid_user_increments_invalid_user_metric(self) -> None:
        parser = SSHLogParser()

        parser.parse_line(
            "Mar  8 00:17:01 host sshd[123]: maximum authentication attempts exceeded "
            "for invalid user ghost from 10.0.0.1 port 2222 ssh2 [preauth]"
        )

        metrics_output = generate_latest(registry).decode()
        self.assertIn(
            'ssh_invalid_user_attempts_total{source_ip="10.0.0.1",user="ghost"} 1.0',
            metrics_output,
        )

    def test_bounded_metric_labels_collapse_overflow_values(self) -> None:
        parser = SSHLogParser(metrics_max_users=1, metrics_max_source_ips=1)

        parser.parse_line(
            "Mar  8 00:17:01 host sshd[101]: Failed password for alice "
            "from 10.0.0.1 port 2222 ssh2"
        )
        parser.parse_line(
            "Mar  8 00:17:02 host sshd[102]: Failed password for bob "
            "from 10.0.0.2 port 2223 ssh2"
        )

        metrics_output = generate_latest(registry).decode()
        self.assertIn(
            'ssh_failed_logins_total{source_ip="10.0.0.1",user="alice"} 1.0',
            metrics_output,
        )
        self.assertIn(
            'ssh_failed_logins_total{source_ip="__other__",user="__other__"} 1.0',
            metrics_output,
        )

    @patch("ssh_stats.subprocess.run")
    def test_refresh_runtime_state_tracks_remote_sessions_only(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["who"],
            returncode=0,
            stdout=(
                "alice pts/0 2026-03-11 12:00 192.168.1.20\n"
                "bob pts/1 2026-03-11 12:05 :0\n"
                "carol pts/2 2026-03-11 12:10\n"
            ),
            stderr="",
        )
        parser = SSHLogParser()
        parser.unique_users.update({"alice", "bob", "carol"})

        parser.refresh_runtime_state()

        self.assertEqual(
            parser.api_sessions_active(),
            [
                {
                    "user": "alice",
                    "tty": "pts/0",
                    "login_time": "2026-03-11 12:00",
                    "source": "192.168.1.20",
                }
            ],
        )
        self.assertEqual(parser.api_users_status()[0]["status"], "Online")
        self.assertEqual(parser.api_users_status()[1]["status"], "Offline")

    @patch("ssh_stats.subprocess.run")
    def test_users_status_includes_active_users_not_yet_seen_in_logs(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["who"],
            returncode=0,
            stdout="dave pts/3 2026-03-11 12:15 (192.168.1.30)\n",
            stderr="",
        )
        parser = SSHLogParser()
        parser.unique_users.update({"alice"})

        parser.refresh_runtime_state()

        self.assertEqual(
            parser.api_users_status(),
            [
                {
                    "user": "alice",
                    "status": "Offline",
                    "sessions": 0,
                    "sources": "",
                },
                {
                    "user": "dave",
                    "status": "Online",
                    "sessions": 1,
                    "sources": "192.168.1.30",
                },
            ],
        )
        metrics_output = generate_latest(registry).decode()
        self.assertIn('ssh_user_online{user="dave"} 1.0', metrics_output)

    @patch("ssh_stats.subprocess.run")
    def test_refresh_runtime_state_falls_back_to_plain_who_output(self, mock_run) -> None:
        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=["who", "--ips"],
                returncode=1,
                stdout="",
                stderr="unsupported option",
            ),
            subprocess.CompletedProcess(
                args=["who"],
                returncode=0,
                stdout=(
                    "alice pts/0 Mar 11 12:00 (192.168.1.20)\n"
                    "bob pts/1 Mar 11 12:05 (:0)\n"
                ),
                stderr="",
            ),
        ]
        parser = SSHLogParser()

        parser.refresh_runtime_state()

        self.assertEqual(
            parser.api_sessions_active(),
            [
                {
                    "user": "alice",
                    "tty": "pts/0",
                    "login_time": "Mar 11 12:00",
                    "source": "192.168.1.20",
                }
            ],
        )

    @patch("ssh_stats.subprocess.run")
    def test_plain_who_without_source_is_not_misclassified_as_remote(self, mock_run) -> None:
        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=["who", "--ips"],
                returncode=1,
                stdout="",
                stderr="unsupported option",
            ),
            subprocess.CompletedProcess(
                args=["who"],
                returncode=0,
                stdout="alice pts/0 Mar 11 12:00\n",
                stderr="",
            ),
        ]
        parser = SSHLogParser()

        parser.refresh_runtime_state()

        self.assertEqual(parser.api_sessions_active(), [])

    @patch("ssh_stats.subprocess.run")
    def test_ipv6_mapped_remote_source_is_not_filtered_out(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["who"],
            returncode=0,
            stdout="alice pts/0 2026-03-11 12:00 ::ffff:192.168.1.20\n",
            stderr="",
        )
        parser = SSHLogParser()

        parser.refresh_runtime_state()

        self.assertEqual(
            parser.api_sessions_active(),
            [
                {
                    "user": "alice",
                    "tty": "pts/0",
                    "login_time": "2026-03-11 12:00",
                    "source": "::ffff:192.168.1.20",
                }
            ],
        )

    def test_heatmap_respects_time_range(self) -> None:
        parser = SSHLogParser()
        parser.login_events = [
            parse_iso_timestamp("2026-03-01T10:00:00"),
            parse_iso_timestamp("2026-03-05T12:00:00"),
        ]

        rows = parser.api_heatmap(
            start_time=parse_iso_timestamp("2026-03-04T00:00:00"),
            end_time=parse_iso_timestamp("2026-03-06T00:00:00"),
        )

        self.assertEqual(next(row for row in rows if row["day"] == "Thu")["12"], 1)
        self.assertEqual(sum(row["10"] for row in rows), 0)

    def test_tail_log_handles_copytruncate_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"
            log_path.write_text(
                "Mar  8 00:17:01 host sshd[101]: Failed password for root "
                "from 10.0.0.1 port 2222 ssh2\n",
                encoding="utf-8",
            )

            parser = SSHLogParser(log_dir=temp_dir)
            start_inode, start_offset = parser.load_existing_logs()

            stop_event = threading.Event()
            thread = threading.Thread(
                target=parser.tail_log,
                args=(stop_event, 0.05, start_inode, start_offset),
                daemon=True,
            )
            thread.start()
            time.sleep(0.1)

            log_path.write_text("", encoding="utf-8")
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    "Mar  8 00:17:02 host sshd[102]: Failed password for admin "
                    "from 10.0.0.2 port 2223 ssh2\n"
                )

            deadline = time.time() + 2
            while time.time() < deadline:
                attempts = parser.api_failed_attempts(limit=10)
                if any(attempt["source_ip"] == "10.0.0.2" for attempt in attempts):
                    break
                time.sleep(0.05)

            stop_event.set()
            thread.join(timeout=1)

            failed_attempts = parser.api_failed_attempts(limit=10)
            self.assertEqual(len(failed_attempts), 2)
            self.assertEqual(failed_attempts[0]["source_ip"], "10.0.0.2")

    def test_tail_log_resumes_from_startup_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"
            log_path.write_text(
                "Mar  8 00:17:01 host sshd[101]: Failed password for root "
                "from 10.0.0.1 port 2222 ssh2\n",
                encoding="utf-8",
            )

            parser = SSHLogParser(log_dir=temp_dir)
            start_inode, start_offset = parser.load_existing_logs()

            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    "Mar  8 00:17:02 host sshd[102]: Failed password for root "
                    "from 10.0.0.2 port 2223 ssh2\n"
                )

            stop_event = threading.Event()
            thread = threading.Thread(
                target=parser.tail_log,
                args=(stop_event, 0.05, start_inode, start_offset),
                daemon=True,
            )
            thread.start()

            deadline = time.time() + 2
            while time.time() < deadline:
                if len(parser.api_failed_attempts(limit=10)) == 2:
                    break
                time.sleep(0.05)

            stop_event.set()
            thread.join(timeout=1)

            failed_attempts = parser.api_failed_attempts(limit=10)
            self.assertEqual(len(failed_attempts), 2)
            self.assertEqual(failed_attempts[0]["source_ip"], "10.0.0.2")

    def test_health_is_degraded_when_no_logs_are_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parser = SSHLogParser(log_dir=temp_dir)

            parser.load_existing_logs()

            health = parser.health_status()
            self.assertEqual(health["status"], "degraded")
            self.assertEqual(health["checks"]["log_access"]["status"], "degraded")


class SSHStatsHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        for metric in (
            LOGIN_COUNTER,
            LOGOUT_COUNTER,
            FAILED_LOGIN_COUNTER,
            INVALID_USER_COUNTER,
            ACTIVE_SESSIONS_GAUGE,
            SESSION_DURATION_HIST,
            ERROR_COUNTER,
            PREAUTH_CLOSE_COUNTER,
            LOGIN_HEATMAP_GAUGE,
            USER_ONLINE_GAUGE,
        ):
            metric._metrics.clear()
        UNIQUE_USERS_GAUGE.set(0)

    def _start_server(
        self,
        parser: SSHLogParser,
        *,
        enable_json_api: bool = True,
        cors_allowed_origins: tuple[str, ...] = (),
    ) -> str:
        handler = type("TestMetricsHandler", (MetricsHandler,), {})
        handler.parser = parser
        handler.enable_json_api = enable_json_api
        handler.cors_allowed_origins = cors_allowed_origins

        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 1)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}"

    def test_health_endpoint_reports_runtime_checks(self) -> None:
        parser = SSHLogParser()
        parser._set_health_check("log_access", "ok", "ready")
        parser._set_health_check("tailing", "ok", "ready")
        parser._set_health_check("who_refresh", "ok", "ready")
        base_url = self._start_server(parser)

        with urlopen(f"{base_url}/health") as response:
            body = json.load(response)

        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["checks"]["log_access"]["status"], "ok")

    def test_json_api_can_be_disabled(self) -> None:
        parser = SSHLogParser()
        base_url = self._start_server(parser, enable_json_api=False)

        with self.assertRaises(HTTPError) as exc_info:
            urlopen(f"{base_url}/api/summary")

        self.assertEqual(exc_info.exception.code, 403)
        self.assertEqual(
            json.loads(exc_info.exception.read().decode())["error"],
            "JSON API is disabled",
        )

    def test_cors_allowlist_echoes_matching_origin(self) -> None:
        parser = SSHLogParser()
        base_url = self._start_server(
            parser,
            cors_allowed_origins=("https://grafana.example.com",),
        )
        request = Request(
            f"{base_url}/health",
            headers={"Origin": "https://grafana.example.com"},
        )

        with urlopen(request) as response:
            response.read()
            allow_origin = response.headers.get("Access-Control-Allow-Origin")

        self.assertEqual(allow_origin, "https://grafana.example.com")

    def test_options_request_returns_cors_headers(self) -> None:
        parser = SSHLogParser()
        base_url = self._start_server(parser, cors_allowed_origins=("*",))
        request = Request(f"{base_url}/api/summary", method="OPTIONS")

        with urlopen(request) as response:
            response.read()
            allow_origin = response.headers.get("Access-Control-Allow-Origin")
            allow_methods = response.headers.get("Access-Control-Allow-Methods")

        self.assertEqual(allow_origin, "*")
        self.assertEqual(allow_methods, "GET, OPTIONS")


class SSHStatsConfigTests(unittest.TestCase):
    @patch.dict(
        os.environ,
        {
            "SSH_STATS_LISTEN_ADDRESS": "192.0.2.10",
            "SSH_STATS_DISABLE_JSON_API": "true",
            "SSH_STATS_CORS_ALLOW_ORIGINS": "https://grafana.example.com,https://ops.example.com",
        },
        clear=False,
    )
    def test_build_arg_parser_uses_release_friendly_env_settings(self) -> None:
        args = build_arg_parser().parse_args([])

        self.assertEqual(args.listen_address, "192.0.2.10")
        self.assertTrue(args.disable_json_api)
        self.assertEqual(
            args.cors_allow_origins,
            ["https://grafana.example.com", "https://ops.example.com"],
        )


if __name__ == "__main__":
    unittest.main()
