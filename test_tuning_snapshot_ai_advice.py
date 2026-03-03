import json
import os
import subprocess
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer


def _apache_ts(dt_utc):
    return dt_utc.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _write_dummy_log(path):
    now = datetime.now(timezone.utc)
    entries = [
        f'10.0.0.1 - - [{_apache_ts(now - timedelta(minutes=20))}] "GET / HTTP/1.1" 200 123 "-" "Mozilla"',
        f'10.0.0.1 - - [{_apache_ts(now - timedelta(minutes=19))}] "GET /a HTTP/1.1" 200 123 "-" "Mozilla"',
        f'10.0.0.2 - - [{_apache_ts(now - timedelta(minutes=18))}] "GET /b HTTP/1.1" 200 123 "-" "Mozilla"',
    ]
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(entries) + "\n")


def test_ai_advice_requires_env_vars():
    try:
        import psutil  # noqa: F401
    except Exception:
        print("SKIP: psutil is not available in this environment.")
        return

    repo_root = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(repo_root, "tuning_snapshot.py")

    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "access.log")
        md_path = os.path.join(tmpdir, "snapshot.md")
        advice_path = os.path.join(tmpdir, "advice.json")
        _write_dummy_log(log_path)

        env = os.environ.copy()
        env.pop("BOT_BLOCKER_AI_ENDPOINT_URL", None)
        env.pop("BOT_BLOCKER_AI_API_KEY", None)
        env.pop("BOT_BLOCKER_AI_MODEL", None)
        result = subprocess.run(
            [
                "python3",
                script_path,
                "--file",
                log_path,
                "--time-window",
                "hour",
                "--output",
                md_path,
                "--ai-advice-output",
                advice_path,
                "--log-level",
                "ERROR",
            ],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        assert result.returncode != 0
        assert "Missing required AI environment variables" in (result.stderr + result.stdout)


def test_ai_advice_writes_artifact():
    try:
        import psutil  # noqa: F401
    except Exception:
        print("SKIP: psutil is not available in this environment.")
        return

    captured = {"auth": None, "body": None}

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            captured["auth"] = self.headers.get("Authorization")
            captured["body"] = self.rfile.read(length).decode("utf-8")
            response = {
                "id": "mock-chat-1",
                "usage": {"total_tokens": 42},
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "params_to_change": [{"name": "min-rpm-threshold", "delta": -0.5}],
                                    "candidate_ips_or_subnets": [],
                                    "reasons": ["test"],
                                    "risk_level": "low",
                                    "dry_run_plan": "run blocker.py --dry-run",
                                }
                            )
                        }
                    }
                ],
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode("utf-8"))

        def log_message(self, msg_format, *args):  # noqa: A003
            return

    repo_root = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(repo_root, "tuning_snapshot.py")
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/v1/chat/completions"
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "access.log")
            md_path = os.path.join(tmpdir, "snapshot.md")
            bundle_path = os.path.join(tmpdir, "bundle.json")
            advice_path = os.path.join(tmpdir, "advice.json")
            _write_dummy_log(log_path)

            env = os.environ.copy()
            env["BOT_BLOCKER_AI_ENDPOINT_URL"] = endpoint
            test_api_key = "test-key"
            env["BOT_BLOCKER_AI_API_KEY"] = test_api_key
            env["BOT_BLOCKER_AI_MODEL"] = "test-model"

            result = subprocess.run(
                [
                    "python3",
                    script_path,
                    "--file",
                    log_path,
                    "--time-window",
                    "hour",
                    "--output",
                    md_path,
                    "--ai-bundle-output",
                    bundle_path,
                    "--ai-advice-output",
                    advice_path,
                    "--log-level",
                    "ERROR",
                ],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            assert result.returncode == 0, result.stderr + result.stdout
            assert os.path.exists(advice_path)

            with open(advice_path, "r", encoding="utf-8") as handle:
                artifact = json.load(handle)
            assert artifact["advisory_only"] is True
            assert artifact["provider"] == "openai-compatible"
            assert artifact["response"]["parsed"]["risk_level"] == "low"
            assert captured["auth"] == f"Bearer {test_api_key}"
            request_payload = json.loads(captured["body"])
            assert "messages" in request_payload, "Expected messages in outbound payload"
            assert len(request_payload["messages"]) >= 2, "Expected system+user messages in outbound payload"
            assert request_payload["messages"][0].get("role") == "system", "Expected first message role=system"
            assert request_payload["messages"][1].get("role") == "user", "Expected second message role=user"
            user_content = request_payload["messages"][1]["content"]
            content_parts = user_content.split("\n", 1)
            assert len(content_parts) == 2, "Expected prompt header and JSON evidence in user content"
            assert content_parts[0].strip(), "Expected non-empty prompt header in user content"
            evidence_json = content_parts[1]
            evidence = json.loads(evidence_json)
            assert evidence["command_line"] == "<redacted>"
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    test_ai_advice_requires_env_vars()
    test_ai_advice_writes_artifact()
    print("Tuning snapshot AI advisory tests passed.")
