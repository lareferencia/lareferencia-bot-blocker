import json
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone


def _apache_ts(dt_utc):
    return dt_utc.strftime("%d/%b/%Y:%H:%M:%S +0000")


def test_tuning_snapshot_ai_bundle_output():
    try:
        import psutil  # noqa: F401
    except Exception:
        print("SKIP: psutil is not available in this environment.")
        return

    repo_root = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(repo_root, "tuning_snapshot.py")

    now = datetime.now(timezone.utc)
    entries = [
        f'10.0.0.1 - - [{_apache_ts(now - timedelta(minutes=20))}] "GET / HTTP/1.1" 200 123 "-" "Mozilla"',
        f'10.0.0.1 - - [{_apache_ts(now - timedelta(minutes=19))}] "GET /a HTTP/1.1" 200 123 "-" "Mozilla"',
        f'10.0.0.2 - - [{_apache_ts(now - timedelta(minutes=18))}] "GET /b HTTP/1.1" 200 123 "-" "Mozilla"',
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "access.log")
        md_path = os.path.join(tmpdir, "snapshot.md")
        json_path = os.path.join(tmpdir, "snapshot-ai.json")

        with open(log_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(entries) + "\n")

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
                json_path,
                "--log-level",
                "ERROR",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0, result.stderr or result.stdout
        assert os.path.exists(md_path)
        assert os.path.exists(json_path)

        with open(json_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)

        assert "window" in payload
        assert "near_miss" in payload
        assert "execution_log_summary" in payload
        assert "ufw_status_summary" in payload
        assert payload["window"]["total_requests"] >= 1


if __name__ == "__main__":
    test_tuning_snapshot_ai_bundle_output()
    print("Tuning snapshot AI bundle test passed.")
