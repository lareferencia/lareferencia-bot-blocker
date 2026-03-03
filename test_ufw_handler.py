import ipaddress
import subprocess
from datetime import datetime, timedelta, timezone

from ufw_handler import BLOCK_TCP_PORTS, COMMENT_PREFIX, UFWManager


class RecordingUFWManager(UFWManager):
    def __init__(self):
        self.dry_run = False
        self.commands = []

    def _check_ufw_available(self):
        return True

    def _run_ufw_command(self, command_args):
        self.commands.append(command_args)
        return subprocess.CompletedProcess(args=command_args, returncode=0, stdout="", stderr="")


class CleanupRecordingUFWManager(UFWManager):
    def __init__(self, status_stdout, dry_run=False, load_ratio=0.0):
        self.dry_run = dry_run
        self.status_stdout = status_stdout
        self.load_ratio = load_ratio
        self.commands = []

    def _check_ufw_available(self):
        return True

    def _run_ufw_command(self, command_args):
        self.commands.append(command_args)
        if command_args == ["status", "numbered"]:
            return subprocess.CompletedProcess(
                args=command_args,
                returncode=0,
                stdout=self.status_stdout,
                stderr="",
            )
        return subprocess.CompletedProcess(args=command_args, returncode=0, stdout="", stderr="")

    def _system_load_ratio(self):
        return self.load_ratio


def test_block_target_restricts_rules_to_web_ports():
    manager = RecordingUFWManager()

    success = manager.block_target(ipaddress.ip_address("1.2.3.4"), 15)

    assert success is True
    assert len(manager.commands) == len(BLOCK_TCP_PORTS)

    for command_args, port in zip(manager.commands, BLOCK_TCP_PORTS):
        assert command_args[:7] == ["insert", "1", "deny", "from", "1.2.3.4/32", "to", "any"]
        assert command_args[7:11] == ["port", str(port), "proto", "tcp"]
        assert command_args[11] == "comment"
        assert command_args[12].startswith("blocked_by_stats_py_until_")


def test_clean_expired_rules_uses_cli_delete_in_descending_order():
    now_utc = datetime.now(timezone.utc)
    expired_ts = (now_utc - timedelta(minutes=90)).strftime("%Y%m%dT%H%M%SZ")
    future_ts = (now_utc + timedelta(minutes=90)).strftime("%Y%m%dT%H%M%SZ")
    status_stdout = "\n".join([
        f"[ 1] 80/tcp DENY IN 1.2.3.4/32 # {COMMENT_PREFIX}{expired_ts}",
        f"[ 2] 443/tcp DENY IN 1.2.3.4/32 # {COMMENT_PREFIX}{expired_ts}",
        f"[ 3] 80/tcp DENY IN 5.6.7.8/32 # {COMMENT_PREFIX}{future_ts}",
    ])
    manager = CleanupRecordingUFWManager(status_stdout=status_stdout)

    deleted_count = manager.clean_expired_rules()

    assert deleted_count == 2
    assert manager.commands == [
        ["status", "numbered"],
        ["--force", "delete", "2"],
        ["--force", "delete", "1"],
    ]


if __name__ == "__main__":
    test_block_target_restricts_rules_to_web_ports()
    test_clean_expired_rules_uses_cli_delete_in_descending_order()
    print("UFW handler test passed.")
