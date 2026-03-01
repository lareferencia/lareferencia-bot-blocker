import ipaddress
import subprocess

from ufw_handler import BLOCK_TCP_PORTS, UFWManager


class RecordingUFWManager(UFWManager):
    def __init__(self):
        self.dry_run = False
        self.commands = []

    def _check_ufw_available(self):
        return True

    def _run_ufw_command(self, command_args):
        self.commands.append(command_args)
        return subprocess.CompletedProcess(args=command_args, returncode=0, stdout="", stderr="")


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


if __name__ == "__main__":
    test_block_target_restricts_rules_to_web_ports()
    print("UFW handler test passed.")
