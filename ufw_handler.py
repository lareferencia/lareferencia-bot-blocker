#!/usr/bin/env python3
"""
Module for handling interactions with the UFW firewall using ISO 8601 comments.
"""
import re
import subprocess
import sys
import os
from datetime import datetime, timezone, timedelta
import ipaddress
import logging
from collections import defaultdict

# Logger for this module
logger = logging.getLogger('botstats.ufw')

# Comment prefix for rules added by this script
COMMENT_PREFIX = "blocked_by_stats_py_until_"
BLOCK_TCP_PORTS = (80, 443)

# Cleanup heuristic constants (intentionally fixed, no CLI flags).
CLEANUP_GRACE_MINUTES = 45
CLEANUP_MAX_DELETE_PER_RUN = 24
CLEANUP_PER_FAMILY_DELETE_CAP = 2
CLEANUP_HIGH_LOAD_RATIO = 1.5
CLEANUP_HIGH_LOAD_MAX_DELETE = 8

class UFWManager:
    """
    Handles UFW operations: blocking targets with expiration comments and cleaning expired rules.
    """

    def __init__(self, dry_run=False):
        """Initializes the UFW handler."""
        self.dry_run = dry_run
        self._check_ufw_available()

    def _check_ufw_available(self):
        """Verifies UFW availability."""
        try:
            result = subprocess.run(["which", "ufw"], check=False, capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                 # logger.warning("UFW command not found. Blocking/cleanup will fail.") # <-- COMMENTED OUT
                 return False
            return True
        except Exception:
            logger.warning("Could not verify UFW availability. Some operations might fail.")
            return False

    def _run_ufw_command(self, command_args):
        """Executes a UFW command."""
        full_command_list = ['sudo', 'ufw'] + command_args
        command_str = ' '.join(full_command_list)

        if self.dry_run:
            log_prefix = "[DRY RUN]"
            logger.info(f"{log_prefix} Would execute: {command_str}")
            return subprocess.CompletedProcess(args=full_command_list, returncode=0, stdout=f"{log_prefix} Command not executed.\n", stderr="")

        logger.debug(f"Executing: {command_str}")
        try:
            result = subprocess.run(full_command_list, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                logger.warning(f"Command '{command_str}' failed with code {result.returncode}")
                logger.warning(f"Stderr: {result.stderr.strip()}")
                logger.warning(f"Stdout: {result.stdout.strip()}")
            else:
                logger.debug(f"Command '{command_str}' executed successfully.")
            return result
        except FileNotFoundError:
            logger.error(f"Error: 'sudo' or 'ufw' command not found.")
            return subprocess.CompletedProcess(args=full_command_list, returncode=127, stdout="", stderr="Command not found")
        except Exception as e:
            logger.error(f"Error executing UFW command '{command_str}': {e}")
            return subprocess.CompletedProcess(args=full_command_list, returncode=1, stdout="", stderr=str(e))

    @staticmethod
    def _extract_target_network(line):
        """Extracts blocked source token from a UFW status line and parses it as network."""
        line_no_comment = line.split('#', 1)[0]
        patterns = [
            r"\bDENY\b(?:\s+IN)?\s+([0-9A-Fa-f:\./]+)\b",
            r"\bfrom\s+([0-9A-Fa-f:\./]+)\b",
        ]
        for pattern in patterns:
            match = re.search(pattern, line_no_comment, re.IGNORECASE)
            if not match:
                continue
            token = match.group(1).strip()
            try:
                return ipaddress.ip_network(token, strict=False)
            except ValueError:
                continue
        return None

    @staticmethod
    def _network_family_key(network_obj):
        """Groups networks into cleanup families to avoid bulk release from one origin."""
        if network_obj is None:
            return None

        try:
            if isinstance(network_obj, ipaddress.IPv4Network):
                if network_obj.prefixlen >= 16:
                    return str(network_obj.supernet(new_prefix=16))
                return str(network_obj)

            if isinstance(network_obj, ipaddress.IPv6Network):
                if network_obj.prefixlen >= 48:
                    return str(network_obj.supernet(new_prefix=48))
                return str(network_obj)
        except ValueError:
            return str(network_obj)

        return str(network_obj)

    @staticmethod
    def _system_load_ratio():
        """Returns normalized 1-minute load ratio (load1 / cpu_count), or None if unavailable."""
        try:
            load_1m = os.getloadavg()[0]
            cpu_count = os.cpu_count() or 1
            if cpu_count <= 0:
                return None
            return float(load_1m) / float(cpu_count)
        except Exception:
            return None

    def _remove_expired_rules_from_file(self, rules_file, rules_to_remove):
        """
        Remove expired rule blocks from a UFW rules file.

        Each block consists of a ``### tuple ###`` metadata line followed by
        one or more iptables command lines (``-A`` / ``-I``).  A block is
        removed when any of its lines contains both the target IP/subnet string
        and the associated comment string from *rules_to_remove*.

        Args:
            rules_file (str): Path to a UFW rules file (e.g. /etc/ufw/user.rules).
            rules_to_remove (set): Set of (ip_str, comment_str) pairs to match.

        Returns:
            int: Number of rule blocks removed.
        """
        try:
            with open(rules_file, 'r') as fh:
                lines = fh.readlines()
        except FileNotFoundError:
            logger.debug("Rules file not found, skipping: %s", rules_file)
            return 0
        except OSError as exc:
            logger.error("Could not read %s: %s", rules_file, exc)
            return 0

        new_lines = []
        removed_blocks = 0
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.strip().startswith('### tuple ###'):
                # Collect the full block: the tuple metadata line plus all
                # immediately following iptables command lines.
                block = [line]
                j = i + 1
                while j < len(lines) and lines[j].strip().startswith(_UFW_IPTABLES_PREFIXES):
                    block.append(lines[j])
                    j += 1

                # Remove the block if any line in it references one of the
                # (ip, comment) pairs we want to delete.
                # Use " {ip_str}" (space-prefixed) to avoid matching a longer
                # IP that happens to contain ip_str as a substring
                # (e.g. prevent '1.2.3.4/32' matching '11.2.3.4/32').
                if any(
                    f" {ip_str}" in bl and comment_str in bl
                    for ip_str, comment_str in rules_to_remove
                    for bl in block
                ):
                    removed_blocks += 1
                    logger.debug(
                        "Removing expired rule block from %s: %s",
                        rules_file, block[0].strip(),
                    )
                else:
                    new_lines.extend(block)
                i = j
            else:
                new_lines.append(line)
                i += 1

        if removed_blocks > 0:
            try:
                with open(rules_file, 'w') as fh:
                    fh.writelines(new_lines)
                logger.debug(
                    "Removed %d expired rule block(s) from %s.",
                    removed_blocks, rules_file,
                )
            except OSError as exc:
                logger.error("Could not write %s: %s", rules_file, exc)
                return 0

        return removed_blocks

    def block_target(self, subnet_or_ip_obj, block_duration_minutes):
        """
        Blocks an IP or subnet using UFW on TCP web ports only with an ISO 8601 expiration comment.
        Inserts the rules at position 1 for priority.

        Args:
            subnet_or_ip_obj (ipaddress.network or ipaddress.address): IP/Subnet object to block.
            block_duration_minutes (int): Block duration in minutes.

        Returns:
            bool: True if the command was executed successfully (or in dry run), False otherwise.
        """
        valid_types = (ipaddress.IPv4Network, ipaddress.IPv6Network, ipaddress.IPv4Address, ipaddress.IPv6Address)
        if not isinstance(subnet_or_ip_obj, valid_types):
            logger.error(f"Invalid data type for blocking: {type(subnet_or_ip_obj)}")
            return False

        # Ensure target is in CIDR format (e.g., 1.2.3.4/32)
        target_str = str(subnet_or_ip_obj.exploded) # Use exploded for consistency
        if isinstance(subnet_or_ip_obj, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            prefix_len = 32 if subnet_or_ip_obj.version == 4 else 128
            target_str = f"{target_str}/{prefix_len}"
        elif isinstance(subnet_or_ip_obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
             target_str = str(subnet_or_ip_obj) # Already in CIDR

        # Calculate expiration timestamp and format comment
        expiry_time_utc = datetime.now(timezone.utc) + timedelta(minutes=block_duration_minutes)
        expiry_str_iso = expiry_time_utc.strftime('%Y%m%dT%H%M%SZ')
        comment = f"{COMMENT_PREFIX}{expiry_str_iso}"

        logger.info(f"Attempting to block: {target_str} until {expiry_str_iso} UTC")
        all_rules_succeeded = True
        for port in BLOCK_TCP_PORTS:
            command_args = [
                "insert", "1", "deny",
                "from", target_str,
                "to", "any",
                "port", str(port),
                "proto", "tcp",
                "comment", comment
            ]
            result = self._run_ufw_command(command_args)

            # Check for success (return code 0) or if rule already existed
            if result.returncode == 0:
                continue
            if "Skipping adding existing rule" in result.stdout or "Skipping adding existing rule" in result.stderr:
                logger.info(f"Note: The {port}/tcp rule for {target_str} probably already existed.")
                continue

            all_rules_succeeded = False
            logger.error("Failed to add %s/tcp deny rule for %s.", port, target_str)

        return all_rules_succeeded


    def clean_expired_rules(self):
        """
        Removes expired UFW rules based on the ISO 8601 UTC timestamp comment.

        Returns:
            int: The number of rules deleted.
        """
        deleted_count = 0
        logger.debug(f"Starting expired rule cleanup (prefix: '{COMMENT_PREFIX}').")
        try:
            result = self._run_ufw_command(['status', 'numbered'])
            if result.returncode != 0:
                logger.error(f"Failed to get UFW status: {result.stderr}")
                return 0
            if self.dry_run and "[DRY RUN]" in result.stdout:
                 logger.info("[DRY RUN] Skipping rule parsing.")
                 return 0

            logger.debug("--- UFW Status Output ---")
            logger.debug(result.stdout)
            logger.debug("--- End UFW Status Output ---")

            # Regex to find rules with the specific comment format
            rule_pattern = re.compile(
                r"\[\s*(\d+)\].*?#\s*" +       # Capture rule number
                re.escape(COMMENT_PREFIX) +    # Match the exact prefix
                r"(\d{8}T\d{6}Z)"              # Capture the ISO timestamp
            )
            logger.debug(f"Using regex pattern: {rule_pattern.pattern}")

            now_utc = datetime.now(timezone.utc)
            logger.debug(f"Current UTC time for comparison: {now_utc}")
            parsed_rules = []
            expired_count = 0
            held_by_grace = 0

            lines = result.stdout.splitlines()
            logger.debug(f"Processing {len(lines)} lines from UFW status.")
            for line_num, line in enumerate(lines):
                match = rule_pattern.search(line)
                if match:
                    rule_number_str, expiry_timestamp_str = match.groups()
                    logger.debug(f"Regex matched line {line_num + 1}: Rule={rule_number_str}, Expiry={expiry_timestamp_str}")
                    rule_number = int(rule_number_str)
                    try:
                        expiry_time_naive = datetime.strptime(expiry_timestamp_str, '%Y%m%dT%H%M%SZ')
                        expiry_time_utc = expiry_time_naive.replace(tzinfo=timezone.utc)
                        logger.debug(f"Rule {rule_number}: Parsed expiry UTC={expiry_time_utc}")
                        target_network = self._extract_target_network(line)
                        family_key = self._network_family_key(target_network)

                        if now_utc >= expiry_time_utc:
                            expired_count += 1
                            age_seconds = (now_utc - expiry_time_utc).total_seconds()
                            age_minutes = age_seconds / 60.0
                            is_eligible = age_minutes >= CLEANUP_GRACE_MINUTES
                            if not is_eligible:
                                held_by_grace += 1

                            parsed_rules.append({
                                'rule_number': rule_number,
                                'expiry_time_utc': expiry_time_utc,
                                'expiry_timestamp_str': expiry_timestamp_str,
                                'age_minutes': age_minutes,
                                'eligible': is_eligible,
                                'target_network': target_network,
                                'family_key': family_key,
                            })
                        else:
                            logger.debug(f"Rule {rule_number} has not expired yet.")
                    except ValueError as e:
                        logger.warning(f"Could not parse timestamp for rule {rule_number_str} ('{expiry_timestamp_str}') - Error: {e}")
                    except Exception as e:
                         logger.error(f"Error processing rule details for rule {rule_number_str} - Error: {e}")

            if expired_count == 0:
                logger.info("No expired rules found matching the criteria.")
                return 0

            eligible_rules = [r for r in parsed_rules if r['eligible']]
            eligible_count = len(eligible_rules)
            if eligible_count == 0:
                logger.info(
                    "Cleanup heuristic held all expired rules in grace period (expired=%d, grace=%dm).",
                    expired_count,
                    CLEANUP_GRACE_MINUTES
                )
                return 0

            # Heuristic cap: if host is still under pressure, release more slowly.
            max_delete_this_run = CLEANUP_MAX_DELETE_PER_RUN
            load_ratio = self._system_load_ratio()
            if load_ratio is not None and load_ratio >= CLEANUP_HIGH_LOAD_RATIO:
                max_delete_this_run = min(max_delete_this_run, CLEANUP_HIGH_LOAD_MAX_DELETE)
                logger.info(
                    "Cleanup running under high load (ratio=%.2f). Reducing delete cap to %d.",
                    load_ratio,
                    max_delete_this_run
                )

            # Prefer oldest expired rules, but limit deletions per /16 (IPv4) or /48 (IPv6) family.
            eligible_rules.sort(key=lambda r: r['expiry_time_utc'])
            family_delete_count = defaultdict(int)
            selected_rules = []
            held_by_family_cap = 0

            for rule in eligible_rules:
                if len(selected_rules) >= max_delete_this_run:
                    break

                family_key = rule.get('family_key')
                if family_key and family_delete_count[family_key] >= CLEANUP_PER_FAMILY_DELETE_CAP:
                    held_by_family_cap += 1
                    continue

                selected_rules.append(rule)
                if family_key:
                    family_delete_count[family_key] += 1

            if not selected_rules:
                logger.info(
                    "Cleanup heuristic selected 0 deletions (eligible=%d, held_by_family_cap=%d).",
                    eligible_count,
                    held_by_family_cap
                )
                return 0

            logger.info(
                "Cleanup heuristic: expired=%d, eligible=%d, selected=%d, held_grace=%d, held_family=%d, cap=%d.",
                expired_count,
                eligible_count,
                len(selected_rules),
                held_by_grace,
                held_by_family_cap,
                max_delete_this_run
            )

            # Build (ip_str, comment_str) pairs so we can match exact rule blocks in
            # the UFW rules files.  Using per-rule keys avoids accidentally removing
            # an unselected rule that happens to share the same expiry timestamp.
            rules_to_remove = set()
            for rule in selected_rules:
                ts_str = rule.get('expiry_timestamp_str', '')
                target = rule.get('target_network')
                if ts_str and target:
                    rules_to_remove.add((str(target), f"{COMMENT_PREFIX}{ts_str}"))
                else:
                    logger.debug(
                        "Skipping rule %s: missing expiry_timestamp_str or target_network.",
                        rule.get('rule_number'),
                    )

            if self.dry_run:
                deleted_count = len(selected_rules)
            else:
                # Edit the persistent UFW rules files then reload.
                # `ufw delete <num>` triggers initcaps() in UFW's Python backend, which
                # runs `iptables -N <chain>`.  On some systems (e.g. Amazon Linux with
                # iptables-nft) iptables writes the "Chain already exists" error to
                # stderr while UFW only checks stdout, so UFW treats it as fatal and
                # returns code 1 without deleting anything.
                # `ufw reload` (= stop + start) removes all chains first, so the
                # fresh `iptables -N` calls in start/initcaps succeed cleanly.
                ufw_rules_files = ['/etc/ufw/user.rules', '/etc/ufw/user6.rules']
                total_removed = 0
                for rules_file in UFW_RULES_FILES:
                    total_removed += self._remove_expired_rules_from_file(
                        rules_file, rules_to_remove
                    )

                if total_removed > 0:
                    reload_result = self._run_ufw_command(['--force', 'reload'])
                    if reload_result.returncode == 0:
                        deleted_count = total_removed
                        logger.info(
                            "Cleanup applied: removed %d rule block(s) from rules files and reloaded UFW.",
                            deleted_count,
                        )
                    else:
                        logger.error(
                            "UFW reload failed after editing rules files. "
                            "Rules files were modified but iptables state may be stale."
                        )
                else:
                    logger.warning(
                        "No expired rule blocks found in UFW rules files "
                        "(%s). Rules may have been added outside this script.",
                        ', '.join(UFW_RULES_FILES),
                    )

        except Exception as e:
            logger.error(f"An error occurred during rule cleanup: {e}", exc_info=True)

        return deleted_count
