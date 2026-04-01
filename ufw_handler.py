#!/usr/bin/env python3
"""
Module for handling interactions with the UFW firewall using ISO 8601 comments.
"""
import re
import subprocess
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
CLEANUP_FORCE_DELETE_AFTER_HOURS = 48

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
        is_read_only = bool(command_args) and command_args[0] == 'status'

        if self.dry_run and not is_read_only:
            log_prefix = "[DRY RUN]"
            logger.info(f"{log_prefix} Would execute: {command_str}")
            return subprocess.CompletedProcess(args=full_command_list, returncode=0, stdout=f"{log_prefix} Command not executed.\n", stderr="")

        logger.debug(f"Executing: {command_str}")
        try:
            env = os.environ.copy()
            env["LC_ALL"] = "C"
            env["LANG"] = "C"
            result = subprocess.run(
                full_command_list,
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
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

    @staticmethod
    def _normalize_target_identifier(target):
        """Normalizes a network/address into the same string form used by blocker.py."""
        if target is None:
            return None

        if isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return str(target)

        if isinstance(target, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            max_prefix = 32 if target.version == 4 else 128
            if target.prefixlen == max_prefix:
                return str(target.network_address)
            return str(target)

        return str(target)

    def get_active_managed_targets(self):
        """
        Returns the currently active blocker-managed targets from `ufw status numbered`.

        Active means the rule comment has not yet expired. Targets are normalized to
        match blocker.py identifiers, e.g. IPv4 host rules become `1.2.3.4`, while
        subnets remain in CIDR form such as `1.2.3.0/24`.
        """
        result = self._run_ufw_command(['status', 'numbered'])
        if result.returncode != 0:
            logger.error("Failed to get UFW status while checking active managed targets: %s", result.stderr)
            return set()

        rule_pattern = re.compile(
            r"\[\s*(\d+)\].*?#\s*" +
            re.escape(COMMENT_PREFIX) +
            r"(\d{8}T\d{6}Z)"
        )
        now_utc = datetime.now(timezone.utc)
        active_targets = set()

        for line in result.stdout.splitlines():
            match = rule_pattern.search(line)
            if not match:
                continue

            _rule_number_str, expiry_timestamp_str = match.groups()
            try:
                expiry_time_utc = datetime.strptime(
                    expiry_timestamp_str, '%Y%m%dT%H%M%SZ'
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

            if expiry_time_utc < now_utc:
                continue

            target_network = self._extract_target_network(line)
            target_id = self._normalize_target_identifier(target_network)
            if target_id:
                active_targets.add(target_id)

        logger.info("Detected %d active blocker-managed targets already present in UFW.", len(active_targets))
        return active_targets

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


    def clean_expired_rules(self, delete_all=False):
        """
        Removes expired UFW rules based on the ISO 8601 UTC timestamp comment.

        Args:
            delete_all (bool): If True, delete all expired rules in one run and
                bypass grace period and cleanup throttling.

        Returns:
            int: The number of UFW rules deleted.
        """
        deleted_count = 0
        logger.debug(f"Starting expired rule cleanup (prefix: '{COMMENT_PREFIX}').")
        try:
            result = self._run_ufw_command(['status', 'numbered'])
            if result.returncode != 0:
                logger.error(f"Failed to get UFW status: {result.stderr}")
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
            expired_rule_entries = []
            expired_rule_count = 0
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
                            expired_rule_count += 1
                            age_seconds = (now_utc - expiry_time_utc).total_seconds()
                            age_minutes = age_seconds / 60.0
                            is_eligible = delete_all or (age_minutes >= CLEANUP_GRACE_MINUTES)
                            if not is_eligible:
                                held_by_grace += 1

                            expired_rule_entries.append({
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

            if expired_rule_count == 0:
                logger.info("No expired rules found matching the criteria.")
                return 0

            # Group the port-specific rules into logical block entries so we never
            # delete only one port (80 or 443) for the same target/comment pair.
            grouped_blocks = {}
            for rule in expired_rule_entries:
                target_network = rule.get('target_network')
                target_key = str(target_network) if target_network is not None else None
                group_key = (target_key, rule['expiry_timestamp_str'])
                group = grouped_blocks.get(group_key)
                if group is None:
                    group = {
                        'target_key': target_key,
                        'expiry_time_utc': rule['expiry_time_utc'],
                        'expiry_timestamp_str': rule['expiry_timestamp_str'],
                        'eligible': rule['eligible'],
                        'family_key': rule.get('family_key'),
                        'max_age_minutes': rule.get('age_minutes', 0.0),
                        'rule_numbers': [],
                    }
                    grouped_blocks[group_key] = group
                else:
                    group['eligible'] = group['eligible'] and rule['eligible']
                    if rule['expiry_time_utc'] < group['expiry_time_utc']:
                        group['expiry_time_utc'] = rule['expiry_time_utc']
                    group['max_age_minutes'] = max(group['max_age_minutes'], rule.get('age_minutes', 0.0))
                group['rule_numbers'].append(rule['rule_number'])

            expired_block_count = len(grouped_blocks)
            eligible_blocks = [block for block in grouped_blocks.values() if block['eligible']]
            eligible_count = len(eligible_blocks)
            if eligible_count == 0:
                logger.info(
                    "Cleanup heuristic held all expired blocks in grace period (expired_rules=%d, expired_blocks=%d, grace=%dm).",
                    expired_rule_count,
                    expired_block_count,
                    CLEANUP_GRACE_MINUTES
                )
                return 0

            eligible_blocks.sort(key=lambda block: block['expiry_time_utc'])
            if delete_all:
                selected_blocks = eligible_blocks
                held_by_family_cap = 0
                max_delete_this_run = len(selected_blocks)
                logger.info(
                    "Cleanup full mode: expired_rules=%d, expired_blocks=%d, eligible_blocks=%d, selected_blocks=%d (grace/caps disabled).",
                    expired_rule_count,
                    expired_block_count,
                    eligible_count,
                    len(selected_blocks)
                )
            else:
                force_delete_after_minutes = CLEANUP_FORCE_DELETE_AFTER_HOURS * 60
                stale_blocks = [
                    block for block in eligible_blocks
                    if block.get('max_age_minutes', 0.0) >= force_delete_after_minutes
                ]
                recent_eligible_blocks = [
                    block for block in eligible_blocks
                    if block.get('max_age_minutes', 0.0) < force_delete_after_minutes
                ]

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
                family_delete_count = defaultdict(int)
                selected_blocks = list(stale_blocks)
                held_by_family_cap = 0

                for block in recent_eligible_blocks:
                    if len(selected_blocks) >= len(stale_blocks) + max_delete_this_run:
                        break

                    family_key = block.get('family_key')
                    if family_key and family_delete_count[family_key] >= CLEANUP_PER_FAMILY_DELETE_CAP:
                        held_by_family_cap += 1
                        continue

                    selected_blocks.append(block)
                    if family_key:
                        family_delete_count[family_key] += 1

            if not selected_blocks:
                logger.info(
                    "Cleanup heuristic selected 0 block deletions (eligible_blocks=%d, held_by_family_cap=%d).",
                    eligible_count,
                    held_by_family_cap
                )
                return 0

            if not delete_all:
                logger.info(
                    "Cleanup heuristic: expired_rules=%d, expired_blocks=%d, eligible_blocks=%d, stale_blocks=%d, selected_blocks=%d, held_grace=%d, held_family=%d, cap=%d, force_after_h=%d.",
                    expired_rule_count,
                    expired_block_count,
                    eligible_count,
                    len(stale_blocks),
                    len(selected_blocks),
                    held_by_grace,
                    held_by_family_cap,
                    max_delete_this_run
                    ,
                    CLEANUP_FORCE_DELETE_AFTER_HOURS
                )

            rule_numbers_to_delete = []
            for block in selected_blocks:
                rule_numbers_to_delete.extend(block['rule_numbers'])

            # Delete in descending order so the rule numbers reported by
            # `ufw status numbered` remain valid for the remaining deletions.
            rule_numbers_to_delete = sorted(set(rule_numbers_to_delete), reverse=True)

            if self.dry_run:
                deleted_count = len(rule_numbers_to_delete)
                logger.info(
                    "[DRY RUN] Cleanup would delete %d rule(s): %s",
                    deleted_count,
                    ', '.join(str(rule_number) for rule_number in rule_numbers_to_delete)
                )
            else:
                for rule_number in rule_numbers_to_delete:
                    delete_result = self._run_ufw_command(['--force', 'delete', str(rule_number)])
                    if delete_result.returncode == 0:
                        deleted_count += 1
                        continue

                    logger.error(
                        "Failed to delete expired UFW rule number %s via CLI.",
                        rule_number,
                    )

        except Exception as e:
            logger.error(f"An error occurred during rule cleanup: {e}", exc_info=True)

        return deleted_count
