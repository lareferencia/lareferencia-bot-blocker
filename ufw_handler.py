#!/usr/bin/env python3
"""
Module for handling interactions with the UFW firewall using ISO 8601 comments.
"""
import re
import subprocess
import sys
from datetime import datetime, timezone, timedelta
import ipaddress
import logging

# Logger for this module
logger = logging.getLogger('botstats.ufw')

# Comment prefix for rules added by this script
COMMENT_PREFIX = "blocked_by_stats_py_until_"

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
                 logger.warning("UFW command not found. Blocking/cleanup will fail.")
                 return False
            return True
        except Exception:
            logger.warning("Could not verify UFW availability. Some operations might fail.")
            return False

    def _run_ufw_command(self, command_args):
        """Executes a UFW command, handling potential 'delete' confirmation."""
        base_command = ['sudo', 'ufw']
        full_command_list = base_command + command_args
        command_str = ' '.join(full_command_list)
        shell_needed = False
        final_command = full_command_list

        is_delete_command = command_args and command_args[0] == 'delete'

        if self.dry_run:
            log_prefix = "[DRY RUN]"
            if is_delete_command:
                command_str = f"echo y | {command_str}"
            logger.info(f"{log_prefix} Would execute: {command_str}")
            return subprocess.CompletedProcess(args=final_command, returncode=0, stdout=f"{log_prefix} Command not executed.\n", stderr="")
        else:
            log_prefix = ""
            if is_delete_command:
                command_str = f"echo y | {command_str}"
                shell_needed = True
                final_command = command_str
                logger.debug("Using 'shell=True' for UFW delete command to handle confirmation.")

            logger.debug(f"{log_prefix}Executing: {command_str}")
            try:
                result = subprocess.run(final_command, capture_output=True, text=True, check=False, shell=shell_needed)
                if result.returncode != 0:
                    logger.warning(f"Command '{command_str}' failed with code {result.returncode}")
                    logger.warning(f"Stderr: {result.stderr.strip()}")
                    logger.warning(f"Stdout: {result.stdout.strip()}")
                else:
                    logger.debug(f"Command '{command_str}' executed successfully.")
                return result
            except FileNotFoundError:
                logger.error(f"Error: 'sudo' or 'ufw' command not found.")
                return subprocess.CompletedProcess(args=final_command, returncode=127, stdout="", stderr="Command not found")
            except Exception as e:
                logger.error(f"Error executing UFW command '{command_str}': {e}")
                return subprocess.CompletedProcess(args=final_command, returncode=1, stdout="", stderr=str(e))


    def block_target(self, subnet_or_ip_obj, block_duration_minutes):
        """
        Blocks an IP or subnet using UFW with an ISO 8601 expiration comment.
        Inserts the rule at position 1 for priority.

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

        # Construct command to insert rule at position 1
        command_args = ["insert", "1", "deny", "from", target_str, "to", "any", "comment", comment]

        logger.info(f"Attempting to block: {target_str} until {expiry_str_iso} UTC")
        result = self._run_ufw_command(command_args)

        # Check for success (return code 0) or if rule already existed
        if result.returncode == 0:
             return True
        elif result.returncode !=0 and ("Skipping adding existing rule" in result.stdout or "Skipping adding existing rule" in result.stderr):
             logger.info(f"Note: The rule for {target_str} probably already existed.")
             return True # Consider already existing as 'success' in this context
        else:
             return False


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
            rules_to_delete = []

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

                        if now_utc >= expiry_time_utc:
                            logger.info(f"Rule {rule_number} EXPIRED at {expiry_time_utc}. Marked for deletion.")
                            rules_to_delete.append(rule_number)
                        else:
                             logger.debug(f"Rule {rule_number} has not expired yet.")
                    except ValueError as e:
                        logger.warning(f"Could not parse timestamp for rule {rule_number_str} ('{expiry_timestamp_str}') - Error: {e}")
                    except Exception as e:
                         logger.error(f"Error processing rule details for rule {rule_number_str} - Error: {e}")

            # Delete rules by number, in descending order
            if rules_to_delete:
                 logger.info(f"Attempting to delete {len(rules_to_delete)} expired rules...")
                 for rule_num in sorted(rules_to_delete, reverse=True):
                     delete_result = self._run_ufw_command(['delete', str(rule_num)])
                     if delete_result.returncode == 0 and not self.dry_run:
                         if "Deleting:" in delete_result.stdout and f"rule {rule_num}" in delete_result.stdout:
                              logger.info(f"Successfully deleted rule {rule_num} (confirmed by stdout).")
                              deleted_count += 1
                         elif "Skipping" not in delete_result.stdout:
                              logger.info(f"Successfully executed delete command for rule {rule_num} (return code 0).")
                              deleted_count += 1
                         else:
                              logger.warning(f"Delete command for rule {rule_num} returned 0 but stdout indicates skipping: {delete_result.stdout}")
                     elif self.dry_run:
                          deleted_count += 1
            else:
                 logger.info("No expired rules found matching the criteria.")

        except Exception as e:
            logger.error(f"An error occurred during rule cleanup: {e}", exc_info=True)

        return deleted_count