#!/usr/bin/env python3
"""
Module for handling interactions with the UFW firewall.
Allows blocking IPs/subnets and cleaning expired rules.
"""
import re
import subprocess
import sys
from datetime import datetime, timezone, timedelta
import ipaddress
import logging

# Logger for this module
logger = logging.getLogger('botstats.ufw')

# Regular expression to detect UFW rules with expiration timestamp
RULE_STATUS_REGEX = re.compile(
    r"\[\s*(\d+)\].*(?:ALLOW|DENY)\s+IN\s+FROM\s+(\S+).*\s#\s*blocked_by_stats_py_until_(\d{8}T\d{6}Z)"
)

class UFWManager:
    """
    Class for handling UFW operations in a more encapsulated way.
    """
    
    def __init__(self, dry_run=False):
        """
        Initializes the UFW handler.
        
        Args:
            dry_run (bool): If True, shows but does not execute the commands
        """
        self.dry_run = dry_run
        self._check_ufw_available()
        
    def _check_ufw_available(self):
        """
        Verifies that UFW is available and the user has permissions.
        
        Returns:
            bool: True if UFW is available, False otherwise
        """
        try:
            result = subprocess.run(
                ["which", "ufw"], 
                check=False, 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            logger.warning("Could not verify UFW availability. Some operations might fail.")
            return False
            
    def block_target(self, subnet_or_ip, block_duration_minutes):
        """
        Blocks an IP or subnet using UFW.
        
        Args:
            subnet_or_ip (ipaddress.IPv4Network|ipaddress.IPv6Network|ipaddress.IPv4Address|ipaddress.IPv6Address): 
                IP or subnet to block
            block_duration_minutes (int): Block duration in minutes
            
        Returns:
            bool: True if the command executed successfully, False otherwise
        """
        # Validate address or network type
        valid_types = (
            ipaddress.IPv4Network, ipaddress.IPv6Network, 
            ipaddress.IPv4Address, ipaddress.IPv6Address
        )
        if not isinstance(subnet_or_ip, valid_types):
            logger.error(f"Invalid data type for blocking: {type(subnet_or_ip)}")
            return False

        target = str(subnet_or_ip)
        # Ensure network format for individual IPs
        if isinstance(subnet_or_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            # /32 for IPv4 and /128 for IPv6
            prefix_len = 32 if subnet_or_ip.version == 4 else 128
            target = f"{target}/{prefix_len}"

        # Calculate expiration timestamp in UTC
        expiry_time = datetime.now(timezone.utc) + timedelta(minutes=block_duration_minutes)
        # Compact ISO 8601 format for filenames/comments
        expiry_str = expiry_time.strftime('%Y%m%dT%H%M%SZ')
        comment = f"blocked_by_stats_py_until_{expiry_str}"

        # Use 'insert 1' to give priority to the blocking rule
        command = ["sudo", "ufw", "insert", "1", "deny", "from", target, "to", "any", "comment", comment]

        logger.info(f"Attempting to block: {target} until {expiry_str} UTC")
        if self.dry_run:
            logger.info(f"[DRY RUN] UFW command: {' '.join(command)}")
            return True

        try:
            result = subprocess.run(
                command, 
                check=True, 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            logger.info(f"UFW command executed successfully for {target}.")
            if result.stdout:
                logger.debug(f"UFW output: {result.stdout.strip()}")
            # UFW sometimes prints informational messages to stderr
            if result.stderr:
                logger.debug(f"UFW output (stderr): {result.stderr.strip()}")
            return True
        except FileNotFoundError:
            logger.error("The 'sudo' or 'ufw' command was not found. Make sure ufw is installed.")
            return False
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout executing UFW command for {target}.")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"Error executing the UFW command for {target}:")
            logger.error(f"Command: {' '.join(command)}")
            logger.error(f"Return code: {e.returncode}")
            logger.error(f"Error output: {e.stderr.strip()}")
            logger.error(f"Standard output: {e.stdout.strip()}")
            # Check if the error is because the rule already exists
            if "Skipping adding existing rule" in e.stdout or "Skipping adding existing rule" in e.stderr:
                 logger.info(f"Note: The rule for {target} probably already existed.")
                 return True
            return False
        except Exception as e:
            logger.error(f"Unexpected error executing UFW for {target}: {e}")
            return False

    def get_expired_rules(self):
        """
        Gets a list of expired UFW rule numbers.
        
        Returns:
            list: List of expired rule numbers sorted from highest to lowest
        """
        rules_to_delete = []
        try:
            cmd = ["sudo", "ufw", "status", "numbered"]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=15)
            output_lines = result.stdout.splitlines()
            now_utc = datetime.now(timezone.utc)
            for line in output_lines:
                match = RULE_STATUS_REGEX.search(line)
                if match:
                    rule_number_str, target, expiry_str = match.groups()
                    rule_number = int(rule_number_str)
                    try:
                        expiry_time = datetime.strptime(expiry_str, '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
                        if now_utc >= expiry_time:
                            rules_to_delete.append(rule_number)
                    except ValueError:
                        pass
            return sorted(rules_to_delete, reverse=True)
        except Exception as e:
            logger.error(f"Error getting UFW rules: {e}")
            return []

    def delete_rule(self, rule_number):
        """
        Deletes a UFW rule by its number.
        
        Args:
            rule_number (int): Number of the rule to delete
            
        Returns:
            bool: True if the rule was deleted successfully, False otherwise
        """
        command = ["sudo", "ufw", "--force", "delete", str(rule_number)]
        if self.dry_run:
            logger.info(f"[DRY RUN] Would delete rule #{rule_number}: {' '.join(command)}")
            return True
            
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)
            logger.info(f"UFW rule #{rule_number} deleted.")
            return True
        except Exception as e:
            logger.error(f"Error deleting UFW rule #{rule_number}: {e}")
            return False

    def clean_expired_rules(self, comment_prefix="blocked_by_stats_py_until_"):
        """
        Removes expired UFW rules based on ISO 8601 UTC timestamp in the comment.
        Parses comments like: # blocked_by_stats_py_until_20250417T135757Z

        Args:
            comment_prefix (str): The prefix used in comments before the timestamp.

        Returns:
            int: The number of rules deleted.
        """
        deleted_count = 0
        logger.debug("Starting expired rule cleanup process (ISO 8601 format).")
        try:
            # Get numbered rules
            result = self._run_ufw_command(['status', 'numbered'])
            if result.returncode != 0:
                logger.error(f"Failed to get UFW status: {result.stderr}")
                return 0
            if self.dry_run and "[DRY RUN]" in result.stdout:
                 logger.info("[DRY RUN] Skipping rule parsing as status was not actually fetched.")
                 return 0

            logger.debug("--- UFW Status Output ---")
            logger.debug(result.stdout)
            logger.debug("--- End UFW Status Output ---")

            # Regex to find rules with the specific comment format
            # Captures rule number and the ISO timestamp
            rule_pattern = re.compile(
                r"\[\s*(\d+)\].*?#\s*" +       # Capture rule number, match comment start
                re.escape(comment_prefix) +    # Match the exact prefix
                r"(\d{8}T\d{6}Z)"              # Capture the ISO timestamp (YYYYMMDDTHHMMSSZ)
            )
            logger.debug(f"Using regex pattern: {rule_pattern.pattern}")

            now_utc = datetime.now(timezone.utc)
            logger.debug(f"Current UTC time for comparison: {now_utc}")
            rules_to_delete = []

            lines = result.stdout.splitlines()
            logger.debug(f"Processing {len(lines)} lines from UFW status.")
            for line_num, line in enumerate(lines):
                logger.debug(f"Processing line {line_num + 1}: {line.strip()}")
                match = rule_pattern.search(line)
                if match:
                    rule_number_str, expiry_timestamp_str = match.groups()
                    logger.debug(f"Regex matched line {line_num + 1}: Rule={rule_number_str}, Expiry={expiry_timestamp_str}")
                    rule_number = int(rule_number_str)

                    try:
                        # Parse the ISO 8601 UTC timestamp
                        # The format includes 'Z' which strptime doesn't handle directly for timezone.
                        # We parse it as naive and then replace tzinfo because we know 'Z' means UTC.
                        expiry_time_naive = datetime.strptime(expiry_timestamp_str, '%Y%m%dT%H%M%SZ')
                        expiry_time_utc = expiry_time_naive.replace(tzinfo=timezone.utc) # Make it timezone-aware UTC

                        logger.debug(f"Rule {rule_number}: Parsed expiry UTC={expiry_time_utc}")

                        if now_utc >= expiry_time_utc:
                            logger.info(f"Rule {rule_number} EXPIRED at {expiry_time_utc}. Marked for deletion.")
                            rules_to_delete.append(rule_number)
                        else:
                             logger.debug(f"Rule {rule_number} has not expired yet.")

                    except ValueError as e:
                        logger.warning(f"Could not parse timestamp for rule {rule_number_str} ('{expiry_timestamp_str}') in line: {line.strip()} - Error: {e}")
                    except Exception as e:
                         logger.error(f"Error processing rule details for rule {rule_number_str} in line: {line.strip()} - Error: {e}")
                # else: # Optional: Log lines that didn't match
                #     logger.debug(f"Line {line_num + 1} did not match regex.")

            # Delete rules by number, in descending order
            if rules_to_delete:
                 logger.info(f"Attempting to delete {len(rules_to_delete)} expired rules...")
                 for rule_num in sorted(rules_to_delete, reverse=True):
                     delete_result = self._run_ufw_command(['delete', str(rule_num)])
                     if delete_result.returncode == 0 and not self.dry_run:
                         logger.info(f"Successfully deleted rule {rule_num}.")
                         deleted_count += 1
                     elif self.dry_run:
                          logger.info(f"[DRY RUN] Would delete rule {rule_num}.")
                          deleted_count += 1
                     else:
                         logger.error(f"Failed to delete rule {rule_num}: {delete_result.stderr}")
                         logger.error(f"UFW delete stdout for rule {rule_num}: {delete_result.stdout}")
            else:
                 logger.info("No expired rules found matching the criteria.")

        except Exception as e:
            logger.error(f"An error occurred during rule cleanup: {e}", exc_info=True)

        return deleted_count

    def _run_ufw_command(self, command_args):
        """
        Executes a UFW command using subprocess, handling potential 'delete' confirmation.

        Args:
            command_args (list): List of arguments for the ufw command (e.g., ['status', 'numbered']).

        Returns:
            subprocess.CompletedProcess: Result object from subprocess.run.
        """
        base_command = ['sudo', 'ufw']
        full_command_list = base_command + command_args
        command_str = ' '.join(full_command_list)
        shell_needed = False
        final_command = full_command_list # Default to list for non-shell execution

        # Check if this is a delete command that might need confirmation
        is_delete_command = command_args and command_args[0] == 'delete'

        if self.dry_run:
            log_prefix = "[DRY RUN]"
            if is_delete_command:
                # Simulate piping 'yes' in dry run log message
                command_str = f"echo y | {command_str}"
            logger.info(f"{log_prefix} Would execute: {command_str}")
            return subprocess.CompletedProcess(args=final_command, returncode=0, stdout=f"{log_prefix} Command not executed.\n", stderr="")
        else:
            log_prefix = ""
            if is_delete_command:
                # Prepend 'echo y |' and use shell=True for delete command
                command_str = f"echo y | {command_str}"
                shell_needed = True
                final_command = command_str # Use the full string command for shell=True
                logger.warning("Using 'shell=True' for UFW delete command to handle confirmation.")

            logger.debug(f"{log_prefix}Executing: {command_str}")
            try:
                result = subprocess.run(
                    final_command, # Use list or string depending on shell_needed
                    capture_output=True,
                    text=True,
                    check=False,
                    shell=shell_needed # Set shell=True only for delete command
                )
                if result.returncode != 0:
                    logger.warning(f"Command '{command_str}' failed with code {result.returncode}")
                    logger.warning(f"Stderr: {result.stderr.strip()}")
                    logger.warning(f"Stdout: {result.stdout.strip()}") # Log stdout too, might contain info
                else:
                    # Check stdout for confirmation messages even on success
                    if "Proceed with operation (y|n)?" in result.stdout:
                         logger.debug(f"Handled confirmation prompt for '{command_str}'.")
                    logger.debug(f"Command '{command_str}' executed successfully.")
                return result
            except FileNotFoundError:
                logger.error(f"Error: 'sudo' or 'ufw' command not found. Is UFW installed and sudo available?")
                return subprocess.CompletedProcess(args=final_command, returncode=127, stdout="", stderr="Command not found")
            except Exception as e:
                logger.error(f"Error executing UFW command '{command_str}': {e}")
                return subprocess.CompletedProcess(args=final_command, returncode=1, stdout="", stderr=str(e))