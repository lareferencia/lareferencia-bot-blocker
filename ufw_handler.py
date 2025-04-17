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

    def clean_expired_rules(self, comment_prefix="BOTSTATS"):
        """
        Removes expired UFW rules previously added by this script.
        Parses comments like: "BOTSTATS - 123 reqs - 2023-10-27 15:30 - Remove after 60 min"

        Args:
            comment_prefix (str): The prefix used in comments for rules added by this script.

        Returns:
            int: The number of rules deleted.
        """
        deleted_count = 0
        try:
            # Get numbered rules
            result = self._run_ufw_command(['status', 'numbered'])
            if result.returncode != 0:
                logger.error(f"Failed to get UFW status: {result.stderr}")
                return 0

            # Regex to find rules added by this script with duration info
            # Example comment: BOTSTATS - 123 reqs - 2023-10-27 15:30 - Remove after 60 min
            rule_pattern = re.compile(
                r"\[\s*(\d+)\].*ALLOW IN.* Anywhere.*#\s*" + # Rule number and basic structure (adjust if needed)
                re.escape(comment_prefix) +                 # Match the prefix
                r"\s*-\s*\d+\s*reqs\s*-\s*" +                # Match requests part
                r"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2})" +        # Capture timestamp (YYYY-MM-DD HH:MM)
                r"\s*-\s*Remove after\s*(\d+)\s*min"         # Capture duration in minutes
            )
            # Alternative regex if DENY rules are used:
            # rule_pattern = re.compile(
            #     r"\[\s*(\d+)\].*DENY IN.* FROM\s*(.*?)\s.*#\s*" + # Rule number, DENY, capture IP/Subnet
            #     re.escape(comment_prefix) +                 # Match the prefix
            #     r"\s*-\s*\d+\s*reqs\s*-\s*" +                # Match requests part
            #     r"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2})" +        # Capture timestamp (YYYY-MM-DD HH:MM)
            #     r"\s*-\s*Remove after\s*(\d+)\s*min"         # Capture duration in minutes
            # )


            now_utc = datetime.now(timezone.utc) # Use timezone-aware comparison
            rules_to_delete = []

            # Iterate through lines of UFW status output in reverse to avoid index shifting during deletion
            for line in reversed(result.stdout.splitlines()):
                match = rule_pattern.search(line)
                if match:
                    rule_number_str, timestamp_str, duration_str = match.groups()
                    rule_number = int(rule_number_str)
                    duration_minutes = int(duration_str)

                    try:
                        # Assume stored timestamp is naive local time, convert to UTC for comparison
                        # If the timestamp was stored as UTC, use timezone.utc directly
                        rule_timestamp_naive = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M')
                        # Make it timezone-aware (assume it was local time when added)
                        # This might need adjustment if server timezone changed or rules were added in different zones
                        rule_timestamp_aware = rule_timestamp_naive.astimezone() # Convert naive local to aware local
                        rule_timestamp_utc = rule_timestamp_aware.astimezone(timezone.utc) # Convert aware local to UTC

                        expiry_time_utc = rule_timestamp_utc + timedelta(minutes=duration_minutes)

                        if now_utc >= expiry_time_utc:
                            logger.info(f"Rule {rule_number} expired at {expiry_time_utc}. Marked for deletion.")
                            rules_to_delete.append(rule_number)
                        else:
                             logger.debug(f"Rule {rule_number} has not expired yet (expires at {expiry_time_utc}).")

                    except ValueError as e:
                        logger.warning(f"Could not parse timestamp or duration for rule in line: {line} - Error: {e}")
                    except Exception as e:
                         logger.error(f"Error processing rule in line: {line} - Error: {e}")


            # Delete rules by number, in descending order to maintain correct indices
            if rules_to_delete:
                 logger.info(f"Attempting to delete {len(rules_to_delete)} expired rules...")
                 # Sort descending to delete higher numbers first
                 for rule_num in sorted(rules_to_delete, reverse=True):
                     # Important: UFW might ask for confirmation interactively.
                     # Using 'yes' pipe or modifying sudoers might be needed if running non-interactively.
                     # Simplified approach: Assume non-interactive or sudoers configured.
                     # Consider adding 'echo y |' before the command if needed and running via shell=True (less safe).
                     delete_result = self._run_ufw_command(['delete', str(rule_num)])
                     if delete_result.returncode == 0:
                         logger.info(f"Successfully deleted rule {rule_num}.")
                         deleted_count += 1
                     else:
                         logger.error(f"Failed to delete rule {rule_num}: {delete_result.stderr}")
                         # Log stdout as well for potential confirmation prompts
                         logger.error(f"UFW delete stdout for rule {rule_num}: {delete_result.stdout}")


        except Exception as e:
            logger.error(f"An error occurred during rule cleanup: {e}")

        return deleted_count

    def _run_ufw_command(self, command_args):
        """
        Executes a UFW command using subprocess.

        Args:
            command_args (list): List of arguments for the ufw command (e.g., ['status', 'numbered']).

        Returns:
            subprocess.CompletedProcess: Result object from subprocess.run.
        """
        base_command = ['sudo', 'ufw']
        full_command = base_command + command_args
        command_str = ' '.join(full_command)

        if self.dry_run:
            logger.info(f"[DRY RUN] Would execute: {command_str}")
            # Return a dummy CompletedProcess object for dry run consistency
            return subprocess.CompletedProcess(
                args=full_command,
                returncode=0,
                stdout="[DRY RUN] Command not executed.\n",
                stderr=""
            )
        else:
            logger.debug(f"Executing: {command_str}")
            try:
                # Execute command, capture output, use text mode
                result = subprocess.run(
                    full_command,
                    capture_output=True,
                    text=True,
                    check=False # Don't raise exception on non-zero exit code, handle it manually
                )
                if result.returncode != 0:
                    logger.warning(f"Command '{command_str}' failed with code {result.returncode}")
                    logger.warning(f"Stderr: {result.stderr.strip()}")
                else:
                    logger.debug(f"Command '{command_str}' executed successfully.")
                return result
            except FileNotFoundError:
                logger.error(f"Error: 'sudo' or 'ufw' command not found. Is UFW installed and sudo available?")
                # Return a dummy error object
                return subprocess.CompletedProcess(args=full_command, returncode=127, stdout="", stderr="Command not found")
            except Exception as e:
                logger.error(f"Error executing UFW command '{command_str}': {e}")
                return subprocess.CompletedProcess(args=full_command, returncode=1, stdout="", stderr=str(e))