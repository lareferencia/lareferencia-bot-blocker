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

    def clean_expired_rules(self):
        """
        Cleans all expired UFW rules.
        
        Returns:
            int: Number of rules deleted
        """
        expired = self.get_expired_rules()
        if not expired:
            logger.info("No expired rules to delete.")
            return 0
            
        count = 0
        for rule_num in expired:
            if self.delete_rule(rule_num):
                count += 1
                
        if count > 0:
            logger.info(f"Cleanup completed. {count} rules deleted.")
        return count