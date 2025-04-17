#!/usr/bin/env python3
"""
Module for parsing and analyzing web server logs.
Contains functions to extract relevant information from logs in CLF or extended CLF format.
"""
import re
from datetime import datetime
import ipaddress
import logging

# Logger for this module
logger = logging.getLogger('botstats.parser')

def parse_log_line(line):
    """
    Extracts key fields from a log line using regular expression.
    Assumes the log follows the extended format (extended CLF).
    
    Args:
        line (str): Log file line to parse
        
    Returns:
        dict: Dictionary with extracted fields or None if the line doesn't match the pattern
    """
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<request>[^"]+)" '
        r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]+)" "(?P<useragent>[^"]+)"'
    )
    match = log_pattern.search(line)
    if match:
        return match.groupdict()
    return None

def get_subnet(ip_str, version=None, subnet_mask_ipv4=24, subnet_mask_ipv6=64):
    """
    Returns the subnet as an ipaddress.ip_network object based on specified masks.
    Defaults to /24 for IPv4 and /64 for IPv6 if masks are not provided.
    
    Args:
        ip_str (str): IP address in string format
        version (int, optional): IP version to force (4 or 6). Default: None (auto-detect)
        subnet_mask_ipv4 (int): Subnet mask prefix length for IPv4 (e.g., 24 for /24). Default: 24
        subnet_mask_ipv6 (int): Subnet mask prefix length for IPv6 (e.g., 64 for /64). Default: 64
        
    Returns:
        ipaddress.ip_network: Object representing the subnet, or None if the IP is invalid
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # If version is specified, verify that the IP matches
        if version and ip.version != version:
            return None
            
        if ip.version == 4:
            # Create a network with the specified IPv4 mask
            return ipaddress.ip_network(f"{ip_str}/{subnet_mask_ipv4}", strict=False)
        elif ip.version == 6:
            # Create a network with the specified IPv6 mask
            return ipaddress.ip_network(f"{ip_str}/{subnet_mask_ipv6}", strict=False)
    except ValueError:
        # Log the error or handle it as needed
        logger.error(f"Invalid IP address format: {ip_str}")
        return None
    
    return None # Should not be reached if IP is valid IPv4 or IPv6

def is_localhost(ip_str):
    """
    Checks if an IP address is localhost (IPv4: 127.0.0.1/8 or IPv6: ::1).
    
    Args:
        ip_str (str): IP address in string format
        
    Returns:
        bool: True if the IP is localhost, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            return ip.is_loopback  # Checks if in 127.0.0.0/8
        elif ip.version == 6:
            return ip == ipaddress.IPv6Address('::1')
        return False
    except ValueError:
        return False

def calculate_danger_score(rpm, total_requests, has_suspicious_ua, time_span=0, min_duration=5):
    """
    Calculates a danger score based only on RPM (requests per minute).
    Other parameters are maintained for backward compatibility.
    
    Args:
        rpm (float): Requests per minute
        total_requests (int): Total requests (not used in calculation)
        has_suspicious_ua (bool): Whether it has a suspicious user-agent (not used in calculation)
        time_span (float): Duration of activity in seconds (not used in calculation)
        min_duration (float): Minimum duration in seconds (not used in calculation)
        
    Returns:
        float: Danger score based solely on RPM
    """
    # Score is now simply the RPM value
    return rpm

def is_ip_in_whitelist(ip, whitelist):
    """
    Verifies if an IP is in the whitelist.
    
    Args:
        ip (str): The IP address to verify
        whitelist (list): List of IPs or subnets in string format
        
    Returns:
        bool: True if the IP is in the whitelist, False otherwise
    """
    if not whitelist:
        return False
        
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        for item in whitelist:
            try:
                # If the item is a network, verify if the IP is contained
                if '/' in item:
                    network = ipaddress.ip_network(item, strict=False)
                    if ip_obj in network:
                        return True
                # If it's an exact IP
                else:
                    whitelist_ip = ipaddress.ip_address(item)
                    if ip_obj == whitelist_ip:
                        return True
            except ValueError:
                continue
    except ValueError:
        return False
        
    return False