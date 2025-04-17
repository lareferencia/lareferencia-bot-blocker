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

def get_subnet(ip_str, subnet_masks_ipv4=None, subnet_masks_ipv6=None):
    """
    Returns a list of subnets as ipaddress.ip_network objects based on specified masks.
    Defaults to /24 for IPv4 and /64 for IPv6 if masks are not provided.

    Args:
        ip_str (str): IP address in string format
        subnet_masks_ipv4 (list[int], optional): List of subnet mask prefix lengths for IPv4. Default: [24]
        subnet_masks_ipv6 (list[int], optional): List of subnet mask prefix lengths for IPv6. Default: [64]

    Returns:
        list[ipaddress.ip_network]: List of objects representing the subnets, or empty list if IP is invalid
    """
    # Set default masks if none provided
    if subnet_masks_ipv4 is None:
        subnet_masks_ipv4 = [24]
    if subnet_masks_ipv6 is None:
        subnet_masks_ipv6 = [64]

    subnets = []
    try:
        ip = ipaddress.ip_address(ip_str)

        if ip.version == 4:
            # Create networks for each specified IPv4 mask
            for mask in subnet_masks_ipv4:
                try:
                    network = ipaddress.ip_network(f"{ip_str}/{mask}", strict=False)
                    subnets.append(network)
                except ValueError:
                    logger.warning(f"Could not create IPv4 network {ip_str}/{mask}")
        elif ip.version == 6:
            # Create networks for each specified IPv6 mask
            for mask in subnet_masks_ipv6:
                try:
                    network = ipaddress.ip_network(f"{ip_str}/{mask}", strict=False)
                    subnets.append(network)
                except ValueError:
                    logger.warning(f"Could not create IPv6 network {ip_str}/{mask}")

    except ValueError:
        # Log the error or handle it as needed
        logger.error(f"Invalid IP address format: {ip_str}")
        return [] # Return empty list for invalid IP

    return subnets

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