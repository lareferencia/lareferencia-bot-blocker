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
    Returns the subnet(s) as ipaddress.ip_network objects.
    If multiple masks are given, returns a list.
    If no masks are given (or None), returns a single network object
    using default masks (/24 for IPv4, /64 for IPv6) or None if invalid.

    Args:
        ip_str (str): IP address in string format
        subnet_masks_ipv4 (list[int], optional): List of subnet mask prefix lengths for IPv4.
        subnet_masks_ipv6 (list[int], optional): List of subnet mask prefix lengths for IPv6.

    Returns:
        ipaddress.ip_network or list[ipaddress.ip_network] or None:
            - Single network object if no masks specified.
            - List of network objects if masks are specified.
            - None if IP is invalid.
    """
    return_list = (subnet_masks_ipv4 is not None) or (subnet_masks_ipv6 is not None)

    # Set default masks if needed (used if return_list is False or list is empty)
    default_ipv4_mask = 24
    default_ipv6_mask = 64
    if subnet_masks_ipv4 is None:
        subnet_masks_ipv4 = [default_ipv4_mask]
    if subnet_masks_ipv6 is None:
        subnet_masks_ipv6 = [default_ipv6_mask]

    subnets = []
    try:
        ip = ipaddress.ip_address(ip_str)

        if ip.version == 4:
            masks_to_use = subnet_masks_ipv4
            if not masks_to_use: masks_to_use = [default_ipv4_mask] # Ensure default if list was empty
            for mask in masks_to_use:
                try:
                    network = ipaddress.ip_network(f"{ip_str}/{mask}", strict=False)
                    subnets.append(network)
                except ValueError:
                    logger.warning(f"Could not create IPv4 network {ip_str}/{mask}")
        elif ip.version == 6:
            masks_to_use = subnet_masks_ipv6
            if not masks_to_use: masks_to_use = [default_ipv6_mask] # Ensure default if list was empty
            for mask in masks_to_use:
                try:
                    network = ipaddress.ip_network(f"{ip_str}/{mask}", strict=False)
                    subnets.append(network)
                except ValueError:
                    logger.warning(f"Could not create IPv6 network {ip_str}/{mask}")

    except ValueError:
        logger.error(f"Invalid IP address format: {ip_str}")
        return None # Return None for invalid IP

    if not subnets: # If no valid networks were created
        return None if not return_list else []

    if return_list:
        return subnets
    else:
        # Return the first (and likely only) subnet created using default masks
        return subnets[0]

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

# Remove has_suspicious_ua parameter
def calculate_danger_score(rpm, total_requests, time_span=0, min_duration=5):
    """
    Calculates a danger score based on RPM and total requests.
    Higher RPM and more requests increase the score.

    Args:
        rpm (float): Requests per minute.
        total_requests (int): Total number of requests.
        # has_suspicious_ua (bool): Whether a suspicious user agent was detected. (Removed)
        time_span (float): Duration of activity in seconds.
        min_duration (int): Minimum duration in seconds for RPM to be considered significant.

    Returns:
        float: Calculated danger score.
    """
    score = 0

    # Score based on RPM (only if duration is significant)
    if rpm > 0 and time_span >= min_duration:
        if rpm > 500:
            score += 100
        elif rpm > 200:
            score += 50
        elif rpm > 100:
            score += 25
        elif rpm > 50:
            score += 10
        else:
            score += rpm / 10 # Smaller contribution for lower RPMs

    # Score based on total requests (logarithmic scale to reduce impact of huge numbers)
    if total_requests > 1:
        # Using log base 10. Adjust multiplier as needed.
        # Example: 10 reqs -> ~10 pts, 100 reqs -> ~20 pts, 1000 reqs -> ~30 pts
        request_score = math.log10(total_requests) * 10
        score += request_score
    elif total_requests == 1:
        score += 0.1 # Very small score for single requests

    # Bonus for suspicious User Agent (Removed)
    # if has_suspicious_ua:
    #    score *= 1.5 # Increase score by 50%

    # Ensure score is not negative
    return max(0, score)

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