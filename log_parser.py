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

def get_subnet(ip_str, version=None):
    """
    Returns the subnet as an ipaddress.ip_network object.
    For IPv4 returns a /24 network, for IPv6 returns a /64 network.
    
    Args:
        ip_str (str): IP address in string format
        version (int, optional): IP version to force (4 or 6). Default: None (auto-detect)
        
    Returns:
        ipaddress.ip_network: Object representing the subnet, or None if the IP is invalid
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # If version is specified, verify that the IP matches
        if version and ip.version != version:
            return None
            
        if ip.version == 4:
            # Create a /24 network without validating if the IP is the network address
            return ipaddress.ip_network(f"{ip_str}/24", strict=False)
        elif ip.version == 6:
            # For IPv6 we use /64 which is common for subnets
            return ipaddress.ip_network(f"{ip_str}/64", strict=False)
    except ValueError:
        return None
    
    return None  # Unhandled case (shouldn't reach here)

def calculate_danger_score(rpm, total_requests, has_suspicious_ua):
    """
    Calculates a danger score based on RPM, total requests
    and whether it has a suspicious user-agent.
    
    Args:
        rpm (float): Requests per minute
        total_requests (int): Total requests
        has_suspicious_ua (bool): Whether it has a suspicious user-agent
        
    Returns:
        float: Danger score
    """
    # Base factor is the RPM normalized by the threshold
    score = rpm / 100
    
    # Additional factors
    if has_suspicious_ua:
        score *= 1.5  # Increase for suspicious user-agent
    
    # Total number of requests also increases the danger
    score += total_requests / 1000
    
    return score

def process_log_in_chunks(filename, handler_func, chunk_size=10000, reverse=False, **kwargs):
    """
    Process the log file in segments to reduce memory usage.
    
    Args:
        filename (str): Path to the log file
        handler_func (callable): Function that processes each chunk of lines
        chunk_size (int): Chunk size in number of lines
        reverse (bool): If True, processes the file from end to beginning
                      and stops when a line is outside the time window
        **kwargs: Additional arguments to pass to handler_func
        
    Returns:
        Any: The result of the last call to handler_func
        
    Note:
        When reverse=True, handler_func should return False to stop processing
        once it detects a log entry outside the desired time window.
    """
    total_processed = 0
    
    if not reverse:
        # Original forward processing
        with open(filename, 'r') as f:
            chunk = []
            for i, line in enumerate(f):
                chunk.append(line)
                if i % chunk_size == chunk_size - 1:
                    result = handler_func(chunk, **kwargs)
                    total_processed += chunk_size
                    chunk = []
                    # If handler returns False, stop processing
                    if result is False:
                        logger.info(f"Handler requested to stop processing after {total_processed} lines")
                        return total_processed
            # Process the last segment if it exists
            if chunk:
                result = handler_func(chunk, **kwargs)
                total_processed += len(chunk)
                if result is False:
                    logger.info(f"Handler requested to stop processing after {total_processed} lines")
    else:
        # Reverse processing (from newest to oldest)
        logger.info("Processing log file in reverse mode (newest to oldest)")
        
        # First, get file size and calculate number of chunks
        import os
        file_size = os.path.getsize(filename)
        
        with open(filename, 'r') as f:
            # Start from end of file
            position = file_size
            lines_buffer = []
            current_chunk = []
            
            while position > 0:
                # Adjust chunk size for last read
                read_size = min(position, chunk_size * 100)  # Read larger chunks for efficiency
                position -= read_size
                
                # Seek to position and read a block
                f.seek(position)
                block = f.read(read_size)
                
                # Handle case when position is not at line start
                if position > 0:
                    # Skip partial first line if not at BOF
                    block = block[block.find('\n')+1:]
                
                # Add to buffer and split into lines
                lines_buffer = block.splitlines() + lines_buffer
                
                # Process in chunks of the specified size
                while len(lines_buffer) >= chunk_size:
                    current_chunk = lines_buffer[:chunk_size]
                    lines_buffer = lines_buffer[chunk_size:]
                    
                    result = handler_func(current_chunk, **kwargs)
                    total_processed += len(current_chunk)
                    
                    # If handler returns False, stop processing
                    if result is False:
                        logger.info(f"Handler requested to stop processing after {total_processed} lines")
                        return total_processed
                
                # If we're at the beginning of file, process remaining lines
                if position == 0 and lines_buffer:
                    result = handler_func(lines_buffer, **kwargs)
                    total_processed += len(lines_buffer)
                    if result is False:
                        logger.info(f"Handler requested to stop processing after {total_processed} lines")
    
    return total_processed

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