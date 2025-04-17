#!/usr/bin/env python3
"""
Module for parsing web server logs and loading them into Pandas DataFrames.
"""
import re
from datetime import datetime, timezone
import ipaddress
import logging
import math
import pandas as pd
import os # Needed for _read_lines_reverse

# Logger for this module
logger = logging.getLogger('botstats.parser')

# Pre-compile log pattern for efficiency
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<request>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]+)" "(?P<useragent>[^"]+)"'
)

# Helper function for efficient reverse reading (copied from threat_analyzer)
def _read_lines_reverse(filename, buf_size=8192):
    """Read a file line by line backwards, memory efficiently."""
    # ... (Implementation of _read_lines_reverse - unchanged) ...
    with open(filename, 'rb') as f:
        segment = None
        offset = 0
        f.seek(0, os.SEEK_END)
        file_size = remaining_size = f.tell()
        while remaining_size > 0:
            offset = min(file_size, offset + buf_size)
            f.seek(file_size - offset)
            buffer = f.read(min(remaining_size, buf_size))
            try:
                buffer_str = buffer.decode('utf-8')
            except UnicodeDecodeError:
                buffer_str = buffer.decode('utf-8', errors='ignore')

            remaining_size -= buf_size
            lines = buffer_str.splitlines(True)
            if segment is not None:
                if buffer_str[-1] != '\n':
                     lines[-1] += segment
                else:
                    yield segment
            segment = lines[0]
            for i in range(len(lines) - 1, 0, -1):
                 if lines[i]:
                     yield lines[i]
        if segment is not None:
            yield segment


def parse_datetime_to_utc(dt_str):
    """Parses log datetime string and returns timezone-aware UTC datetime or None."""
    try:
        # Try parsing with timezone offset first
        dt_aware = datetime.strptime(dt_str, '%d/%b/%Y:%H:%M:%S %z')
        return dt_aware.astimezone(timezone.utc)
    except ValueError:
        try:
            # Fallback to parsing without timezone (assume local)
            dt_naive = datetime.strptime(dt_str, '%d/%b/%Y:%H:%M:%S')
            # Convert naive local time to aware local time, then to UTC
            dt_aware_local = dt_naive.astimezone()
            return dt_aware_local.astimezone(timezone.utc)
        except ValueError:
            logger.warning(f"Skipping line due to malformed date: {dt_str}")
            return None

def load_log_into_dataframe(log_file, start_date_utc=None, whitelist=None):
    """
    Reads a log file, parses relevant fields, filters by date and whitelist,
    and returns a Pandas DataFrame.

    Args:
        log_file (str): Path to the log file.
        start_date_utc (datetime, optional): Aware UTC datetime. Only entries >= this date are kept.
        whitelist (list, optional): List of IPs/subnets to exclude.

    Returns:
        pd.DataFrame: DataFrame with columns ['ip', 'timestamp'] or None if error.
                      'timestamp' column contains timezone-aware UTC datetime objects.
    """
    parsed_data = []
    total_lines = 0
    skipped_date = 0
    skipped_whitelist = 0
    skipped_parsing = 0

    log_source = None
    reading_mode = ""

    try:
        if start_date_utc:
            reading_mode = "reverse"
            logger.info(f"Processing log file in reverse, stopping before {start_date_utc}")
            log_source = _read_lines_reverse(log_file)
        else:
            reading_mode = "forward"
            logger.info("Processing log file forwards (oldest first)")
            log_source = open(log_file, 'r', encoding='utf-8', errors='ignore')

        for line in log_source:
            total_lines += 1
            match = LOG_PATTERN.search(line)
            if not match:
                skipped_parsing += 1
                continue

            data = match.groupdict()
            ip = data['ip']

            # 1. Whitelist Check (early exit)
            if is_ip_in_whitelist(ip, whitelist):
                skipped_whitelist += 1
                continue

            # 2. Date Parsing and Filtering
            timestamp_utc = parse_datetime_to_utc(data['datetime'])
            if timestamp_utc is None:
                skipped_date += 1
                continue

            # Stop reverse reading if timestamp is before start_date_utc
            if start_date_utc and timestamp_utc < start_date_utc:
                if reading_mode == "reverse":
                    logger.info(f"Reached entry older than {start_date_utc}. Stopping reverse scan.")
                    break
                else: # Forward reading, just skip this line
                    skipped_date += 1
                    continue

            # Append relevant data
            parsed_data.append({'ip': ip, 'timestamp': timestamp_utc})

            # Log progress periodically
            if total_lines % 50000 == 0:
                 logger.info(f"Processed {total_lines} lines...")

        logger.info(f"Finished reading log file. Total lines: {total_lines}")
        logger.info(f"Entries added: {len(parsed_data)}, Skipped (Parsing): {skipped_parsing}, Skipped (Date): {skipped_date}, Skipped (Whitelist): {skipped_whitelist}")

        if not parsed_data:
            logger.warning("No valid log entries found after filtering.")
            return pd.DataFrame(columns=['ip', 'timestamp']) # Return empty DataFrame

        # Create DataFrame
        df = pd.DataFrame(parsed_data)
        # Ensure timestamp column is datetime type
        df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
        logger.info(f"DataFrame created with {len(df)} entries.")
        return df

    except FileNotFoundError:
        logger.error(f"File not found {log_file}")
        return None
    except Exception as e:
        logger.error(f"Error processing log file {log_file}: {e}", exc_info=True)
        return None
    finally:
        if reading_mode == "forward" and log_source and not log_source.closed:
            log_source.close()


# --- Functions kept from previous version ---

def get_subnet(ip_str):
    """
    Returns the default subnet (/24 for IPv4, /64 for IPv6) as an
    ipaddress.ip_network object, or None if the IP is invalid.
    """
    # ... (Implementation of get_subnet - simplified to only return default) ...
    default_ipv4_mask = 24
    default_ipv6_mask = 64
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            mask = default_ipv4_mask
        elif ip.version == 6:
            mask = default_ipv6_mask
        else:
            return None
        return ipaddress.ip_network(f"{ip_str}/{mask}", strict=False)
    except ValueError:
        # Logged internally by ipaddress usually, or we can add:
        # logger.debug(f"Invalid IP address format for subnet calculation: {ip_str}")
        return None


def calculate_danger_score(avg_rpm, total_requests, time_span_seconds=0, min_duration_seconds=5):
    """
    Calculates a danger score based on average RPM during activity and total requests.

    Args:
        avg_rpm (float): Average requests per minute during active minutes.
        total_requests (int): Total number of requests.
        time_span_seconds (float): Total duration of activity in seconds.
        min_duration_seconds (int): Minimum duration in seconds for RPM to be considered significant.

    Returns:
        float: Calculated danger score.
    """
    # ... (Implementation of calculate_danger_score - unchanged logic, using avg_rpm now) ...
    score = 0
    if avg_rpm > 0 and time_span_seconds >= min_duration_seconds:
        if avg_rpm > 500: score += 100
        elif avg_rpm > 200: score += 50
        elif avg_rpm > 100: score += 25
        elif avg_rpm > 50: score += 10
        else: score += avg_rpm / 10
    if total_requests > 1:
        request_score = math.log10(total_requests) * 10
        score += request_score
    elif total_requests == 1:
        score += 0.1
    return max(0, score)


def is_ip_in_whitelist(ip, whitelist):
    """
    Verifies if an IP is in the whitelist. Handles IPs and Subnets.
    """
    # ... (Implementation of is_ip_in_whitelist - unchanged) ...
    if not whitelist: return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        for item in whitelist:
            try:
                if '/' in item:
                    network = ipaddress.ip_network(item, strict=False)
                    if ip_obj in network: return True
                else:
                    whitelist_ip = ipaddress.ip_address(item)
                    if ip_obj == whitelist_ip: return True
            except ValueError: continue # Ignore invalid whitelist entries
    except ValueError: return False # Ignore invalid IP to check
    return False