#!/usr/bin/env python3
"""
Module for analysis and threat detection based on server logs.
Strategy: Group logs by default subnet (/24 or /64) during analysis,
calculate metrics per subnet, and report threats based on subnet activity.
"""
import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta
import logging
import json
import csv
import os
import io
import math

from log_parser import parse_log_line, get_subnet, calculate_danger_score, is_ip_in_whitelist

# Logger for this module
logger = logging.getLogger('botstats.analyzer')

# Helper function for efficient reverse reading (_read_lines_reverse)
# ... (existing code for _read_lines_reverse) ...
def _read_lines_reverse(filename, buf_size=8192):
    """Read a file line by line backwards, memory efficiently."""
    with open(filename, 'rb') as f:
        segment = None
        offset = 0
        f.seek(0, os.SEEK_END)
        file_size = remaining_size = f.tell()
        while remaining_size > 0:
            offset = min(file_size, offset + buf_size)
            f.seek(file_size - offset)
            buffer = f.read(min(remaining_size, buf_size))
            # Ensure buffer is string
            try:
                buffer_str = buffer.decode('utf-8')
            except UnicodeDecodeError:
                # Handle potential decoding errors, e.g., skip or replace
                buffer_str = buffer.decode('utf-8', errors='ignore')

            remaining_size -= buf_size
            lines = buffer_str.splitlines(True) # Keep line endings
            if segment is not None:
                # If the previous chunk starts right after the previous one's end
                if buffer_str[-1] != '\n':
                     # Handle the case where a line is split across chunks
                     lines[-1] += segment
                else:
                    # The segment is a complete line by itself
                    yield segment
            segment = lines[0]
            # Yield lines in reverse order
            for i in range(len(lines) - 1, 0, -1):
                 if lines[i]:
                     yield lines[i]
        # Don't forget the last segment if it exists
        if segment is not None:
            yield segment

class ThreatAnalyzer:
    """
    Class for analyzing logs and detecting potential threats based on subnet activity.
    """

    def __init__(self, rpm_threshold=100, whitelist=None):
        """
        Initializes the threat analyzer.

        Args:
            rpm_threshold (float): Requests per minute threshold to consider activity suspicious.
            whitelist (list): List of additional IPs or subnets that should never be blocked.
        """
        self.rpm_threshold = rpm_threshold
        # Always include localhost addresses in the whitelist
        self.whitelist = ['127.0.0.1', '::1']
        if whitelist:
            # Add any provided whitelist entries, avoiding duplicates
            for item in whitelist:
                if item not in self.whitelist:
                    self.whitelist.append(item)

        # Store data aggregated by subnet: { subnet_obj: {'times': [], 'ips': set()} }
        self.subnet_data = defaultdict(lambda: {'times': [], 'ips': set()})
        self.unified_threats = []
        self.blocked_targets = set() # Keep track of targets blocked in this run

    def load_whitelist_from_file(self, whitelist_file):
        """
        Loads additional whitelist entries from a file, adding them to the existing list.

        Args:
            whitelist_file (str): Path to the file with the whitelist

        Returns:
            int: Number of new entries loaded from the file.
        """
        if not os.path.exists(whitelist_file):
            logger.error(f"Whitelist file not found: {whitelist_file}")
            return 0

        loaded_count = 0
        try:
            with open(whitelist_file, 'r') as f:
                # Filter empty lines and comments
                entries_from_file = [
                    line.strip() for line in f
                    if line.strip() and not line.strip().startswith('#')
                ]
            # Add entries from file if they are not already in the list
            for entry in entries_from_file:
                if entry not in self.whitelist:
                    self.whitelist.append(entry)
                    loaded_count += 1
            logger.info(f"{loaded_count} new entries loaded from {whitelist_file}. Whitelist now has {len(self.whitelist)} total entries.")
            return loaded_count
        except Exception as e:
            logger.error(f"Error loading whitelist from {whitelist_file}: {e}")
            return 0

    def analyze_log_file(self, log_file, start_date=None):
        """
        Analyzes a log file, grouping data by default subnet (/24 or /64).

        Args:
            log_file (str): Path to the log file.
            start_date (datetime, optional): Date from which to analyze.

        Returns:
            int: Number of entries processed.
        """
        total_processed = 0
        log_source = None
        reading_mode = ""

        try:
            if start_date:
                reading_mode = "reverse"
                logger.info(f"Processing log file in reverse (newest first), stopping before {start_date}")
                log_source = _read_lines_reverse(log_file)
            else:
                reading_mode = "forward"
                logger.info("Processing log file forwards (oldest first)")
                log_source = open(log_file, 'r')

            for line in log_source:
                data = parse_log_line(line)
                if data is None:
                    continue

                # Get date and time from the log
                dt_str = data['datetime'].split()[0]
                try:
                    # Attempt to parse with timezone offset if present, otherwise assume naive
                    try:
                        dt = datetime.strptime(dt_str, '%d/%b/%Y:%H:%M:%S %z')
                    except ValueError:
                        dt = datetime.strptime(dt_str, '%d/%b/%Y:%H:%M:%S')
                except ValueError:
                    logger.warning(f"Skipping line due to malformed date: {dt_str}")
                    continue # Skip malformed date

                # Stop if we reached lines older than start_date
                if start_date and dt < start_date:
                    if reading_mode == "reverse":
                        logger.info(f"Reached entry older than {start_date}. Stopping reverse scan.")
                        break
                    else: # Forward reading, just skip
                        continue

                ip = data['ip']
                if is_ip_in_whitelist(ip, self.whitelist):
                    continue

                # Get the default subnet (/24 or /64)
                default_subnet = get_subnet(ip) # Call without masks
                if default_subnet:
                    # Store timestamp and IP within the subnet's data
                    self.subnet_data[default_subnet]['times'].append(dt)
                    self.subnet_data[default_subnet]['ips'].add(ip) # Add IP string to the set
                    total_processed += 1

            logger.info(f"Finished processing. Analyzed {total_processed} log entries grouped into {len(self.subnet_data)} subnets.")
            return total_processed

        except FileNotFoundError:
            logger.error(f"File not found {log_file}")
            raise
        except Exception as e:
            logger.error(f"Error processing log file {log_file}: {e}")
            raise
        finally:
            if reading_mode == "forward" and log_source and not log_source.closed:
                log_source.close()


    def identify_threats(self):
        """
        Identifies threats by calculating metrics directly for each aggregated subnet.

        Returns:
            list: List of detected subnet threats, sorted by total requests descending.
        """
        MIN_DURATION_FOR_RPM_SIGNIFICANCE = 5 # Minimum duration in seconds for RPM to be considered significant
        self.unified_threats = []

        logger.info(f"Calculating metrics for {len(self.subnet_data)} aggregated subnets...")

        # Iterate through aggregated subnet data
        for subnet, details in self.subnet_data.items():
            times = sorted(details['times'])
            total_requests = len(times)
            ip_set = details['ips']
            ip_count = len(ip_set)

            if total_requests == 0:
                continue

            # Calculate metrics directly for the SUBNET
            subnet_rpm = 0
            subnet_time_span = 0
            if total_requests >= 2:
                subnet_time_span = (times[-1] - times[0]).total_seconds()
                if subnet_time_span > 0:
                    subnet_rpm = (total_requests / (subnet_time_span / 60))
            elif total_requests == 1:
                 subnet_rpm = 0
                 subnet_time_span = 0

            # Calculate danger score for the subnet based on its aggregate activity
            subnet_danger_score = calculate_danger_score(subnet_rpm, total_requests, subnet_time_span, MIN_DURATION_FOR_RPM_SIGNIFICANCE)
            # is_suspicious_by_rpm = ( # This wasn't used in the previous version, can be added if needed
            #     subnet_rpm > self.rpm_threshold and
            #     subnet_time_span >= MIN_DURATION_FOR_RPM_SIGNIFICANCE
            # )

            # Threat is always the subnet
            threat_id = subnet
            threat_type = 'subnet'

            # Store the list of IPs involved in details
            threat_details_list = sorted(list(ip_set)) # Sort IPs alphabetically for consistent output

            # Create the threat dictionary
            if threat_id is not None and subnet_danger_score > 0: # Keep check on danger score > 0
                threat = {
                    'type': threat_type,
                    'id': threat_id,
                    'danger_score': subnet_danger_score, # Store aggregate danger score
                    'total_requests': total_requests, # Primary sorting key
                    'subnet_rpm': subnet_rpm,
                    'subnet_time_span': subnet_time_span,
                    'ip_count': ip_count,
                    'details': threat_details_list # Store list of IPs
                }
                self.unified_threats.append(threat)

        # Sort the final list by TOTAL REQUESTS descending
        self.unified_threats = sorted(
            self.unified_threats,
            key=lambda x: x['total_requests'],
            reverse=True
        )

        logger.info(f"Identified {len(self.unified_threats)} subnet threats, sorted by total requests.")
        return self.unified_threats

    def get_top_threats(self, top=10):
        """
        Gets the most dangerous threats.

        Args:
            top (int): Number of threats to return

        Returns:
            list: The top N most dangerous threats
        """
        if not self.unified_threats:
             self.identify_threats() # Ensure threats are identified

        return self.unified_threats[:top]


    def export_results(self, format_type, output_file):
        """
        Exports the results to a file in a specific format.

        Args:
            format_type (str): Export format ('json', 'csv', 'text')
            output_file (str): Path of the output file

        Returns:
            bool: True if export was successful, False otherwise
        """
        if not self.unified_threats:
            # Try identifying threats if list is empty, in case analyze was called but not identify
            self.identify_threats()
            if not self.unified_threats: # Check again
                 logger.warning("No threats identified, cannot export.")
                 return False

        try:
            if format_type.lower() == 'json':
                # Convert ipaddress objects and datetimes to strings for JSON serialization
                json_threats = []
                for threat in self.unified_threats:
                    json_threat = threat.copy()
                    json_threat['id'] = str(json_threat['id']) # Convert network object ID
                    # Details are now just a list of IP strings, no datetimes to convert
                    # json_threat['details'] = threat['details'] # Already a list of strings
                    json_threats.append(json_threat)
                # ... (rest of JSON export) ...
                with open(output_file, 'w') as f:
                    json.dump(json_threats, f, indent=2)

            elif format_type.lower() == 'csv':
                 # Define fields - include common fields
                 fieldnames = [
                     'type', 'id', 'danger_score', 'total_requests',
                     'subnet_rpm', 'subnet_time_span', 'ip_count'
                 ]
                 with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()

                    for threat in self.unified_threats:
                        # Create a simplified version for CSV, converting ID to string
                        csv_threat = threat.copy()
                        csv_threat['id'] = str(csv_threat['id'])
                        writer.writerow(csv_threat) # extrasaction='ignore' handles missing fields

            elif format_type.lower() == 'text':
                 with open(output_file, 'w') as f:
                     f.write(f"=== {len(self.unified_threats)} SUBNET THREATS DETECTED (Sorted by Total Requests) ===\n")
                     for i, threat in enumerate(self.unified_threats, 1):
                         target_id_str = str(threat['id'])
                         threat_label = "Subnet"
                         danger_str = f"Danger: {threat['danger_score']:.2f}"
                         rpm_str = f", ~{threat.get('subnet_rpm', 0):.2f} agg RPM" if threat.get('subnet_rpm', 0) > 0 else ""
                         ip_count_str = f"{threat['ip_count']} IP" if threat['ip_count'] == 1 else f"{threat['ip_count']} IPs"

                         f.write(f"\n#{i} {threat_label}: {target_id_str} - Requests: {threat['total_requests']} ({ip_count_str}, {danger_str}{rpm_str})\n")

                         # Show list of IPs involved (limited)
                         if threat['details']:
                             max_details_to_show = 5 # Show a few more IPs if available
                             ips_to_show = threat['details'][:max_details_to_show]
                             f.write(f"  -> IPs involved: {', '.join(ips_to_show)}")
                             if threat['ip_count'] > max_details_to_show:
                                 f.write(f", ... ({threat['ip_count'] - max_details_to_show} more)")
                             f.write("\n") # Newline after IP list

            else:
                logger.error(f"Unsupported export format: {format_type}")
                return False

            logger.info(f"Results exported to {output_file} in {format_type} format")
            return True

        except Exception as e:
            logger.error(f"Error exporting results: {e}")
            # Log traceback for debugging if needed
            # import traceback
            # logger.error(traceback.format_exc())
            return False