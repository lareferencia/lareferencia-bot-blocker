#!/usr/bin/env python3
"""
Module for analysis and threat detection based on server logs.
Strategy: Calculate per-IP metrics, then group by subnet (/24 or /64)
to classify as single-IP or multi-IP (subnet) threat with details.
"""
import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta
import logging
import json
import csv
import os
import io

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
    Class for analyzing logs and detecting potential threats based on IP and subnet activity.
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

        # Store data per IP again
        self.ip_data = defaultdict(lambda: {'times': [], 'urls': [], 'useragents': []})
        # We will group by subnet during identify_threats
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
        Analyzes a log file, storing data per IP address.

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

                # Store data per IP
                self.ip_data[ip]['times'].append(dt)
                self.ip_data[ip]['urls'].append(data['request'])
                self.ip_data[ip]['useragents'].append(data['useragent'])
                total_processed += 1

            logger.info(f"Finished processing. Analyzed {total_processed} log entries for {len(self.ip_data)} unique IPs.")
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
        Identifies threats by calculating per-IP metrics, then grouping by subnet
        to classify as single-IP or multi-IP (subnet) threats with details.

        Returns:
            list: List of detected threats (IPs or Subnets), sorted by danger score.
        """
        MIN_DURATION_FOR_RPM_SIGNIFICANCE = 5 # Minimum duration in seconds for RPM to be considered significant
        self.unified_threats = []
        # Structure to hold aggregated subnet info:
        # { subnet_obj: {'ips': [ip_details_dict], 'all_times': [], 'total_requests': 0} }
        subnet_aggregation = defaultdict(lambda: {'ips': [], 'all_times': [], 'total_requests': 0})

        logger.info(f"Calculating metrics for {len(self.ip_data)} unique IPs...")

        # 1. Calculate metrics per IP and group by subnet
        for ip, info in self.ip_data.items():
            times = sorted(info['times'])
            total_requests = len(times)
            if total_requests == 0:
                continue

            # Calculate metrics for this IP
            ip_rpm = 0
            ip_time_span = 0
            if total_requests >= 2:
                ip_time_span = (times[-1] - times[0]).total_seconds()
                if ip_time_span > 0:
                    ip_rpm = (total_requests / (ip_time_span / 60))
            elif total_requests == 1:
                 ip_rpm = 0
                 ip_time_span = 0

            has_suspicious_ua = False # Placeholder
            suspicious_ua = ""      # Placeholder
            ip_danger_score = calculate_danger_score(ip_rpm, total_requests, has_suspicious_ua)
            is_suspicious_by_rpm = (
                ip_rpm > self.rpm_threshold and
                ip_time_span >= MIN_DURATION_FOR_RPM_SIGNIFICANCE
            )
            first_seen = times[0] if times else None
            last_seen = times[-1] if times else None

            ip_details_dict = {
                'ip': ip,
                'rpm': ip_rpm,
                'total_requests': total_requests,
                'time_span': ip_time_span,
                'danger_score': ip_danger_score,
                'is_suspicious_by_rpm': is_suspicious_by_rpm,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'has_suspicious_ua': has_suspicious_ua, # Add placeholders back
                'suspicious_ua': suspicious_ua
            }

            # Get the default subnet for this IP
            default_subnet = get_subnet(ip)
            if default_subnet:
                subnet_aggregation[default_subnet]['ips'].append(ip_details_dict)
                subnet_aggregation[default_subnet]['all_times'].extend(times)
                subnet_aggregation[default_subnet]['total_requests'] += total_requests

        logger.info(f"Aggregating results into {len(subnet_aggregation)} subnets...")

        # 2. Create threats based on subnet aggregation
        for subnet, agg_details in subnet_aggregation.items():
            ips_in_subnet = agg_details['ips']
            ip_count = len(ips_in_subnet)
            subnet_total_requests = agg_details['total_requests']
            all_times_sorted = sorted(agg_details['all_times'])

            if ip_count == 0 or subnet_total_requests == 0:
                continue

            # Calculate aggregate metrics for the subnet
            subnet_total_danger = sum(ip['danger_score'] for ip in ips_in_subnet)
            subnet_rpm = 0
            subnet_time_span = 0
            if len(all_times_sorted) >= 2:
                 subnet_time_span = (all_times_sorted[-1] - all_times_sorted[0]).total_seconds()
                 if subnet_time_span > 0:
                     subnet_rpm = (subnet_total_requests / (subnet_time_span / 60))

            threat_id = None
            threat_type = None
            threat_details_list = []
            threat_danger_score = 0

            if ip_count == 1:
                # Single IP threat
                ip_detail = ips_in_subnet[0]
                try:
                    threat_id = ipaddress.ip_network(ip_detail['ip']) # /32 or /128
                    threat_type = 'ip'
                    threat_danger_score = ip_detail['danger_score'] # Use IP's score
                    threat_details_list = [ip_detail] # Detail is the IP itself
                except ValueError:
                    logger.warning(f"Could not create network object for single IP: {ip_detail['ip']}")
                    continue
            else:
                # Multi-IP subnet threat
                threat_id = subnet # /24 or /64
                threat_type = 'subnet'
                threat_danger_score = subnet_total_danger # Use aggregate score
                # Sort IPs within the subnet by their individual danger score for details
                threat_details_list = sorted(ips_in_subnet, key=lambda x: x['danger_score'], reverse=True)

            # Create the threat dictionary
            if threat_id is not None and threat_danger_score > 0:
                threat = {
                    'type': threat_type,
                    'id': threat_id,
                    'danger_score': threat_danger_score, # Use specific score (IP or aggregate)
                    'total_requests': subnet_total_requests, # Always aggregate total requests
                    'subnet_rpm': subnet_rpm, # Aggregate RPM
                    'subnet_time_span': subnet_time_span, # Aggregate time span
                    'ip_count': ip_count,
                    'details': threat_details_list # Details of the single IP or sorted list for subnet
                }
                self.unified_threats.append(threat)

        # 3. Sort the final list by danger score
        self.unified_threats = sorted(
            self.unified_threats,
            key=lambda x: x['danger_score'],
            reverse=True
        )

        logger.info(f"Identified {len(self.unified_threats)} threats (IPs/Subnets), sorted by danger score.")
        return self.unified_threats

    # ... (get_top_threats remains the same) ...
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


    # ... (export_results needs minor adjustments for potential 'ip' type and details format) ...
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
                    # Convert datetimes in details if they exist
                    if 'details' in json_threat:
                        for detail in json_threat['details']:
                            if 'first_seen' in detail and detail['first_seen']:
                                detail['first_seen'] = detail['first_seen'].isoformat()
                            if 'last_seen' in detail and detail['last_seen']:
                                detail['last_seen'] = detail['last_seen'].isoformat()
                    json_threats.append(json_threat)

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
                 # Basic text output similar to console output but to file
                 with open(output_file, 'w') as f:
                     f.write(f"=== {len(self.unified_threats)} THREATS DETECTED ===\n")
                     for i, threat in enumerate(self.unified_threats, 1):
                         target_id_str = str(threat['id'])
                         threat_label = "IP" if threat['type'] == 'ip' else "Subnet"
                         rpm_str = f", ~{threat.get('subnet_rpm', 0):.2f} RPM" if threat.get('subnet_rpm', 0) > 0 else ""
                         ip_count_str = f"{threat['ip_count']} IP" if threat['ip_count'] == 1 else f"{threat['ip_count']} IPs"

                         f.write(f"\n#{i} {threat_label}: {target_id_str} - Danger: {threat['danger_score']:.2f} ({ip_count_str}, {threat['total_requests']} reqs{rpm_str})\n")
                         # Optionally show details for single IP threats if populated
                         if threat['type'] == 'ip' and threat['details']:
                             ip_detail = threat['details'][0]
                             rpm_flag_str = "*" if ip_detail.get('is_suspicious_by_rpm', False) else ""
                             detail_rpm_str = f"~{ip_detail['rpm']:.2f} rpm{rpm_flag_str}" if ip_detail['rpm'] > 0 else "RPM N/A"
                             # ua_str = f" | UA: {ip_detail.get('suspicious_ua', '')}" if ip_detail.get('has_suspicious_ua', False) else "" # If UA added later
                             f.write(f"  -> Activity Metrics: {ip_detail['total_requests']} reqs, {detail_rpm_str}\n")
                         elif threat['type'] == 'subnet':
                             # Could add logic here to fetch and display top IPs from self.subnet_data if needed
                             f.write(f"  -> Involves {threat['ip_count']} unique IPs in {target_id_str}.\n")


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