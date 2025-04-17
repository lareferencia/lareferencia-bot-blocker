#!/usr/bin/env python3
"""
Module for analysis and threat detection based on server logs.
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

# Helper function for efficient reverse reading
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
    Class for analyzing logs and detecting potential threats.
    """
    
    def __init__(self, rpm_threshold=100, whitelist=None, subnet_masks_ipv4=None, subnet_masks_ipv6=None):
        """
        Initializes the threat analyzer.
        
        Args:
            rpm_threshold (float): Requests per minute threshold to consider an IP suspicious
            whitelist (list): List of IPs or subnets that should never be blocked
            subnet_masks_ipv4 (list[int]): List of IPv4 subnet masks to analyze (e.g., [24, 16])
            subnet_masks_ipv6 (list[int]): List of IPv6 subnet masks to analyze (e.g., [64])
        """
        self.rpm_threshold = rpm_threshold
        self.whitelist = whitelist or []
        # Use provided masks or defaults
        self.subnet_masks_ipv4 = subnet_masks_ipv4 if subnet_masks_ipv4 is not None else [24]
        self.subnet_masks_ipv6 = subnet_masks_ipv6 if subnet_masks_ipv6 is not None else [64]
        # Ensure masks are sorted from most specific to least specific (largest number first)
        self.subnet_masks_ipv4.sort(reverse=True)
        self.subnet_masks_ipv6.sort(reverse=True)
        self.ip_data = defaultdict(lambda: {'times': [], 'urls': [], 'useragents': []})
        self.unified_threats = []
        self.blocked_targets = set()
        
    def load_whitelist_from_file(self, whitelist_file):
        """
        Loads a whitelist from a file.
        
        Args:
            whitelist_file (str): Path to the file with the whitelist
            
        Returns:
            int: Number of entries loaded
        """
        if not os.path.exists(whitelist_file):
            logger.error(f"Whitelist file not found: {whitelist_file}")
            return 0
            
        try:
            with open(whitelist_file, 'r') as f:
                # Filter empty lines and comments
                self.whitelist = [
                    line.strip() for line in f 
                    if line.strip() and not line.strip().startswith('#')
                ]
            logger.info(f"Whitelist loaded with {len(self.whitelist)} entries from {whitelist_file}")
            return len(self.whitelist)
        except Exception as e:
            logger.error(f"Error loading whitelist from {whitelist_file}: {e}")
            return 0
    
    def analyze_log_file(self, log_file, start_date=None):
        """
        Analyzes a complete log file. Reads forwards if start_date is None,
        reads backwards from the end if start_date is provided, stopping
        when lines older than start_date are found.
        
        Args:
            log_file (str): Path to the log file
            start_date (datetime, optional): Date from which to analyze
            
        Returns:
            int: Number of entries processed
        """
        total_processed = 0
        try:
            if start_date:
                logger.info(f"Processing log file in reverse (newest first), stopping before {start_date}")
                # Process in reverse, stopping at start_date
                for line in _read_lines_reverse(log_file):
                    data = parse_log_line(line)
                    if data is None:
                        continue
                        
                    # Get date and time from the log
                    dt_str = data['datetime'].split()[0]
                    try:
                        dt = datetime.strptime(dt_str, '%d/%b/%Y:%H:%M:%S')
                    except ValueError:
                        continue # Skip malformed date
                        
                    # Stop if we reached lines older than start_date
                    if dt < start_date:
                        logger.info(f"Reached entry older than {start_date}. Stopping reverse scan.")
                        break 
                        
                    ip = data['ip']
                    if is_ip_in_whitelist(ip, self.whitelist):
                        continue
                        
                    self.ip_data[ip]['times'].append(dt)
                    self.ip_data[ip]['urls'].append(data['request'])
                    self.ip_data[ip]['useragents'].append(data['useragent'])
                    total_processed += 1
            else:
                logger.info("Processing log file forwards (oldest first)")
                # Process forwards, reading the whole file
                with open(log_file, 'r') as f:
                    for line in f:
                        data = parse_log_line(line)
                        if data is None:
                            continue
                            
                        # Get date and time from the log
                        dt_str = data['datetime'].split()[0]
                        try:
                            dt = datetime.strptime(dt_str, '%d/%b/%Y:%H:%M:%S')
                        except ValueError:
                            continue # Skip malformed date
                            
                        ip = data['ip']
                        if is_ip_in_whitelist(ip, self.whitelist):
                            continue
                            
                        self.ip_data[ip]['times'].append(dt)
                        self.ip_data[ip]['urls'].append(data['request'])
                        self.ip_data[ip]['useragents'].append(data['useragent'])
                        total_processed += 1
                        
            logger.info(f"Finished processing. Analyzed {total_processed} log entries within the specified time frame.")
            return total_processed
            
        except FileNotFoundError:
            logger.error(f"File not found {log_file}")
            raise
        except Exception as e:
            logger.error(f"Error processing log file {log_file}: {e}")
            raise
    
    def identify_threats(self):
        """
        Identifies threats based on accumulated data, grouping IPs by multiple subnet levels,
        sorts by danger score, and then filters to avoid reporting overlapping subnets.

        Returns:
            list: List of filtered, non-overlapping detected threats, sorted by danger score descending.
        """
        # ... (Step 1: Grouping remains the same) ...
        MIN_DURATION_FOR_RPM_SIGNIFICANCE = 5 # Minimum duration in seconds for RPM to be considered significant

        # Step 1: Group all IPs by multiple subnet levels and calculate metrics
        subnet_details = defaultdict(lambda: {'ips': {}, 'total_requests': 0, 'all_times': []})
        logger.info(f"Analyzing IPs and grouping by subnets (IPv4: {self.subnet_masks_ipv4}, IPv6: {self.subnet_masks_ipv6})...")

        processed_ips = 0
        for ip, info in self.ip_data.items():
            processed_ips += 1
            times = sorted(info['times'])
            total_requests = len(times)
            if total_requests == 0:
                continue

            # Calculate RPM, time_span, danger_score, is_suspicious_by_rpm for the IP
            # ... (calculation logic as before) ...
            rpm = 0
            time_span = 0
            if total_requests >= 2:
                time_span = (times[-1] - times[0]).total_seconds()
                if time_span > 0:
                    rpm = (total_requests / (time_span / 60))
            elif total_requests == 1:
                 rpm = 0
                 time_span = 0
            has_suspicious_ua = False # Placeholder
            suspicious_ua = ""      # Placeholder
            danger_score = calculate_danger_score(rpm, total_requests, has_suspicious_ua)
            is_suspicious_by_rpm = (
                rpm > self.rpm_threshold and
                time_span >= MIN_DURATION_FOR_RPM_SIGNIFICANCE
            )
            first_seen = times[0] if times else None
            last_seen = times[-1] if times else None

            # Get the list of subnets this IP belongs to for all specified masks
            subnets = get_subnet(ip, subnet_masks_ipv4=self.subnet_masks_ipv4, subnet_masks_ipv6=self.subnet_masks_ipv6)

            if subnets:
                ip_info = {
                    'ip': ip, 'rpm': rpm, 'total_requests': total_requests, 'time_span': time_span,
                    'has_suspicious_ua': has_suspicious_ua, 'suspicious_ua': suspicious_ua,
                    'danger_score': danger_score, 'is_suspicious_by_rpm': is_suspicious_by_rpm,
                    'first_seen': first_seen, 'last_seen': last_seen
                }
                # Add this IP's info and requests to *each* subnet level it belongs to
                for subnet in subnets:
                    if ip not in subnet_details[subnet]['ips']:
                         subnet_details[subnet]['ips'][ip] = ip_info
                         # Add timestamps only once per IP per subnet level
                         if first_seen: subnet_details[subnet]['all_times'].append(first_seen)
                         if last_seen: subnet_details[subnet]['all_times'].append(last_seen)
                    # Accumulate total requests for the subnet level
                    subnet_details[subnet]['total_requests'] += total_requests
        logger.info(f"Processed {processed_ips} unique IPs into {len(subnet_details)} subnet views.")


        # ... (Step 2: Consolidating initial threats remains the same) ...
        initial_threats = []
        logger.info(f"Consolidating initial threats for {len(subnet_details)} subnet views...")

        for subnet, details in subnet_details.items():
            ips_in_subnet = list(details['ips'].values())
            subnet_total_danger = sum(info['danger_score'] for info in ips_in_subnet)
            subnet_ip_count = len(ips_in_subnet)
            subnet_total_requests = details['total_requests'] # Use accumulated total

            # Calculate aggregate time span and RPM for the subnet
            subnet_rpm = 0
            subnet_time_span = 0
            all_times = details['all_times']
            if len(all_times) >= 2:
                first_subnet_time = min(all_times)
                last_subnet_time = max(all_times)
                subnet_time_span = (last_subnet_time - first_subnet_time).total_seconds()
                if subnet_time_span > 0:
                    subnet_rpm = (subnet_total_requests / (subnet_time_span / 60))

            # Create a threat entry if there's any danger score associated
            if subnet_total_danger > 0:
                threat = {
                    'type': 'subnet', 'id': subnet, 'danger_score': subnet_total_danger,
                    'total_requests': subnet_total_requests, 'subnet_rpm': subnet_rpm,
                    'subnet_time_span': subnet_time_span, 'ip_count': subnet_ip_count,
                    'details': sorted(ips_in_subnet, key=lambda x: x['danger_score'], reverse=True)
                }
                initial_threats.append(threat)


        # Step 3: Sort the initial threats list purely by danger score (highest first)
        initial_threats_sorted = sorted(
            initial_threats,
            key=lambda x: x['danger_score'],
            reverse=True
        )
        logger.info(f"Generated and sorted {len(initial_threats_sorted)} initial threat entries by danger score.")

        # Step 4: Filter out overlapping subnets, keeping the highest-ranked ones encountered first
        self.unified_threats = []
        covered_networks = set() # Keep track of networks already added to the final list
        logger.info("Filtering overlapping subnet threats (keeping highest score first)...")

        for threat in initial_threats_sorted:
            current_network = threat['id']
            is_subsumed = False
            is_supernet_of_selected = False

            # Check if current_network is already covered by or equal to a network in the final list
            for selected_threat in self.unified_threats:
                selected_network = selected_threat['id']
                try:
                    if current_network.subnet_of(selected_network) or current_network == selected_network:
                        is_subsumed = True
                        logger.debug(f"Skipping {current_network} (Score: {threat['danger_score']:.2f}): Subsumed by already selected {selected_network} (Score: {selected_threat['danger_score']:.2f})")
                        break
                    # Check if current_network is a supernet of an already selected network
                    if selected_network.subnet_of(current_network):
                        is_supernet_of_selected = True
                        logger.debug(f"Note: {current_network} (Score: {threat['danger_score']:.2f}) is a supernet of already selected {selected_network} (Score: {selected_threat['danger_score']:.2f})")
                        # We might still add the supernet if it's not subsumed by another,
                        # but this flag could be used for more complex logic if needed later.
                        # For now, just note it. We prioritize adding the highest score first.
                except (TypeError, AttributeError):
                    continue

            if not is_subsumed:
                # This threat has the highest score among overlapping candidates encountered so far
                # and is not contained within an already selected threat. Add it.
                self.unified_threats.append(threat)
                logger.debug(f"Selected threat: {current_network} (Score: {threat['danger_score']:.2f}).")
                # Note: We don't need covered_networks set with this logic,
                # as we directly compare against self.unified_threats as it builds.

        # The final list self.unified_threats is already sorted by danger score due to the initial sort.
        logger.info(f"Identified {len(self.unified_threats)} final, non-overlapping subnet threats, sorted by danger score.")
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
            self.identify_threats()
            
        return self.unified_threats[:top]
        
    def export_results(self, format_type, output_file):
        """
        Exports the results to a file in a specific format.
        
        Args:
            format_type (str): Export format ('json', 'csv')
            output_file (str): Path of the output file
            
        Returns:
            bool: True if export was successful, False otherwise
        """
        if not self.unified_threats:
            logger.warning("No threats to export")
            return False
            
        try:
            if format_type.lower() == 'json':
                # Convert ipaddress objects to strings for JSON serialization
                json_threats = []
                for threat in self.unified_threats:
                    json_threat = threat.copy()
                    json_threat['id'] = str(json_threat['id'])
                    if 'details' in json_threat:
                        json_threat['details'] = json_threat['details']
                    json_threats.append(json_threat)
                    
                with open(output_file, 'w') as f:
                    json.dump(json_threats, f, indent=2)
                    
            elif format_type.lower() == 'csv':
                with open(output_file, 'w', newline='') as f:
                    # Define fields by threat type
                    fieldnames = ['type', 'id', 'danger_score', 'total_requests']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for threat in self.unified_threats:
                        # Create a simplified version for CSV
                        csv_threat = {
                            'type': threat['type'],
                            'id': str(threat['id']),
                            'danger_score': threat['danger_score'],
                            'total_requests': threat['total_requests']
                        }
                        writer.writerow(csv_threat)
            else:
                logger.error(f"Unsupported export format: {format_type}")
                return False
                
            logger.info(f"Results exported to {output_file} in {format_type} format")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting results: {e}")
            return False