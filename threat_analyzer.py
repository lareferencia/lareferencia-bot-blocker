#!/usr/bin/env python3
"""
Module for analysis and threat detection using native Python data structures.
Groups logs by IP, calculates metrics, then aggregates by subnet.
"""
import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import logging
import json
import csv
import os
from ipaddress import ip_network, IPv4Network, IPv6Network
import importlib # Needed for dynamic strategy loading
import time # Ensure time is imported

# Import from parser
from parser import (
    stream_log_entries, get_subnet, is_ip_in_whitelist
)

# Logger for this module
logger = logging.getLogger('botstats.analyzer')

class ThreatAnalyzer:
    """
    Analyzes log data using native Python data structures to detect threats based on IP and subnet activity.
    """

    def __init__(self, whitelist=None):
        """
        Initializes the threat analyzer.

        Args:
            whitelist (list): List of additional IPs or subnets that should never be blocked.
        """
        self.whitelist = ['127.0.0.1', '::1']
        if whitelist:
            for item in whitelist:
                if item not in self.whitelist:
                    self.whitelist.append(item)

        # Native data structures for analysis
        # self.log_data removed in streaming refactor
        self.ip_metrics = None        # Metrics calculated per IP (dict)
        self.subnet_metrics = None    # Metrics aggregated per subnet (dict)

        # Final output list (compatible with previous structure)
        self.unified_threats = []

    def load_whitelist_from_file(self, whitelist_file):
        """Loads whitelist from file."""
        # ... (Implementation unchanged) ...
        if not os.path.exists(whitelist_file):
            logger.error(f"Whitelist file not found: {whitelist_file}")
            return 0
        loaded_count = 0
        try:
            with open(whitelist_file, 'r') as f:
                entries_from_file = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            for entry in entries_from_file:
                if entry not in self.whitelist:
                    self.whitelist.append(entry)
                    loaded_count += 1
            logger.info(f"{loaded_count} new entries loaded from {whitelist_file}. Whitelist now has {len(self.whitelist)} total entries.")
            return loaded_count
        except Exception as e:
            logger.error(f"Error loading whitelist from {whitelist_file}: {e}")
            return 0


    def analyze_log_file(self, log_file, start_date_utc=None):
        """
        Streams log data, applying filters and calculating IP metrics on the fly.
        Does NOT store raw log data in memory.

        Args:
            log_file (str): Path to the log file.
            start_date_utc (datetime, optional): Aware UTC datetime filter.

        Returns:
            int: Number of entries processed, or -1 on error.
        """
        logger.info("Streaming and analyzing log data...")
        
        # Initialize metrics storage
        self.ip_metrics = {}
        processed_count = 0
        
        try:
            # Get the generator
            log_stream = stream_log_entries(log_file, start_date_utc, self.whitelist)
            
            if log_stream is None:
                logger.error("Failed to initialize log stream.")
                return -1

            for entry in log_stream:
                processed_count += 1
                ip = entry['ip']
                timestamp = entry['timestamp']
                
                # Calculate/Update IP metrics incrementally
                if ip not in self.ip_metrics:
                    self.ip_metrics[ip] = {
                        'total_requests': 0,
                        'first_seen': timestamp,
                        'last_seen': timestamp,
                        'subnet': get_subnet(ip)
                    }
                
                metrics = self.ip_metrics[ip]
                metrics['total_requests'] += 1
                
                # Update timestamps
                if timestamp < metrics['first_seen']:
                    metrics['first_seen'] = timestamp
                if timestamp > metrics['last_seen']:
                    metrics['last_seen'] = timestamp

                # Log progress periodically
                if processed_count % 50000 == 0:
                     logger.info(f"Analyzed {processed_count} entries...")

            # Finalize metrics (calculate time_span)
            for ip, metrics in self.ip_metrics.items():
                time_span = (metrics['last_seen'] - metrics['first_seen']).total_seconds()
                metrics['time_span_seconds'] = max(0, time_span)

            if processed_count == 0:
                logger.warning("No valid log entries found after filtering.")
                return 0

            logger.info(f"Successfully analyzed {processed_count} log entries. Metrics calculated for {len(self.ip_metrics)} IPs.")
            return processed_count

        except Exception as e:
            logger.error(f"Error during log analysis: {e}", exc_info=True)
            return -1

    def _calculate_ip_metrics(self, analysis_duration_seconds=None):
        """Deprecated. Metrics are now calculated in analyze_log_file."""
        logger.warning("_calculate_ip_metrics is deprecated and should not be called directly.")
        return True

    def _aggregate_subnet_metrics(self, analysis_duration_seconds=None):
        """Aggregates IP metrics by subnet using native Python data structures."""
        if self.ip_metrics is None or not self.ip_metrics:
            logger.warning("IP metrics not available. Cannot aggregate subnet metrics.")
            return False

        logger.info("Aggregating metrics by subnet...")

        # Group IP metrics by subnet
        subnet_groups = defaultdict(list)
        for ip, metrics in self.ip_metrics.items():
            subnet = metrics.get('subnet')
            if subnet:
                subnet_groups[subnet].append(metrics)

        # Aggregate metrics for each subnet
        self.subnet_metrics = {}
        for subnet, ip_list in subnet_groups.items():
            # Sum total requests
            total_requests = sum(m['total_requests'] for m in ip_list)
            
            # Count unique IPs
            ip_count = len(ip_list)
            
            # Calculate subnet time span (min first_seen to max last_seen)
            first_seen_values = [m['first_seen'] for m in ip_list]
            last_seen_values = [m['last_seen'] for m in ip_list]
            subnet_first_seen = min(first_seen_values)
            subnet_last_seen = max(last_seen_values)
            subnet_time_span = (subnet_last_seen - subnet_first_seen).total_seconds()
            subnet_time_span = max(0, subnet_time_span)

            # Calculate requests per minute over the entire analysis window
            if analysis_duration_seconds and analysis_duration_seconds > 0:
                subnet_req_per_min_window = total_requests / (analysis_duration_seconds / 60.0)
            else:
                subnet_req_per_min_window = 0.0

            self.subnet_metrics[subnet] = {
                'total_requests': total_requests,
                'ip_count': ip_count,
                'subnet_time_span': subnet_time_span,
                'subnet_req_per_min_window': subnet_req_per_min_window
            }

        logger.info(f"Finished aggregating metrics for {len(self.subnet_metrics)} subnets.")
        return True

    def identify_threats(self,
                         strategy_name,
                         effective_min_requests,
                         shared_context_params,
                         config):
        """
        Orchestrates the aggregation by subnet,
        strategy application, and formatting the final threat list.
        Assumes analyze_log_file has already populated self.ip_metrics.
        """
        # --- Extract necessary parameters from shared_context_params ---
        analysis_duration_seconds = shared_context_params.get('analysis_duration_seconds', 0)

        # --- Ensure IP metrics are available ---
        if self.ip_metrics is None:
             logger.error("IP metrics not calculated. Call analyze_log_file first.")
             return None

        # --- Aggregate Subnet Metrics ---
        start_time = time.time()
        if not self._aggregate_subnet_metrics(analysis_duration_seconds=analysis_duration_seconds):
            logger.error("Failed during subnet metrics aggregation.")
            return None
        logger.info(f"Subnet metrics aggregation took {time.time() - start_time:.2f} seconds.")

        # --- Load Strategy ---
        try:
            strategy_module = importlib.import_module(f"strategies.{strategy_name}")
            strategy_instance = strategy_module.Strategy()
            logger.info(f"Successfully loaded strategy: {strategy_name}")
        except ImportError:
            logger.error(f"Could not load strategy module: strategies.{strategy_name}.py")
            return None
        except AttributeError:
            logger.error(f"Strategy module strategies.{strategy_name}.py does not contain a 'Strategy' class.")
            return None
        except Exception as e:
             logger.error(f"An unexpected error occurred loading strategy '{strategy_name}': {e}", exc_info=True)
             return None

        # --- Calculate Maximums from self.subnet_metrics for strategy context ---
        strategy_context = shared_context_params.copy()

        if self.subnet_metrics:
            logger.debug("Calculating maximums from subnet_metrics for strategy context...")
            metrics_for_max_calc = {
                'total_requests': 0,
                'ip_count': 0,
                'subnet_time_span': 0.0,
                'subnet_req_per_min_window': 0.0
            }
            for metric_key, default_value in metrics_for_max_calc.items():
                values = [m.get(metric_key, default_value) for m in self.subnet_metrics.values()]
                if values:
                    max_val = max(values)
                    strategy_context[f'max_{metric_key}'] = max_val
                else:
                    strategy_context[f'max_{metric_key}'] = default_value
            logger.debug(f"Strategy context enriched with maximums: {strategy_context}")
        else:
            logger.warning("Subnet metrics empty. Strategies will receive initial shared_context_params without calculated maximums.")
            for metric_key, default_value in {
                'max_total_requests': 0, 'max_ip_count': 0, 'max_subnet_time_span': 0.0,
                'max_subnet_req_per_min_window': 0.0
            }.items():
                 if metric_key not in strategy_context:
                     strategy_context[metric_key] = default_value

        # --- IP Details collection removed for simplification ---

        # --- Apply strategy and build results list ---
        results = []
        if not self.subnet_metrics:
             logger.warning("Subnet metrics empty. Skipping strategy application.")
        else:
             logger.info(f"Applying '{strategy_name}' strategy to {len(self.subnet_metrics)} subnets...")
             start_time = time.time()
             for subnet_obj, metrics in self.subnet_metrics.items():
                 threat_data = metrics.copy()
                 threat_data['id'] = subnet_obj

                 # Calculate score and block decision using the strategy
                 score, should_block, reason = strategy_instance.calculate_threat_score_and_block(
                     threat_data=threat_data,
                     config=config,
                     effective_min_requests=effective_min_requests,
                     shared_context_params=strategy_context
                 )

                 # Build the final dictionary for this threat
                 threat_result = {
                     'type': 'subnet',
                     'id': subnet_obj,
                     'total_requests': int(threat_data.get('total_requests', 0)),
                     'ip_count': int(threat_data.get('ip_count', 0)),
                     'subnet_time_span': round(threat_data.get('subnet_time_span', 0), 2),
                     'subnet_req_per_min_window': round(threat_data.get('subnet_req_per_min_window', 0), 2),
                     'strategy_score': score,
                     'should_block': should_block,
                     'block_reason': reason
                 }
                 results.append(threat_result)
             logger.info(f"Strategy application took {time.time() - start_time:.2f} seconds.")

        # --- Sort Results ---
        results.sort(key=lambda x: x.get('strategy_score', 0), reverse=True)

        # --- Store final list ---
        self.unified_threats = results

        logger.info(f"Threat identification complete. Found {len(self.unified_threats)} subnet threats.")
        return self.unified_threats

    def export_results(self, format_type, output_file, config=None, threats=None):
        """
        Exports the identified threats to a specified format using native Python.
        Accepts the primary threats list. Handles data type serialization.
        """
        if threats is None:
             threats = self.unified_threats
             if not threats:
                 logger.error("No threat data available (checked input and self.unified_threats). Cannot export.")
                 return False

        logger.info(f"Preparing to export {len(threats)} threats to {output_file} in {format_type} format.")

        # Convert threat data for export (handle ipaddress, datetime types)
        export_data = []
        for threat in threats:
             threat_copy = threat.copy()
             # Convert specific fields
             for key, value in threat_copy.items():
                 if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network, ipaddress.IPv4Address, ipaddress.IPv6Address)):
                     threat_copy[key] = str(value)
                 elif isinstance(value, datetime):
                     # Ensure timezone info is handled correctly if present
                     if value.tzinfo:
                         threat_copy[key] = value.isoformat()
                     else:
                         threat_copy[key] = value.replace(tzinfo=timezone.utc).isoformat()
             export_data.append(threat_copy)

        try:
            # Column order for better readability
            cols_order = [
                'id', 'strategy_score', 'should_block', 'block_reason',
                'total_requests', 'ip_count',
                'subnet_req_per_min_window',
                'subnet_time_span'
            ]

            if format_type == 'csv':
                with open(output_file, 'w', newline='') as f:
                    if export_data:
                        # Get all unique keys from all dicts
                        all_keys = set()
                        for item in export_data:
                            all_keys.update(item.keys())
                        
                        # Create ordered fieldnames
                        fieldnames = [k for k in cols_order if k in all_keys]
                        fieldnames.extend([k for k in sorted(all_keys) if k not in fieldnames])
                        
                        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_NONNUMERIC)
                        writer.writeheader()
                        
                        for row in export_data:
                            # Convert lists to JSON strings for CSV compatibility
                            row_copy = row.copy()
                            for key, value in row_copy.items():
                                if isinstance(value, list):
                                    row_copy[key] = json.dumps(value)
                            writer.writerow(row_copy)
                            
            elif format_type == 'json':
                with open(output_file, 'w') as f:
                    json.dump(export_data, f, indent=4, default=str)
                    
            elif format_type == 'text':
                with open(output_file, 'w') as f:
                    if export_data:
                        # Simple text table format
                        for i, threat in enumerate(export_data):
                            f.write(f"\n--- Threat {i+1} ---\n")
                            for key, value in threat.items():
                                if key != 'details' or not value:  # Skip empty details
                                    f.write(f"{key}: {value}\n")
                                elif key == 'details':
                                    f.write(f"{key}:\n")
                                    for detail in value:
                                        f.write(f"  {detail}\n")
            else:
                logger.error(f"Unsupported export format: {format_type}")
                return False
            return True
        except Exception as e:
            logger.error(f"Failed to export results to {output_file}: {e}", exc_info=True)
            return False

    def get_threats_df(self):
        """Returns the identified threats as a dictionary indexed by subnet string.
        Kept for backward compatibility but now returns a dict instead of DataFrame."""
        if not self.unified_threats:
            logger.warning("No threats identified or stored in unified_threats list.")
            return {}
        
        try:
            # Convert list to dict indexed by subnet ID string
            threats_dict = {}
            for threat in self.unified_threats:
                subnet_id = threat.get('id')
                if subnet_id:
                    threats_dict[str(subnet_id)] = threat
            return threats_dict
        except Exception as e:
            logger.error(f"Error converting unified_threats list to dict: {e}", exc_info=True)
            return {}