#!/usr/bin/env python3
"""
Module for analysis and threat detection using Pandas DataFrames.
Groups logs by IP, calculates metrics, then aggregates by subnet.
"""
import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import logging
import json
import csv
import os
import pandas as pd
import numpy as np

# Import from log_parser
from log_parser import (
    load_log_into_dataframe, get_subnet, calculate_danger_score, is_ip_in_whitelist
)

# Logger for this module
logger = logging.getLogger('botstats.analyzer')

class ThreatAnalyzer:
    """
    Analyzes log data using Pandas to detect threats based on IP and subnet activity.
    """

    def __init__(self, rpm_threshold=100, whitelist=None):
        """
        Initializes the threat analyzer.

        Args:
            rpm_threshold (float): Requests per minute threshold (used for flagging, not primary score).
            whitelist (list): List of additional IPs or subnets that should never be blocked.
        """
        self.rpm_threshold = rpm_threshold # Keep for potential future use or simple flagging
        self.whitelist = ['127.0.0.1', '::1']
        if whitelist:
            for item in whitelist:
                if item not in self.whitelist:
                    self.whitelist.append(item)

        # DataFrames for analysis
        self.log_df = None          # Raw log data (ip, timestamp)
        self.ip_metrics_df = None   # Metrics calculated per IP
        self.subnet_metrics_df = None # Metrics aggregated per subnet

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
        Loads log data into a Pandas DataFrame, applying date and whitelist filters.

        Args:
            log_file (str): Path to the log file.
            start_date_utc (datetime, optional): Aware UTC datetime filter.

        Returns:
            int: Number of entries loaded into the DataFrame, or -1 on error.
        """
        logger.info("Loading log data into DataFrame...")
        self.log_df = load_log_into_dataframe(log_file, start_date_utc, self.whitelist)

        if self.log_df is None:
            logger.error("Failed to load log data.")
            return -1

        if self.log_df.empty:
            logger.warning("Log DataFrame is empty after loading and initial filtering.")
            return 0

        logger.info(f"Successfully loaded {len(self.log_df)} log entries into DataFrame.")
        # Ensure timestamp is the index for resampling
        if 'timestamp' in self.log_df.columns:
             self.log_df = self.log_df.set_index('timestamp')
             logger.debug("Timestamp column set as DataFrame index.")
        else:
             logger.error("Timestamp column not found after loading log data.")
             return -1

        return len(self.log_df)

    def _calculate_ip_metrics(self):
        """Calculates metrics per IP address using the loaded DataFrame."""
        if self.log_df is None or self.log_df.empty:
            logger.warning("Log DataFrame is not loaded or empty. Cannot calculate IP metrics.")
            return False

        logger.info("Calculating metrics per IP...")

        # 1. Basic Aggregations (Total Requests, First/Last Seen)
        logger.debug("Calculating total requests, first/last seen per IP...")
        basic_agg = self.log_df.groupby('ip').agg(
            total_requests=('ip', 'count'),
            first_seen=('ip', 'first'), # This gets the timestamp index value
            last_seen=('ip', 'last')   # This gets the timestamp index value
        )
        basic_agg['first_seen'] = basic_agg.index.map(lambda ip: self.log_df.loc[self.log_df['ip'] == ip].index.min())
        basic_agg['last_seen'] = basic_agg.index.map(lambda ip: self.log_df.loc[self.log_df['ip'] == ip].index.max())


        # Calculate time span in seconds
        basic_agg['time_span_seconds'] = (basic_agg['last_seen'] - basic_agg['first_seen']).dt.total_seconds()
        logger.debug(f"Calculated basic aggregations for {len(basic_agg)} IPs.")

        # 2. RPM Metrics (Average and Max during active minutes)
        logger.debug("Calculating RPM metrics (avg/max during activity)...")
        # Resample to get counts per IP per minute
        rpm_counts = self.log_df.groupby('ip').resample('T').size() # 'T' or 'min' for minute frequency
        # Filter out minutes with zero requests (only consider active minutes)
        rpm_counts = rpm_counts[rpm_counts > 0]

        # Calculate avg and max RPM based on active minutes
        rpm_metrics = rpm_counts.groupby('ip').agg(
            avg_rpm_activity='mean',
            max_rpm_activity='max'
        )
        # Fill NaNs with 0 for IPs with only one request (or activity within a single minute)
        rpm_metrics = rpm_metrics.fillna(0)
        logger.debug(f"Calculated RPM metrics for {len(rpm_metrics)} IPs.")

        # 3. Combine Metrics
        logger.debug("Combining basic and RPM metrics...")
        self.ip_metrics_df = basic_agg.join(rpm_metrics, how='left')
        # Fill NaNs in RPM metrics again (for IPs present in basic_agg but not rpm_metrics)
        self.ip_metrics_df[['avg_rpm_activity', 'max_rpm_activity']] = self.ip_metrics_df[['avg_rpm_activity', 'max_rpm_activity']].fillna(0)
        logger.debug("Metrics combined.")

        # 4. Calculate Danger Score per IP
        logger.debug("Calculating danger score per IP...")
        self.ip_metrics_df['danger_score'] = self.ip_metrics_df.apply(
            lambda row: calculate_danger_score(
                row['avg_rpm_activity'],
                row['total_requests'],
                row['time_span_seconds']
                # min_duration_seconds can be passed if needed, defaults to 5 in function
            ),
            axis=1
        )
        logger.debug("Danger scores calculated.")

        # 5. Add Subnet Information
        logger.debug("Adding subnet information...")
        self.ip_metrics_df['subnet'] = self.ip_metrics_df.index.map(get_subnet)
        # Drop rows where subnet could not be determined (invalid IPs somehow?)
        self.ip_metrics_df = self.ip_metrics_df.dropna(subset=['subnet'])
        logger.debug("Subnet information added.")

        logger.info(f"Finished calculating metrics for {len(self.ip_metrics_df)} IPs.")
        return True


    def _aggregate_subnet_metrics(self):
        """Aggregates IP metrics to the subnet level."""
        if self.ip_metrics_df is None or self.ip_metrics_df.empty:
            logger.warning("IP metrics DataFrame not available. Cannot aggregate subnet metrics.")
            return False

        logger.info("Aggregating metrics by subnet...")

        # Define aggregations
        agg_funcs = {
            'total_requests': 'sum',
            'danger_score': ['sum', 'count'], # Sum danger scores AND count IPs using this column
            'avg_rpm_activity': 'mean',
            'max_rpm_activity': 'max',
            'time_span_seconds': 'max'
            # Removed 'ip': 'count'
        }

        # Perform aggregation
        subnet_agg = self.ip_metrics_df.groupby('subnet').agg(agg_funcs)

        # Flatten MultiIndex columns if Pandas version creates them (e.g., ('danger_score', 'sum'))
        if isinstance(subnet_agg.columns, pd.MultiIndex):
             logger.debug("Flattening MultiIndex columns after aggregation.")
             subnet_agg.columns = ['_'.join(col).strip() for col in subnet_agg.columns.values]
             # Rename columns explicitly after flattening
             self.subnet_metrics_df = subnet_agg.rename(
                 columns={
                     'total_requests_sum': 'total_requests', # Assuming sum is default if only one agg
                     'danger_score_sum': 'total_danger_score',
                     'danger_score_count': 'ip_count',
                     'avg_rpm_activity_mean': 'avg_rpm_activity',
                     'max_rpm_activity_max': 'max_rpm_activity',
                     'time_span_seconds_max': 'time_span_seconds'
                 }
             )
        else:
             # Handle older Pandas versions or cases without MultiIndex
             self.subnet_metrics_df = subnet_agg.rename(
                 columns={
                     'danger_score': 'total_danger_score', # Assuming sum was default
                     # Need to figure out how count was named or recalculate
                 }
             )
             # If count wasn't automatically named, recalculate ip_count separately
             if 'ip_count' not in self.subnet_metrics_df.columns:
                  logger.debug("Recalculating ip_count separately.")
                  ip_counts = self.ip_metrics_df.groupby('subnet').size()
                  self.subnet_metrics_df['ip_count'] = ip_counts


        # Ensure essential columns exist, fill missing with 0 if necessary
        expected_cols = ['total_requests', 'total_danger_score', 'ip_count', 'avg_rpm_activity', 'max_rpm_activity', 'time_span_seconds']
        for col in expected_cols:
             if col not in self.subnet_metrics_df.columns:
                  logger.warning(f"Column '{col}' missing after aggregation. Filling with 0.")
                  self.subnet_metrics_df[col] = 0


        # Sort by total_requests descending
        self.subnet_metrics_df = self.subnet_metrics_df.sort_values('total_requests', ascending=False)

        logger.info(f"Finished aggregating metrics for {len(self.subnet_metrics_df)} subnets.")
        return True

    def _format_threat_output(self):
        """Formats the aggregated subnet metrics into the unified_threats list."""
        if self.subnet_metrics_df is None:
            logger.warning("Subnet metrics not available. Cannot format output.")
            self.unified_threats = []
            return

        logger.debug("Formatting subnet metrics into final threat list...")
        self.unified_threats = []

        # Get top IPs per subnet for details (sorted by danger score)
        top_ips_per_subnet = self.ip_metrics_df.sort_values('danger_score', ascending=False)\
                                             .groupby('subnet')

        for subnet, metrics in self.subnet_metrics_df.iterrows():
            # Get top IPs for this subnet
            top_ips = top_ips_per_subnet.get_group(subnet)
            details_list = []
            # Format IP details similar to previous structure, limit count
            max_details = 5
            for ip, ip_metrics in top_ips.head(max_details).iterrows():
                 details_list.append({
                     'ip': ip,
                     'total_requests': int(ip_metrics['total_requests']),
                     'danger_score': round(ip_metrics['danger_score'], 2),
                     'avg_rpm': round(ip_metrics['avg_rpm_activity'], 2),
                     'max_rpm': round(ip_metrics['max_rpm_activity'], 2),
                     # Add first/last seen if needed
                 })

            threat = {
                'type': 'subnet',
                'id': subnet, # This is the ipaddress.ip_network object
                'total_requests': int(metrics['total_requests']),
                'ip_count': int(metrics['ip_count']),
                'danger_score': round(metrics['total_danger_score'], 2), # Renamed from total_danger_score for compatibility
                'subnet_avg_ip_rpm': round(metrics['avg_rpm_activity'], 2), # Avg of avg RPMs
                'subnet_max_ip_rpm': round(metrics['max_rpm_activity'], 2), # Max of max RPMs
                'subnet_time_span': round(metrics['time_span_seconds'], 2), # Max timespan
                'details': details_list # List of top IPs dicts
            }
            self.unified_threats.append(threat)

        # Ensure final list is sorted by total_requests (should already be from DataFrame sort)
        # self.unified_threats = sorted(self.unified_threats, key=lambda x: x['total_requests'], reverse=True)
        logger.debug(f"Formatted {len(self.unified_threats)} threats.")


    def identify_threats(self):
        """
        Orchestrates the calculation of IP metrics, aggregation by subnet,
        and formatting the final threat list.

        Returns:
            list: List of detected subnet threats, sorted by total requests descending.
        """
        if not self._calculate_ip_metrics():
            return []
        if not self._aggregate_subnet_metrics():
            return []

        self._format_threat_output()

        logger.info(f"Threat identification complete. Found {len(self.unified_threats)} subnet threats.")
        return self.unified_threats

    def get_top_threats(self, top=10):
        """Gets the top N threats from the identified list."""
        if not self.unified_threats:
             self.identify_threats()
        return self.unified_threats[:top]

    def export_results(self, format_type, output_file):
        """Exports the results (unified_threats list) to a file."""
        if not self.unified_threats:
            self.identify_threats()
            if not self.unified_threats:
                 logger.warning("No threats identified, cannot export.")
                 return False

        logger.info(f"Exporting {len(self.unified_threats)} threats to {output_file} in {format_type} format...")

        try:
            if format_type.lower() == 'json':
                json_threats = []
                for threat in self.unified_threats:
                    json_threat = threat.copy()
                    json_threat['id'] = str(json_threat['id']) # Convert network object
                    # Details are already serializable (basic types)
                    json_threats.append(json_threat)
                with open(output_file, 'w') as f:
                    json.dump(json_threats, f, indent=2)

            elif format_type.lower() == 'csv':
                 # Flatten the structure for CSV
                 csv_data = []
                 for threat in self.unified_threats:
                      row = {
                          'type': threat['type'],
                          'id': str(threat['id']),
                          'total_requests': threat['total_requests'],
                          'ip_count': threat['ip_count'],
                          'danger_score': threat['danger_score'],
                          'subnet_avg_ip_rpm': threat.get('subnet_avg_ip_rpm', 0),
                          'subnet_max_ip_rpm': threat.get('subnet_max_ip_rpm', 0),
                          'subnet_time_span': threat.get('subnet_time_span', 0),
                          # Optionally add first few IPs from details
                          'top_ip_1': threat['details'][0]['ip'] if len(threat['details']) > 0 else '',
                          'top_ip_1_reqs': threat['details'][0]['total_requests'] if len(threat['details']) > 0 else '',
                          'top_ip_2': threat['details'][1]['ip'] if len(threat['details']) > 1 else '',
                          'top_ip_2_reqs': threat['details'][1]['total_requests'] if len(threat['details']) > 1 else '',
                      }
                      csv_data.append(row)

                 if csv_data:
                     fieldnames = csv_data[0].keys() # Get headers from first row
                     with open(output_file, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(csv_data)
                 else:
                      logger.warning("No data to write to CSV.")


            elif format_type.lower() == 'text':
                 with open(output_file, 'w') as f:
                     f.write(f"=== {len(self.unified_threats)} SUBNET THREATS DETECTED (Sorted by Total Requests) ===\n")
                     for i, threat in enumerate(self.unified_threats, 1):
                         target_id_str = str(threat['id'])
                         danger_str = f"Danger: {threat['danger_score']:.2f}"
                         # Use the new RPM metrics if available
                         avg_rpm_str = f"~{threat.get('subnet_avg_ip_rpm', 0):.2f} avg_ip_rpm"
                         max_rpm_str = f"{threat.get('subnet_max_ip_rpm', 0):.0f} max_ip_rpm"
                         rpm_info = f"{avg_rpm_str}, {max_rpm_str}"
                         ip_count_str = f"{threat['ip_count']} IP" if threat['ip_count'] == 1 else f"{threat['ip_count']} IPs"

                         f.write(f"\n#{i} Subnet: {target_id_str} - Requests: {threat['total_requests']} ({ip_count_str}, {danger_str}, {rpm_info})\n")

                         # Show details for top IPs within the subnet threat
                         if threat['details']:
                             f.write("  -> Top IPs (by danger score):\n")
                             for ip_detail in threat['details']:
                                 f.write(f"     - IP: {ip_detail['ip']} ({ip_detail['total_requests']} reqs, Danger: {ip_detail['danger_score']:.2f}, AvgRPM: {ip_detail['avg_rpm']:.2f}, MaxRPM: {ip_detail['max_rpm']:.0f})\n")
                         else:
                              f.write("  -> No IP details available.\n")
            else:
                logger.error(f"Unsupported export format: {format_type}")
                return False

            logger.info(f"Results exported successfully to {output_file}")
            return True

        except Exception as e:
            logger.error(f"Error exporting results: {e}", exc_info=True)
            return False