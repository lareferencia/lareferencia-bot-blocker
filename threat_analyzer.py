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
    load_log_into_dataframe, get_subnet, is_ip_in_whitelist
)

# Logger for this module
logger = logging.getLogger('botstats.analyzer')

class ThreatAnalyzer:
    """
    Analyzes log data using Pandas to detect threats based on IP and subnet activity.
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

        # 4. Calculate IP Danger Score (using a simple placeholder or basic calculation)
        # This score is now primarily for ranking IPs *within* a subnet's details,
        # the main strategy score is calculated later.
        logger.debug("Calculating basic IP danger score (for detail ranking)...")
        # Use a simplified score calculation here, maybe similar to the old one
        # or just use avg_rpm_activity + log(total_requests)
        self.ip_metrics_df['ip_danger_score'] = self.ip_metrics_df.apply(
            lambda row: (row['avg_rpm_activity'] / 10.0) + (np.log10(row['total_requests'] + 1) * 5),
            axis=1
        )
        logger.debug("IP danger scores calculated.")

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
            'ip_danger_score': ['sum', 'count'], # Calculate sum and count
            'avg_rpm_activity': 'mean',
            'max_rpm_activity': 'max',
            'time_span_seconds': 'max'
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
                     'ip_danger_score_sum': 'aggregated_ip_danger_score', # Added sum
                     'ip_danger_score_count': 'ip_count', # Renamed from danger_score_count
                     'avg_rpm_activity_mean': 'subnet_avg_ip_rpm', # Renamed for clarity
                     'max_rpm_activity_max': 'subnet_max_ip_rpm', # Renamed for clarity
                     'time_span_seconds_max': 'subnet_time_span' # Renamed for clarity
                 }
             )
        else:
             # Handle older Pandas versions or cases without MultiIndex
             self.subnet_metrics_df = subnet_agg.rename(
                 columns={
                     'ip_danger_score': 'aggregated_ip_danger_score', # Assuming sum if only one agg? Check pandas version behavior
                     'avg_rpm_activity': 'subnet_avg_ip_rpm',
                     'max_rpm_activity': 'subnet_max_ip_rpm',
                     'time_span_seconds': 'subnet_time_span'
                 }
             )
             # If count wasn't automatically named, recalculate ip_count separately
             if 'ip_count' not in self.subnet_metrics_df.columns:
                  logger.debug("Recalculating ip_count separately.")
                  ip_counts = self.ip_metrics_df.groupby('subnet').size()
                  self.subnet_metrics_df['ip_count'] = ip_counts
             if 'aggregated_ip_danger_score' not in self.subnet_metrics_df.columns:
                  agg_ip_danger = self.ip_metrics_df.groupby('subnet')['ip_danger_score'].sum()
                  self.subnet_metrics_df['aggregated_ip_danger_score'] = agg_ip_danger

        # Ensure essential columns exist, fill missing with 0 if necessary
        expected_cols = ['total_requests', 'ip_count', 'aggregated_ip_danger_score',
                         'subnet_avg_ip_rpm', 'subnet_max_ip_rpm', 'subnet_time_span']
        for col in expected_cols:
             if col not in self.subnet_metrics_df.columns:
                  logger.warning(f"Column '{col}' missing after aggregation. Filling with 0.")
                  self.subnet_metrics_df[col] = 0

        # DO NOT sort here - sorting will be done in stats.py based on strategy score
        # self.subnet_metrics_df = self.subnet_metrics_df.sort_values('total_requests', ascending=False)

        logger.info(f"Finished aggregating metrics for {len(self.subnet_metrics_df)} subnets.")
        return True

    def _format_threat_output(self):
        """Formats the aggregated subnet metrics into the unified_threats list."""
        if self.subnet_metrics_df is None:
            logger.warning("Subnet metrics not available. Cannot format output.")
            self.unified_threats = []
            return

        logger.debug("Formatting subnet metrics into threat list (without final score/sorting)...")
        self.unified_threats = []

        # Get top IPs per subnet for details - SORT BY MAX RPM ACTIVITY
        logger.debug("Grouping and sorting IPs by subnet based on max_rpm_activity...")
        top_ips_per_subnet = self.ip_metrics_df.sort_values('max_rpm_activity', ascending=False)\
                                             .groupby('subnet')

        for subnet, metrics in self.subnet_metrics_df.iterrows():
            # Get top IPs for this subnet (now sorted by max_rpm_activity)
            details_list = []
            try:
                top_ips = top_ips_per_subnet.get_group(subnet)
                max_details = 5 # Limit the number of IPs shown in details
                for ip, ip_metrics in top_ips.head(max_details).iterrows():
                     details_list.append({
                         'ip': ip,
                         'total_requests': int(ip_metrics['total_requests']),
                         'danger_score': round(ip_metrics['ip_danger_score'], 2), # Keep basic score for info
                         'avg_rpm': round(ip_metrics['avg_rpm_activity'], 2),
                         'max_rpm': round(ip_metrics['max_rpm_activity'], 2), # This was the sort key
                     })
            except KeyError:
                 logger.warning(f"Could not find IPs for subnet {subnet} during detail formatting.")


            # Create threat dict (unchanged)
            threat = {
                'type': 'subnet',
                'id': subnet,
                'total_requests': int(metrics['total_requests']),
                'ip_count': int(metrics['ip_count']),
                'aggregated_ip_danger_score': round(metrics.get('aggregated_ip_danger_score', 0), 2),
                'subnet_avg_ip_rpm': round(metrics.get('subnet_avg_ip_rpm', 0), 2),
                'subnet_max_ip_rpm': round(metrics.get('subnet_max_ip_rpm', 0), 2),
                'subnet_time_span': round(metrics.get('subnet_time_span', 0), 2),
                'details': details_list,
                'strategy_score': 0.0,
                'should_block': False,
                'block_reason': None
            }
            self.unified_threats.append(threat)

        logger.debug(f"Formatted {len(self.unified_threats)} threats (pre-strategy).")


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

    # --- REMOVE get_top_threats method ---
    # def get_top_threats(self, top=10):
    #     # ... (method removed) ...
    #     pass
    # --- END REMOVAL ---

    def export_results(self, format_type, output_file, config=None):
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
                          'strategy_score': threat.get('strategy_score', 0), # Add strategy score
                          'should_block': threat.get('should_block', False), # Add block decision
                          'block_reason': threat.get('block_reason', ''), # Add reason
                          'total_requests': threat['total_requests'],
                          'ip_count': threat['ip_count'],
                          'aggregated_ip_danger_score': threat.get('aggregated_ip_danger_score', 0), # Added
                          'subnet_avg_ip_rpm': threat.get('subnet_avg_ip_rpm', 0),
                          'subnet_max_ip_rpm': threat.get('subnet_max_ip_rpm', 0),
                          'subnet_time_span': threat.get('subnet_time_span', 0),
                          'top_ip_1': threat['details'][0]['ip'] if len(threat['details']) > 0 else '',
                          'top_ip_1_reqs': threat['details'][0]['total_requests'] if len(threat['details']) > 0 else '',
                          'top_ip_1_score': threat['details'][0]['danger_score'] if len(threat['details']) > 0 else '',
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
                     f.write(f"=== {len(self.unified_threats)} SUBNET THREATS DETECTED (Sorted by Strategy Score) ===\n")
                     for i, threat in enumerate(self.unified_threats, 1):
                         target_id_str = str(threat['id'])
                         # Display strategy score
                         strat_score_str = f"Score: {threat.get('strategy_score', 0):.2f}"
                         avg_rpm_str = f"~{threat.get('subnet_avg_ip_rpm', 0):.2f} avg_ip_rpm"
                         max_rpm_str = f"{threat.get('subnet_max_ip_rpm', 0):.0f} max_ip_rpm"
                         ip_count_str = f"{threat['ip_count']} IPs"
                         req_str = f"{threat['total_requests']} reqs"
                         agg_danger_str = f"AggDanger: {threat.get('aggregated_ip_danger_score', 0):.2f}" # Added

                         # Combine metrics for display
                         metrics_summary = f"{req_str}, {ip_count_str}, {agg_danger_str}, {avg_rpm_str}, {max_rpm_str}"
                         # Add block status/reason
                         block_info = ""
                         # Use config if available to check dry_run
                         is_dry_run = config.dry_run if config else False # Default to False if config not passed
                         if threat.get('should_block'):
                              block_status = "[BLOCKED]" if not is_dry_run else "[DRY RUN - BLOCKED]" # Need config here! Pass config to export?
                              block_info = f" {block_status} Reason: {threat.get('block_reason', 'N/A')}"


                         f.write(f"\n#{i} Subnet: {target_id_str} - {strat_score_str} ({metrics_summary}){block_info}\n")

                         # Update details header
                         if threat['details']:
                             f.write("  -> Top IPs (by Max RPM):\n") # Changed header
                             for ip_detail in threat['details']:
                                 # Display order remains the same, but the IPs listed are now sorted by MaxRPM
                                 f.write(f"     - IP: {ip_detail['ip']} ({ip_detail['total_requests']} reqs, Score: {ip_detail['danger_score']:.2f}, AvgRPM: {ip_detail['avg_rpm']:.2f}, MaxRPM: {ip_detail['max_rpm']:.0f})\n")
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