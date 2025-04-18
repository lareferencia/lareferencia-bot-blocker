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
from ipaddress import ip_network

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

        # Add subnet information directly to the main log DataFrame
        logger.debug("Adding subnet information to log DataFrame...")
        self.log_df['subnet'] = self.log_df['ip'].map(get_subnet)
        # Drop rows where subnet couldn't be determined (should be rare)
        self.log_df = self.log_df.dropna(subset=['subnet'])
        logger.debug("Subnet information added.")

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

    def _calculate_subnet_rpm_metrics(self):
        """Calculates total RPM metrics per Subnet."""
        if self.log_df is None or self.log_df.empty:
             logger.warning("Log DataFrame not available. Cannot calculate subnet RPM metrics.")
             return None

        logger.info("Calculating total RPM metrics per Subnet...")
        try:
            # Group by subnet and resample per minute
            subnet_group = self.log_df.groupby('subnet')
            rpm_counts_subnet = subnet_group.resample('T').size()
            rpm_counts_subnet = rpm_counts_subnet[rpm_counts_subnet > 0] # Filter inactive minutes

            # Calculate avg and max RPM for the whole subnet
            subnet_rpm_metrics = rpm_counts_subnet.groupby('subnet').agg(
                subnet_total_avg_rpm='mean', # Avg RPM of the subnet when active
                subnet_total_max_rpm='max'   # Max RPM the subnet reached in any minute
            ).fillna(0)
            logger.info(f"Calculated total RPM metrics for {len(subnet_rpm_metrics)} subnets.")
            return subnet_rpm_metrics
        except Exception as e:
            logger.error(f"Error calculating subnet RPM metrics: {e}", exc_info=True)
            return None

    def _aggregate_subnet_metrics(self):
        """Aggregates IP metrics and adds Subnet RPM metrics using a more robust join approach."""
        if self.ip_metrics_df is None or self.ip_metrics_df.empty:
            logger.warning("IP metrics DataFrame not available. Cannot aggregate subnet metrics.")
            return False

        logger.info("Aggregating metrics by subnet...")
        # Ensure 'subnet' column exists before trying to get unique values
        if 'subnet' not in self.ip_metrics_df.columns:
             logger.error("'subnet' column missing from ip_metrics_df. Cannot proceed with aggregation.")
             return False
        subnet_index = self.ip_metrics_df['subnet'].unique() # Get unique subnet objects as potential index
        logger.debug(f"Found {len(subnet_index)} unique subnets in ip_metrics_df.")

        # --- 1. Calculate Aggregations from ip_metrics_df ---
        logger.debug("Calculating sums/counts from ip_metrics_df...")
        try:
            # Use observed=True if pandas version supports it and index is categorical, otherwise default is fine
            grouped_ips = self.ip_metrics_df.groupby('subnet') #, observed=True)
            agg1 = grouped_ips.agg(
                total_requests=('total_requests', 'sum'),
                ip_count=('ip_danger_score', 'count'), # Use any column guaranteed to exist per IP
                aggregated_ip_danger_score=('ip_danger_score', 'sum')
            )
            # Ensure the index is usable, sometimes groupby might drop the subnet object type
            agg1.index = agg1.index.map(lambda x: ip_network(x, strict=False) if not isinstance(x, (ip_network)) else x) # Use strict=False for safety
            logger.debug(f"Aggregation 1 (requests, count, danger):\n{agg1.head()}")
            if agg1.empty and len(subnet_index) > 0:
                 logger.warning("Aggregation 1 resulted in an empty DataFrame despite having subnets.")
                 # Recreate with 0s if empty but should have rows
                 agg1 = pd.DataFrame(0, index=subnet_index, columns=['total_requests', 'ip_count', 'aggregated_ip_danger_score'])

        except Exception as e:
            logger.error(f"Error during aggregation 1: {e}", exc_info=True)
            return False

        # --- 2. Calculate IP-based RPM Aggregations from ip_metrics_df ---
        logger.debug("Calculating IP-based RPM means/max from ip_metrics_df...")
        try:
            # Use the same grouped object if possible
            agg2 = grouped_ips.agg(
                subnet_avg_ip_rpm=('avg_rpm_activity', 'mean'), # Avg of IP avgs
                subnet_max_ip_rpm=('max_rpm_activity', 'max'),  # Max of IP maxs
                subnet_time_span=('time_span_seconds', 'max') # Max timespan
            ).fillna(0) # Fill NaNs here for IPs with single requests
            agg2.index = agg2.index.map(lambda x: ip_network(x, strict=False) if not isinstance(x, (ip_network)) else x) # Use strict=False
            logger.debug(f"Aggregation 2 (IP RPMs, timespan):\n{agg2.head()}")
            if agg2.empty and len(subnet_index) > 0:
                 logger.warning("Aggregation 2 resulted in an empty DataFrame.")
                 agg2 = pd.DataFrame(0.0, index=subnet_index, columns=['subnet_avg_ip_rpm', 'subnet_max_ip_rpm', 'subnet_time_span'])

        except Exception as e:
            logger.error(f"Error during aggregation 2: {e}", exc_info=True)
            # Allow proceeding without these metrics if needed
            agg2 = pd.DataFrame(index=subnet_index) # Create empty DF with correct index
            agg2[['subnet_avg_ip_rpm', 'subnet_max_ip_rpm', 'subnet_time_span']] = 0.0


        # --- 3. Calculate Subnet Total RPM metrics from log_df ---
        logger.debug("Calculating Subnet Total RPM metrics from log_df...")
        agg3 = self._calculate_subnet_rpm_metrics() # This already returns a DataFrame indexed by subnet or None
        if agg3 is None:
             logger.warning("Subnet total RPM calculation failed. Creating placeholders.")
             agg3 = pd.DataFrame(index=subnet_index) # Create empty DF with correct index
             agg3[['subnet_total_avg_rpm', 'subnet_total_max_rpm']] = 0.0
        else:
             # Ensure index consistency
             agg3.index = agg3.index.map(lambda x: ip_network(x, strict=False) if not isinstance(x, (ip_network)) else x) # Use strict=False
             # Ensure columns exist even if calculation returned empty results for some reason
             if agg3.empty and len(subnet_index) > 0:
                  logger.warning("Aggregation 3 resulted in an empty DataFrame.")
                  # Recreate with 0s if empty but should have rows
                  agg3 = pd.DataFrame(0.0, index=subnet_index, columns=['subnet_total_avg_rpm', 'subnet_total_max_rpm'])
             else:
                  if 'subnet_total_avg_rpm' not in agg3.columns: agg3['subnet_total_avg_rpm'] = 0.0
                  if 'subnet_total_max_rpm' not in agg3.columns: agg3['subnet_total_max_rpm'] = 0.0
        logger.debug(f"Aggregation 3 (Subnet Total RPMs):\n{agg3.head()}")


        # --- 4. Combine the aggregations ---
        logger.debug("Joining aggregated metrics...")
        try:
            # Start with the primary aggregation (requests, count, danger)
            # Ensure agg1 has the correct index before proceeding
            if not isinstance(agg1.index, pd.Index) or agg1.index.empty:
                 logger.error("Index for agg1 is invalid or empty before join.")
                 # Attempt to reindex if possible, otherwise fail
                 if not agg1.empty:
                      agg1 = agg1.reindex(subnet_index, fill_value=0)
                 else: # If agg1 was truly empty, create it with zeros
                      agg1 = pd.DataFrame(0, index=subnet_index, columns=['total_requests', 'ip_count', 'aggregated_ip_danger_score'])

            self.subnet_metrics_df = agg1
            logger.debug(f"DF before join 1 (Index: {self.subnet_metrics_df.index.dtype}):\n{self.subnet_metrics_df.head()}")
            logger.debug(f"agg2 before join 1 (Index: {agg2.index.dtype}):\n{agg2.head()}")

            # Join the other aggregations. Use how='left' to keep all subnets from agg1.
            # Ensure indices are compatible before joining
            if not self.subnet_metrics_df.index.equals(agg2.index):
                 logger.warning("Indices of agg1 and agg2 differ. Attempting reindex before join.")
                 agg2 = agg2.reindex(self.subnet_metrics_df.index, fill_value=0)
            self.subnet_metrics_df = self.subnet_metrics_df.join(agg2, how='left')

            logger.debug(f"DF before join 2 (Index: {self.subnet_metrics_df.index.dtype}):\n{self.subnet_metrics_df.head()}")
            logger.debug(f"agg3 before join 2 (Index: {agg3.index.dtype}):\n{agg3.head()}")
            if not self.subnet_metrics_df.index.equals(agg3.index):
                 logger.warning("Indices of main DF and agg3 differ. Attempting reindex before join.")
                 agg3 = agg3.reindex(self.subnet_metrics_df.index, fill_value=0)
            self.subnet_metrics_df = self.subnet_metrics_df.join(agg3, how='left')


            # Fill any NaNs that might have occurred during joins (e.g., if a subnet was in agg1 but not agg2/agg3)
            self.subnet_metrics_df = self.subnet_metrics_df.fillna(0)
            logger.debug(f"Final combined subnet metrics (before type conversion):\n{self.subnet_metrics_df.head()}")

        except Exception as e:
             logger.error(f"Error joining aggregated subnet metrics: {e}", exc_info=True)
             # Log the state of dataframes just before the error if possible
             try:
                 logger.error(f"State before error:\nagg1:\n{agg1.head()}\nagg2:\n{agg2.head()}\nagg3:\n{agg3.head()}")
             except: pass
             return False

        # --- 5. Ensure correct data types ---
        logger.debug("Ensuring correct data types...")
        try:
            expected_cols = {
                'total_requests': int,
                'ip_count': int,
                'aggregated_ip_danger_score': float,
                'subnet_avg_ip_rpm': float,
                'subnet_max_ip_rpm': float,
                'subnet_time_span': float,
                'subnet_total_avg_rpm': float,
                'subnet_total_max_rpm': float
            }
            for col, dtype in expected_cols.items():
                if col in self.subnet_metrics_df.columns:
                    # Handle potential non-numeric data before converting
                    self.subnet_metrics_df[col] = pd.to_numeric(self.subnet_metrics_df[col], errors='coerce').fillna(0)
                    self.subnet_metrics_df[col] = self.subnet_metrics_df[col].astype(dtype)
                else:
                    logger.warning(f"Column '{col}' missing before type conversion. Adding as {dtype}(0).")
                    if dtype == int:
                        self.subnet_metrics_df[col] = 0
                    else:
                        self.subnet_metrics_df[col] = 0.0
        except Exception as e:
             logger.error(f"Error converting data types for subnet metrics: {e}", exc_info=True)
             # Continue, but data types might be incorrect

        logger.info(f"Finished aggregating metrics for {len(self.subnet_metrics_df)} subnets.")
        logger.debug(f"Final combined subnet metrics (after type conversion):\n{self.subnet_metrics_df.head()}")
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
                'subnet_total_avg_rpm': round(metrics.get('subnet_total_avg_rpm', 0), 2),
                'subnet_total_max_rpm': round(metrics.get('subnet_total_max_rpm', 0), 2),
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
                          'subnet_total_avg_rpm': threat.get('subnet_total_avg_rpm', 0), # Subnet total avg RPM
                          'subnet_total_max_rpm': threat.get('subnet_total_max_rpm', 0), # Subnet total max RPM
                          'subnet_time_span': threat.get('subnet_time_span', 0),
                          'top_ip_1': threat['details'][0]['ip'] if len(threat['details']) > 0 else '',
                          'top_ip_1_reqs': threat['details'][0]['total_requests'] if len(threat['details']) > 0 else '',
                          'top_ip_1_score': threat['details'][0]['danger_score'] if len(threat['details']) > 0 else '',
                          'top_ip_1_max_rpm': threat['details'][0]['max_rpm'] if len(threat['details']) > 0 else '', # Added top IP max RPM
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
                         subnet_total_avg_rpm_str = f"~{threat.get('subnet_total_avg_rpm', 0):.1f} avg_total_rpm"
                         subnet_total_max_rpm_str = f"{threat.get('subnet_total_max_rpm', 0):.0f} max_total_rpm"
                         ip_count_str = f"{threat['ip_count']} IPs"
                         req_str = f"{threat['total_requests']} reqs"
                         agg_danger_str = f"AggDanger: {threat.get('aggregated_ip_danger_score', 0):.2f}" # Added

                         # Combine metrics for display
                         metrics_summary = f"{req_str}, {ip_count_str}, {agg_danger_str}, {avg_rpm_str}, {max_rpm_str}, {subnet_total_avg_rpm_str}, {subnet_total_max_rpm_str}"
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