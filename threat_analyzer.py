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
from ipaddress import ip_network, IPv4Network, IPv6Network

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

        # 4. Add Subnet Information
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
        logger.debug("Calculating sums/counts/min/max timestamps from ip_metrics_df...")
        try:
            # Use observed=True if pandas version supports it and index is categorical, otherwise default is fine
            grouped_ips = self.ip_metrics_df.groupby('subnet') #, observed=True)

            # Calculate ip_count separately using size()
            ip_counts = grouped_ips.size().rename('ip_count')

            # Perform other aggregations
            agg1_main = grouped_ips.agg(
                total_requests=('total_requests', 'sum'),
                # ip_count=('ip', 'count'), # REMOVED - Use size() instead
                subnet_first_seen=('first_seen', 'min'), # Earliest first seen time in the subnet
                subnet_last_seen=('last_seen', 'max')    # Latest last seen time in the subnet
            )

            # Join ip_counts with the main aggregation results
            agg1 = agg1_main.join(ip_counts, how='left')
            # Fill NaN in ip_count if any subnets somehow didn't get counted (shouldn't happen with left join)
            agg1['ip_count'] = agg1['ip_count'].fillna(0).astype(int)


            # Calculate subnet_time_span from the aggregated timestamps
            agg1['subnet_time_span'] = (agg1['subnet_last_seen'] - agg1['subnet_first_seen']).dt.total_seconds()
            # Handle cases where first_seen == last_seen (span is 0) or potential NaNs
            agg1['subnet_time_span'] = agg1['subnet_time_span'].fillna(0).clip(lower=0) # Ensure non-negative

            # Calculate Requests per Minute for the subnet
            # Avoid division by zero if time_span is 0
            agg1['subnet_req_per_min'] = agg1.apply(
                lambda row: (row['total_requests'] / (row['subnet_time_span'] / 60.0)) if row['subnet_time_span'] > 0 else 0,
                axis=1
            )


            # Ensure the index is usable, sometimes groupby might drop the subnet object type
            agg1.index = agg1.index.map(lambda x: ip_network(x, strict=False) if not isinstance(x, (IPv4Network, IPv6Network)) else x) # Use strict=False for safety
            logger.debug(f"Aggregation 1 (requests, count, danger, timespan, req/min):\n{agg1.head()}") # UPDATED log message
            if agg1.empty and len(subnet_index) > 0:
                 logger.warning("Aggregation 1 resulted in an empty DataFrame despite having subnets.")
                 # Recreate with 0s if empty but should have rows
                 agg1 = pd.DataFrame(0, index=subnet_index, columns=['total_requests', 'ip_count', 'subnet_first_seen', 'subnet_last_seen', 'subnet_time_span', 'subnet_req_per_min']) # ADDED column
                 # Ensure correct dtypes for timestamps if recreated
                 agg1['subnet_first_seen'] = pd.NaT
                 agg1['subnet_last_seen'] = pd.NaT


        except Exception as e:
            logger.error(f"Error during aggregation 1: {e}", exc_info=True)
            return False

        # --- 2. Calculate IP-based RPM Aggregations from ip_metrics_df ---
        logger.debug("Calculating IP-based RPM means/max from ip_metrics_df...")
        try:
            # Use the same grouped object if possible
            # Remove subnet_time_span calculation from here
            agg2 = grouped_ips.agg(
                subnet_avg_ip_rpm=('avg_rpm_activity', 'mean'), # Avg of IP avgs
                subnet_max_ip_rpm=('max_rpm_activity', 'max'),  # Max of IP maxs
                # subnet_time_span=('time_span_seconds', 'max') # REMOVED - Calculated in agg1 now
            ).fillna(0) # Fill NaNs here for IPs with single requests
            agg2.index = agg2.index.map(lambda x: ip_network(x, strict=False) if not isinstance(x, (IPv4Network, IPv6Network)) else x) # Use strict=False
            logger.debug(f"Aggregation 2 (IP RPMs):\n{agg2.head()}")
            if agg2.empty and len(subnet_index) > 0:
                 logger.warning("Aggregation 2 resulted in an empty DataFrame.")
                 agg2 = pd.DataFrame(0.0, index=subnet_index, columns=['subnet_avg_ip_rpm', 'subnet_max_ip_rpm'])

        except Exception as e:
            logger.error(f"Error during aggregation 2: {e}", exc_info=True)
            # Allow proceeding without these metrics if needed
            agg2 = pd.DataFrame(index=subnet_index) # Create empty DF with correct index
            agg2[['subnet_avg_ip_rpm', 'subnet_max_ip_rpm']] = 0.0


        # --- 3. Calculate Subnet Total RPM metrics from log_df ---
        logger.debug("Calculating Subnet Total RPM metrics from log_df...")
        agg3 = self._calculate_subnet_rpm_metrics() # This already returns a DataFrame indexed by subnet or None
        if agg3 is None:
             logger.warning("Subnet total RPM calculation failed. Creating placeholders.")
             agg3 = pd.DataFrame(index=subnet_index) # Create empty DF with correct index
             agg3[['subnet_total_avg_rpm', 'subnet_total_max_rpm']] = 0.0
        else:
             # Ensure index consistency
             agg3.index = agg3.index.map(lambda x: ip_network(x, strict=False) if not isinstance(x, (IPv4Network, IPv6Network)) else x) # Use strict=False
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
            # Start with the primary aggregation (requests, count, danger, timespan)
            # Ensure agg1 has the correct index before proceeding
            if not isinstance(agg1.index, pd.Index) or agg1.index.empty:
                 logger.error("Index for agg1 is invalid or empty before join.")
                 # Attempt to reindex if possible, otherwise fail
                 if not agg1.empty:
                      agg1 = agg1.reindex(subnet_index, fill_value=0)
                      # Re-apply NaT for timestamps if reindexed
                      if 'subnet_first_seen' in agg1.columns: agg1['subnet_first_seen'] = pd.NaT
                      if 'subnet_last_seen' in agg1.columns: agg1['subnet_last_seen'] = pd.NaT
                 else: # If agg1 was truly empty, create it with zeros/NaT
                      agg1 = pd.DataFrame(0, index=subnet_index, columns=['total_requests', 'ip_count', 'subnet_first_seen', 'subnet_last_seen', 'subnet_time_span', 'subnet_req_per_min'])
                      agg1['subnet_first_seen'] = pd.NaT
                      agg1['subnet_last_seen'] = pd.NaT

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
            # Exclude timestamp columns from general fillna
            cols_to_fill = self.subnet_metrics_df.columns.difference(['subnet_first_seen', 'subnet_last_seen'])
            self.subnet_metrics_df[cols_to_fill] = self.subnet_metrics_df[cols_to_fill].fillna(0)
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
            # Keep timestamp columns separate
            expected_cols = {
                'total_requests': int,
                'ip_count': int,
                'subnet_avg_ip_rpm': float,
                'subnet_max_ip_rpm': float,
                'subnet_time_span': float, # Already calculated as float seconds
                'subnet_total_avg_rpm': float,
                'subnet_total_max_rpm': float,
                'subnet_req_per_min': float, # ADDED new metric type
                'dominant_bot_name': str # ADDED bot name type
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
            # Optionally convert timestamp columns if needed, but they might be fine as is
            # self.subnet_metrics_df['subnet_first_seen'] = pd.to_datetime(self.subnet_metrics_df['subnet_first_seen'], errors='coerce', utc=True)
            # self.subnet_metrics_df['subnet_last_seen'] = pd.to_datetime(self.subnet_metrics_df['subnet_last_seen'], errors='coerce', utc=True)

            # Drop the intermediate timestamp columns if no longer needed
            self.subnet_metrics_df = self.subnet_metrics_df.drop(columns=['subnet_first_seen', 'subnet_last_seen'], errors='ignore')

        except Exception as e:
             logger.error(f"Error converting data types or dropping columns for subnet metrics: {e}", exc_info=True)
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
        top_ips_per_subnet = self.ip_metrics_df.sort_values(by='max_rpm_activity', ascending=False)\
                                                  .groupby('subnet')

        for subnet, metrics in self.subnet_metrics_df.iterrows():
            # Get top IPs for this subnet (now sorted by max_rpm_activity)
            details_list = []
            if top_ips_per_subnet:
                try:
                    # Ensure the subnet key exists in the grouped object
                    if subnet in top_ips_per_subnet.groups:
                        top_ips = top_ips_per_subnet.get_group(subnet)
                        max_details = 5 # Limit the number of IPs shown in details
                        for ip, ip_metrics in top_ips.head(max_details).iterrows():
                             # Check if ip_metrics is a valid Series/dict
                             if isinstance(ip_metrics, pd.Series):
                                 details_list.append({
                                     'ip': ip,
                                     'total_requests': int(ip_metrics.get('total_requests', 0)),
                                     'avg_rpm': round(ip_metrics.get('avg_rpm_activity', 0), 2),
                                     'max_rpm': round(ip_metrics.get('max_rpm_activity', 0), 2),
                                 })
                             else:
                                 logger.warning(f"Unexpected type for ip_metrics for IP {ip} in subnet {subnet}: {type(ip_metrics)}")
                    else:
                        logger.warning(f"Subnet key {subnet} not found in top_ips_per_subnet groups.")

                except KeyError:
                     # This specific KeyError might be less likely now with the check above, but keep for safety
                     logger.warning(f"Could not find IPs for subnet {subnet} during detail formatting (KeyError).")
                except Exception as e:
                     logger.error(f"Unexpected error formatting details for subnet {subnet}: {e}", exc_info=True)
            else:
                 logger.warning(f"Skipping details for subnet {subnet} due to missing ip_metrics_df.")


            # Create threat dict (ensure all keys exist using .get())
            threat = {
                'type': 'subnet',
                'id': subnet,
                'total_requests': int(metrics.get('total_requests', 0)),
                'ip_count': int(metrics.get('ip_count', 0)),
                'subnet_avg_ip_rpm': round(metrics.get('subnet_avg_ip_rpm', 0), 2),
                'subnet_max_ip_rpm': round(metrics.get('subnet_max_ip_rpm', 0), 2),
                'subnet_total_avg_rpm': round(metrics.get('subnet_total_avg_rpm', 0), 2),
                'subnet_total_max_rpm': round(metrics.get('subnet_total_max_rpm', 0), 2),
                'subnet_time_span': round(metrics.get('subnet_time_span', 0), 2), # Use the correctly calculated span
                'subnet_req_per_min': round(metrics.get('subnet_req_per_min', 0), 2),
                'dominant_bot_name': metrics.get('dominant_bot_name', 'Unknown'), # ADDED bot name
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
        if not self._aggregate_subnet_metrics(): # This now calculates the correct timespan
            return []

        self._format_threat_output()

        logger.info(f"Threat identification complete. Found {len(self.unified_threats)} subnet threats.")
        return self.unified_threats

    def export_results(self, format_type, output_file, config=None, threats=None):
        """
        Exports the identified threats to a specified format.
        Accepts the primary threats list.
        """
        if threats is None:
             logger.error("No threat data provided for export.")
             return False

        logger.info(f"Preparing to export {len(threats)} individual threats to {output_file} in {format_type} format.")

        # Convert threat data for export (handle ipaddress objects)
        export_data = []
        for threat in threats:
             # Create a copy to avoid modifying the original dict
             threat_copy = threat.copy()
             # Convert ipaddress object ID to string
             if isinstance(threat_copy.get('id'), (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                 threat_copy['id'] = str(threat_copy['id'])
             # Convert details IP objects if necessary (should already be strings based on identify_threats)
             # Ensure all data is serializable
             for key, value in threat_copy.items():
                 if isinstance(value, (datetime, pd.Timestamp)):
                     threat_copy[key] = value.isoformat()
                 elif isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network, ipaddress.IPv4Address, ipaddress.IPv6Address)):
                      threat_copy[key] = str(value) # Catch any other potential IP objects
                 # Ensure details list is serializable (IPs should be strings)
                 elif key == 'details' and isinstance(value, list):
                      threat_copy[key] = [
                          {k: str(v) if isinstance(v, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else v for k, v in detail.items()}
                          for detail in value
                      ]


             export_data.append(threat_copy)


        try:
            df_export = pd.DataFrame(export_data)
            # Reorder columns for clarity if needed
            # Define desired column order, including the corrected timespan and req/min
            cols_order = [
                'id', 'strategy_score', 'should_block', 'block_reason',
                'total_requests', 'ip_count',
                'dominant_bot_name', # ADDED bot name
                'subnet_avg_ip_rpm', 'subnet_max_ip_rpm',
                'subnet_total_avg_rpm', 'subnet_total_max_rpm',
                'subnet_req_per_min', # ADDED new metric
                'subnet_time_span', # Ensure this is included
                'details'
            ]
            # Get columns present in the DataFrame, maintaining the desired order
            cols_present = [col for col in cols_order if col in df_export.columns]
            # Add any remaining columns not in the desired order list
            remaining_cols = [col for col in df_export.columns if col not in cols_present]
            df_export = df_export[cols_present + remaining_cols]


            if format_type == 'csv':
                # Handle list in 'details' column for CSV export
                df_export['details'] = df_export['details'].apply(lambda x: json.dumps(x) if isinstance(x, list) else x)
                df_export.to_csv(output_file, index=False)
            elif format_type == 'json':
                # Use records orientation for a list of JSON objects
                df_export.to_json(output_file, orient='records', indent=4)
            elif format_type == 'text':
                # Basic text output, similar to console but to file
                with open(output_file, 'w') as f:
                    # You might want to replicate the console output format here
                    f.write(df_export.to_string(index=False))
            else:
                logger.error(f"Unsupported export format: {format_type}")
                return False
            return True
        except Exception as e:
            logger.error(f"Failed to export results to {output_file}: {e}", exc_info=True)
            return False