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
import importlib # Needed for dynamic strategy loading
import time # Ensure time is imported

# Import from parser (Reverted)
from parser import (
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
             # Convert index to datetime if it's not already (might happen if loaded differently)
             if not pd.api.types.is_datetime64_any_dtype(self.log_df.index):
                 self.log_df['timestamp'] = pd.to_datetime(self.log_df['timestamp'], utc=True)
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

    def _calculate_ip_metrics(self, analysis_duration_seconds=None): # Add analysis_duration_seconds parameter
        """Calculates metrics per IP address using the loaded DataFrame."""
        if self.log_df is None or self.log_df.empty:
            logger.warning("Log DataFrame is not loaded or empty. Cannot calculate IP metrics.")
            return False
        # Ensure 'timestamp' column exists and is datetime
        # Use the DataFrame index if it's already datetime
        if isinstance(self.log_df.index, pd.DatetimeIndex):
             ts_col = self.log_df.index
             logger.debug("Using DataFrame index as timestamp source.")
        elif 'timestamp' in self.log_df.columns and pd.api.types.is_datetime64_any_dtype(self.log_df['timestamp']):
             ts_col = self.log_df['timestamp']
             logger.debug("Using 'timestamp' column as timestamp source.")
        else:
             logger.error("Log DataFrame missing a usable datetime index or 'timestamp' column.")
             # Attempt conversion if 'timestamp' column exists but isn't datetime
             if 'timestamp' in self.log_df.columns:
                 try:
                     self.log_df['timestamp'] = pd.to_datetime(self.log_df['timestamp'], utc=True)
                     if pd.api.types.is_datetime64_any_dtype(self.log_df['timestamp']):
                          logger.warning("Converted 'timestamp' column to datetime.")
                          ts_col = self.log_df['timestamp']
                     else:
                          raise ValueError("Conversion failed")
                 except Exception as e:
                     logger.error(f"Failed to convert 'timestamp' column to datetime: {e}", exc_info=True)
                     return False
             else:
                 return False # Cannot proceed without timestamps

        logger.info("Calculating metrics per IP...")

        # 1. Basic Aggregations (Total Requests, First/Last Seen, Time Span)
        logger.debug("Calculating total requests, first/last seen, time span per IP...")
        try:
            # Group by IP and aggregate directly
            # Use the identified timestamp source (ts_col might be index or column)
            # If ts_col is the index, we need to aggregate based on it.
            # If ts_col is a column, we aggregate based on it.
            # Let's ensure 'timestamp' column exists for simplicity here.
            if isinstance(ts_col, pd.Index):
                 # If timestamp is index, temporarily reset it for consistent aggregation
                 temp_df = self.log_df.reset_index()
                 ts_col_name = temp_df.columns[0] # Get the name of the reset index column
            else:
                 temp_df = self.log_df
                 ts_col_name = 'timestamp'

            basic_agg = temp_df.groupby('ip').agg(
                total_requests=('ip', 'count'),
                first_seen=(ts_col_name, 'min'),
                last_seen=(ts_col_name, 'max')
            )
            # Calculate time span directly on the aggregated result
            basic_agg['time_span_seconds'] = (basic_agg['last_seen'] - basic_agg['first_seen']).dt.total_seconds().fillna(0).clip(lower=0)

            # Calculate Requests per Hour (using analysis window duration)
            if analysis_duration_seconds and analysis_duration_seconds > 0:
                analysis_duration_hours = analysis_duration_seconds / 3600.0
                basic_agg['req_per_hour'] = basic_agg['total_requests'] / analysis_duration_hours
            else:
                basic_agg['req_per_hour'] = 0.0 # Cannot calculate if duration is unknown or zero
                logger.warning("Analysis duration is zero or unknown. 'req_per_hour' for IPs set to 0.")


        except Exception as e:
             logger.error(f"Error during basic IP aggregation: {e}", exc_info=True)
             return False
        logger.debug(f"Calculated basic aggregations for {len(basic_agg)} IPs.")


        # 2. RPM Metrics (Average and Max during active minutes)
        logger.debug("Calculating RPM metrics (avg/max during activity)...")
        rpm_metrics = pd.DataFrame(index=basic_agg.index, columns=['avg_rpm_activity', 'max_rpm_activity']).fillna(0.0) # Initialize with correct index and default float
        try:
            # Ensure log_df has datetime index for resampling
            if not isinstance(self.log_df.index, pd.DatetimeIndex):
                 # If 'timestamp' column exists and is datetime, set it as index
                 if 'timestamp' in self.log_df.columns and pd.api.types.is_datetime64_any_dtype(self.log_df['timestamp']):
                     log_df_indexed = self.log_df.set_index('timestamp')
                     if not isinstance(log_df_indexed.index, pd.DatetimeIndex):
                          raise ValueError("Index is not datetime after set_index.")
                 else:
                      # This case should have been caught earlier, but double-check
                      raise ValueError("Cannot create datetime index for RPM calculation.")
            else:
                 log_df_indexed = self.log_df # Already has datetime index

            # Resample per minute, count requests per IP, filter inactive minutes
            # Use observed=True if pandas version >= 1.5 for potential performance improvement with categorical IPs
            rpm_counts = log_df_indexed.groupby('ip', observed=True).resample('T').size()
            rpm_counts = rpm_counts[rpm_counts > 0] # Keep only minutes with activity

            if not rpm_counts.empty:
                # Calculate avg and max RPM for IPs that had activity
                # Group by the 'ip' level of the MultiIndex
                grouped_rpm = rpm_counts.groupby(level='ip')
                avg_rpm = grouped_rpm.mean()
                max_rpm = grouped_rpm.max()

                # Create DataFrame with results
                rpm_metrics_calculated = pd.DataFrame({
                    'avg_rpm_activity': avg_rpm,
                    'max_rpm_activity': max_rpm
                })
                # Update the initialized rpm_metrics DataFrame, keeping IPs with no multi-minute activity at 0
                rpm_metrics.update(rpm_metrics_calculated)
                logger.debug(f"Calculated RPM metrics for {len(rpm_metrics_calculated)} IPs with multi-minute activity.")
            else:
                 logger.debug("No multi-minute activity found for RPM calculation.")

        except Exception as e:
            logger.error(f"Error calculating RPM metrics: {e}", exc_info=True)
            # Continue with RPM metrics as 0, but log the error

        # 3. Combine Metrics
        logger.debug("Combining basic and RPM metrics...")
        self.ip_metrics_df = basic_agg.join(rpm_metrics, how='left')
        # Fill any potential NaNs from join (though initialization should prevent this)
        # Keep avg_rpm_activity and max_rpm_activity
        self.ip_metrics_df[['avg_rpm_activity', 'max_rpm_activity', 'req_per_hour']] = self.ip_metrics_df[['avg_rpm_activity', 'max_rpm_activity', 'req_per_hour']].fillna(0) # Add req_per_hour to fillna
        logger.debug("Metrics combined.")

        # 4. Add Subnet Information
        logger.debug("Adding subnet information...")
        try:
            # Use the IP index to map to subnets
            self.ip_metrics_df['subnet'] = self.ip_metrics_df.index.map(get_subnet)
            # Drop IPs where subnet couldn't be determined (e.g., invalid IP format somehow)
            rows_before_drop = len(self.ip_metrics_df)
            self.ip_metrics_df = self.ip_metrics_df.dropna(subset=['subnet'])
            rows_after_drop = len(self.ip_metrics_df)
            if rows_before_drop > rows_after_drop:
                 logger.warning(f"Dropped {rows_before_drop - rows_after_drop} IPs due to missing subnet information.")
            logger.debug("Subnet information added.")
        except Exception as e:
             logger.error(f"Error adding subnet information to ip_metrics_df: {e}", exc_info=True)
             return False # Subnet info is crucial for aggregation

        logger.info(f"Finished calculating metrics for {len(self.ip_metrics_df)} IPs.")
        return True

    def _calculate_subnet_rpm_metrics(self):
        """Calculates total RPM metrics per Subnet. (REMOVED - No longer needed for current strategies)"""
        logger.debug("Subnet total RPM calculation skipped (metrics removed).")
        # Return empty DataFrame with expected columns (or None)
        # Returning empty DF to avoid breaking join logic downstream if it expects a DF
        return pd.DataFrame(columns=[]) # No columns needed anymore

    def _aggregate_subnet_metrics(self, analysis_duration_seconds=None):
        """Aggregates IP metrics using a more robust join approach. (Removed some metrics)"""
        if self.ip_metrics_df is None or self.ip_metrics_df.empty:
            logger.warning("IP metrics DataFrame not available. Cannot aggregate subnet metrics.")
            return False

        logger.info("Aggregating metrics by subnet...")
        if 'subnet' not in self.ip_metrics_df.columns:
             logger.error("'subnet' column missing from ip_metrics_df. Cannot proceed.")
             return False

        # --- 1. Calculate Aggregations from ip_metrics_df ---
        logger.debug("Calculating primary aggregations from ip_metrics_df...")
        try:
            # Use observed=True if pandas version supports it
            grouped_ips = self.ip_metrics_df.groupby('subnet', observed=True)

            agg_funcs = {
                'total_requests': 'sum',
                'first_seen': 'min',
                'last_seen': 'max',
                # Remove aggregation of IP RPMs
                # 'avg_rpm_activity': 'mean', # Avg of IP avgs - REMOVED
                # 'max_rpm_activity': 'max'   # Max of IP maxs - REMOVED
            }
            # Calculate ip_count separately
            ip_counts = grouped_ips.size().rename('ip_count')

            # Perform main aggregations
            agg_main = grouped_ips.agg(agg_funcs)

            # Join ip_counts
            agg1 = agg_main.join(ip_counts, how='left').fillna({'ip_count': 0}) # Ensure ip_count is filled if join fails unexpectedly
            agg1['ip_count'] = agg1['ip_count'].astype(int)

            # Rename columns for clarity before calculating derived metrics
            agg1 = agg1.rename(columns={
                # Removed IP RPM renames
                'first_seen': 'subnet_first_seen',
                'last_seen': 'subnet_last_seen'
            })

            # Calculate subnet_time_span (vectorized)
            agg1['subnet_time_span'] = (agg1['subnet_last_seen'] - agg1['subnet_first_seen']).dt.total_seconds().fillna(0).clip(lower=0)

            # Calculate Requests per Minute over the entire analysis window (vectorized)
            if analysis_duration_seconds and analysis_duration_seconds > 0:
                agg1['subnet_req_per_min_window'] = agg1['total_requests'] / (analysis_duration_seconds / 60.0)
                # Calculate Requests per Hour over the entire analysis window (vectorized)
                analysis_duration_hours = analysis_duration_seconds / 3600.0
                agg1['subnet_req_per_hour'] = agg1['total_requests'] / analysis_duration_hours
            else:
                agg1['subnet_req_per_min_window'] = 0.0 # Or np.nan if preferred
                agg1['subnet_req_per_hour'] = 0.0 # Or np.nan if preferred


            # Drop intermediate timestamp columns
            agg1 = agg1.drop(columns=['subnet_first_seen', 'subnet_last_seen'], errors='ignore')

            # Ensure index is the correct type (ipaddress object)
            agg1.index = agg1.index.map(lambda x: ip_network(x, strict=False) if not isinstance(x, (IPv4Network, IPv6Network)) else x)

            logger.debug(f"Primary aggregation complete for {len(agg1)} subnets.")

        except Exception as e:
            logger.error(f"Error during primary aggregation: {e}", exc_info=True)
            return False

        # --- 2. Calculate Subnet Total RPM metrics from log_df ---
        # logger.debug("Calculating Subnet Total RPM metrics from log_df...") # SKIPPED
        agg2 = self._calculate_subnet_rpm_metrics() # Returns empty DF

        # --- 3. Combine the aggregations ---
        logger.debug("Joining aggregated metrics...")
        try:
            # Start with the primary aggregation
            self.subnet_metrics_df = agg1

            # Join the subnet total RPM metrics (agg2 is empty, so join won't add columns)
            if not agg2.empty:
                 agg2_reindexed = agg2.reindex(self.subnet_metrics_df.index).fillna(0.0)
                 self.subnet_metrics_df = self.subnet_metrics_df.join(agg2_reindexed, how='left')

            # Fill any remaining NaNs that might have occurred
            numeric_cols = self.subnet_metrics_df.select_dtypes(include=np.number).columns
            self.subnet_metrics_df[numeric_cols] = self.subnet_metrics_df[numeric_cols].fillna(0)

            logger.debug(f"Final combined subnet metrics (before type conversion):\n{self.subnet_metrics_df.head()}")

        except Exception as e:
             logger.error(f"Error joining aggregated subnet metrics: {e}", exc_info=True)
             return False

        # --- 4. Ensure correct data types ---
        logger.debug("Ensuring correct data types...")
        try:
            expected_types = {
                'total_requests': int,
                'ip_count': int,
                # Removed IP RPMs
                'subnet_time_span': float,
                # Removed subnet_req_per_min
                'subnet_req_per_min_window': float,
                'subnet_req_per_hour': float, # ADDED subnet_req_per_hour
                # Removed Subnet Total RPMs
            }
            for col, dtype in expected_types.items():
                if col in self.subnet_metrics_df.columns:
                    # Ensure column is numeric before converting, coercing errors
                    self.subnet_metrics_df[col] = pd.to_numeric(self.subnet_metrics_df[col], errors='coerce').fillna(0)
                    # Convert to the target type
                    if dtype == int:
                         self.subnet_metrics_df[col] = self.subnet_metrics_df[col].astype(int)
                    else:
                         self.subnet_metrics_df[col] = self.subnet_metrics_df[col].astype(float)
                else:
                    logger.warning(f"Column '{col}' missing before type conversion. Adding as {dtype}(0).")
                    self.subnet_metrics_df[col] = dtype(0) # Add column with default value

        except Exception as e:
             logger.error(f"Error converting data types for subnet metrics: {e}", exc_info=True)
             # Continue, but data types might be incorrect

        logger.info(f"Finished aggregating metrics for {len(self.subnet_metrics_df)} subnets.")
        logger.debug(f"Final combined subnet metrics (after type conversion):\n{self.subnet_metrics_df.head()}")
        return True

    def identify_threats(self,
                         strategy_name,
                         effective_min_requests,
                         shared_context_params, # MODIFIED: Replaces individual context/max args
                         config):
        """
        Orchestrates the calculation of IP metrics, aggregation by subnet,
        strategy application, and formatting the final threat list.
        Requires self.log_df to be set externally.
        """
        # --- Extract necessary parameters from shared_context_params ---
        analysis_duration_seconds = shared_context_params.get('analysis_duration_seconds', 0)
        # total_overall_requests = shared_context_params.get('total_overall_requests', 0) # Available if needed
        # system_load_avg = shared_context_params.get('system_load_avg', -1.0) # Available if needed

        # --- Ensure 'subnet' column exists in log_df ---
        if self.log_df is None or self.log_df.empty:
             logger.error("log_df is not set or is empty. Cannot identify threats.")
             return None # Return None to indicate failure

        if 'subnet' not in self.log_df.columns:
            logger.info("Adding 'subnet' column to log_df...")
            try:
                self.log_df['subnet'] = self.log_df['ip'].map(get_subnet)
                initial_rows = len(self.log_df)
                self.log_df = self.log_df.dropna(subset=['subnet'])
                dropped_rows = initial_rows - len(self.log_df)
                if dropped_rows > 0:
                     logger.warning(f"Dropped {dropped_rows} rows due to missing subnet information.")
                logger.info("'subnet' column added.")
            except Exception as e:
                 logger.error(f"Failed to add 'subnet' column: {e}", exc_info=True)
                 return None # Cannot proceed without subnet

        # --- Calculate Metrics ---
        start_time = time.time()
        if not self._calculate_ip_metrics(analysis_duration_seconds=analysis_duration_seconds):
            logger.error("Failed during IP metrics calculation.")
            return None
        logger.info(f"IP metrics calculation took {time.time() - start_time:.2f} seconds.")

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
            # Store config for strategy use (if needed by strategy, passed directly now)
            # self.config = config # No longer storing config in self
        except ImportError:
            logger.error(f"Could not load strategy module: strategies.{strategy_name}.py")
            return None
        except AttributeError:
            logger.error(f"Strategy module strategies.{strategy_name}.py does not contain a 'Strategy' class.")
            return None
        except Exception as e:
             logger.error(f"An unexpected error occurred loading strategy '{strategy_name}': {e}", exc_info=True)
             return None


        # --- Calculate Maximums for Normalization (REMOVED - now part of shared_context_params) ---
        # max_total_requests, max_subnet_time_span, max_ip_count are now expected
        # directly within shared_context_params if the strategy needs them.
        # Example: max_total_requests = shared_context_params.get('max_total_requests', 0)
        # These were already calculated in blocker.py and put into shared_context_params.


        # --- Prepare Top IP Details (Efficiently) ---
        top_ips_details = {}
        if self.ip_metrics_df is not None and not self.ip_metrics_df.empty:
            logger.debug("Preparing top IP details per subnet...")
            try:
                # Sort IPs by max_rpm_activity descending, group by subnet, take top 5
                top_ips_per_subnet = self.ip_metrics_df.sort_values('max_rpm_activity', ascending=False) \
                                                    .groupby('subnet', observed=True) \
                                                    .head(5) # Get top 5 rows per group

                # Convert these top IPs into the desired dictionary format per subnet
                for subnet, group_df in top_ips_per_subnet.groupby('subnet', observed=True):
                    details_list = []
                    for ip, ip_metrics in group_df.iterrows():
                        details_list.append({
                            'ip': str(ip), # Ensure IP is string
                            'total_requests': int(ip_metrics.get('total_requests', 0)),
                            'avg_rpm': round(ip_metrics.get('avg_rpm_activity', 0), 2),
                            'max_rpm': round(ip_metrics.get('max_rpm_activity', 0), 2),
                        })
                    top_ips_details[subnet] = details_list
                logger.debug(f"Prepared details for {len(top_ips_details)} subnets.")
            except Exception as e:
                logger.error(f"Error preparing top IP details: {e}", exc_info=True)
                # Continue without details if preparation fails


        # --- Apply strategy and build results list ---
        results = []
        if self.subnet_metrics_df is None or self.subnet_metrics_df.empty:
             logger.warning("Subnet metrics DataFrame is empty. Skipping strategy application.")
        else:
             logger.info(f"Applying '{strategy_name}' strategy to {len(self.subnet_metrics_df)} subnets...")
             start_time = time.time()
             for subnet_obj, metrics_row in self.subnet_metrics_df.iterrows():
                 threat_data = metrics_row.to_dict()
                 threat_data['id'] = subnet_obj # Ensure subnet_id object is in the dict

                 # Calculate score and block decision using the strategy
                 score, should_block, reason = strategy_instance.calculate_threat_score_and_block(
                     threat_data=threat_data,
                     config=config, # Pass command line args directly
                     effective_min_requests=effective_min_requests,
                     shared_context_params=shared_context_params # MODIFIED: Pass the whole dict
                 )

                 # Build the final dictionary for this threat
                 threat_result = {
                     'type': 'subnet',
                     'id': subnet_obj, # Keep as object for now, convert during export
                     'total_requests': int(threat_data.get('total_requests', 0)),
                     'ip_count': int(threat_data.get('ip_count', 0)),
                     'subnet_time_span': round(threat_data.get('subnet_time_span', 0), 2),
                     'subnet_req_per_min_window': round(threat_data.get('subnet_req_per_min_window', 0), 2),
                     'subnet_req_per_hour': round(threat_data.get('subnet_req_per_hour', 0), 2), # ADDED: Include subnet_req_per_hour
                     'details': top_ips_details.get(subnet_obj, []), # Get pre-calculated details
                     'strategy_score': score, # Use calculated score
                     'should_block': should_block, # Use calculated decision
                     'block_reason': reason # Use calculated reason
                 }
                 results.append(threat_result)
             logger.info(f"Strategy application took {time.time() - start_time:.2f} seconds.")

        # --- Sort Results ---
        results.sort(key=lambda x: x.get('strategy_score', 0), reverse=True)

        # --- Store final list ---
        self.unified_threats = results # Store the results list

        logger.info(f"Threat identification complete. Found {len(self.unified_threats)} subnet threats.")
        return self.unified_threats

    def export_results(self, format_type, output_file, config=None, threats=None):
        """
        Exports the identified threats to a specified format.
        Accepts the primary threats list. Handles data type serialization.
        """
        if threats is None:
             # Use self.unified_threats if available
             threats = self.unified_threats
             if not threats:
                 logger.error("No threat data available (checked input and self.unified_threats). Cannot export.")
                 return False

        logger.info(f"Preparing to export {len(threats)} threats to {output_file} in {format_type} format.")

        # Convert threat data for export (handle ipaddress, datetime, numpy types)
        export_data = []
        for threat in threats:
             # Create a copy to avoid modifying the original dict
             threat_copy = threat.copy()
             # Convert specific fields
             for key, value in threat_copy.items():
                 if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network, ipaddress.IPv4Address, ipaddress.IPv6Address)):
                     threat_copy[key] = str(value)
                 elif isinstance(value, (datetime, pd.Timestamp)):
                     # Ensure timezone info is handled correctly if present
                     if value.tzinfo:
                         threat_copy[key] = value.isoformat()
                     else:
                         # If somehow naive, assume UTC or local? Let's assume UTC for consistency.
                         threat_copy[key] = value.replace(tzinfo=timezone.utc).isoformat()
                 elif isinstance(value, (np.integer, np.int64)):
                     threat_copy[key] = int(value)
                 elif isinstance(value, (np.floating, np.float64)):
                     threat_copy[key] = float(value)
                 elif isinstance(value, np.bool_):
                      threat_copy[key] = bool(value)
                 # Ensure details list is serializable (IPs should be strings already, but double-check)
                 elif key == 'details' and isinstance(value, list):
                      # Assuming details were already prepared with string IPs
                      threat_copy[key] = value # Keep as is if already serializable
                      # If details might contain non-serializable types, add conversion here:
                      # threat_copy[key] = [
                      #     {k: str(v) if isinstance(v, ...) else v for k, v in detail.items()}
                      #     for detail in value
                      # ]

             export_data.append(threat_copy)


        try:
            df_export = pd.DataFrame(export_data)
            # Reorder columns for clarity - REMOVED metrics
            cols_order = [
                'id', 'strategy_score', 'should_block', 'block_reason',
                'total_requests', 'ip_count',
                'subnet_req_per_min_window',
                'subnet_req_per_hour', # ADDED: Include subnet_req_per_hour
                'subnet_time_span',
                'details'
            ]
            # Get columns present in the DataFrame, maintaining the desired order
            cols_present = [col for col in df_export.columns if col in cols_order]
            # Add any remaining columns not in the desired order list
            remaining_cols = [col for col in df_export.columns if col not in cols_present]
            df_export = df_export[cols_present + remaining_cols]


            if format_type == 'csv':
                # Handle list in 'details' column for CSV export by converting to JSON string
                if 'details' in df_export.columns:
                    df_export['details'] = df_export['details'].apply(lambda x: json.dumps(x) if isinstance(x, list) else x)
                df_export.to_csv(output_file, index=False, quoting=csv.QUOTE_NONNUMERIC) # Ensure proper quoting
            elif format_type == 'json':
                # Use records orientation for a list of JSON objects
                df_export.to_json(output_file, orient='records', indent=4, date_format='iso') # Ensure ISO date format
            elif format_type == 'text':
                # Basic text output, similar to console but to file
                with open(output_file, 'w') as f:
                    # Use pandas to_string with adjusted width for better readability
                    f.write(df_export.to_string(index=False, max_colwidth=100))
            else:
                logger.error(f"Unsupported export format: {format_type}")
                return False
            return True
        except Exception as e:
            logger.error(f"Failed to export results to {output_file}: {e}", exc_info=True)
            return False

    def get_threats_df(self):
        """Returns the identified threats as a DataFrame, converting ID to string."""
        if not self.unified_threats:
            logger.warning("No threats identified or stored in unified_threats list.")
            return pd.DataFrame() # Return empty DataFrame
        try:
            # Convert the list of dictionaries directly to a DataFrame
            df = pd.DataFrame(self.unified_threats)
            # Convert the 'id' column (ipaddress objects) to string for consistent indexing/lookup
            if 'id' in df.columns:
                 df['id_str'] = df['id'].astype(str) # Create a string version
                 df = df.set_index('id_str') # Set the string version as index
                 # Optionally drop the original 'id' object column if no longer needed
                 # df = df.drop(columns=['id'])
            return df
        except Exception as e:
            logger.error(f"Error converting unified_threats list to DataFrame: {e}", exc_info=True)
            return pd.DataFrame() # Return empty DataFrame on error