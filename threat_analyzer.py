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

    def _calculate_ip_metrics(self, analysis_duration_seconds=None):
        """Calculates simplified metrics per IP address - only essential data for blocking."""
        if self.log_df is None or self.log_df.empty:
            logger.warning("Log DataFrame is not loaded or empty. Cannot calculate IP metrics.")
            return False

        logger.info("Calculating simplified IP metrics...")

        try:
            # Use DataFrame index if it's datetime, otherwise use timestamp column
            if isinstance(self.log_df.index, pd.DatetimeIndex):
                temp_df = self.log_df.reset_index()
                ts_col_name = temp_df.columns[0]
            else:
                temp_df = self.log_df
                ts_col_name = 'timestamp'

            # Calculate only essential IP metrics: total requests and req/hour
            basic_agg = temp_df.groupby('ip').agg(
                total_requests=('ip', 'count')
            )

            # Calculate Requests per Hour (for high-rate IP blocking)
            if analysis_duration_seconds and analysis_duration_seconds > 0:
                analysis_duration_hours = analysis_duration_seconds / 3600.0
                basic_agg['req_per_hour'] = basic_agg['total_requests'] / analysis_duration_hours
            else:
                basic_agg['req_per_hour'] = 0.0
                logger.warning("Analysis duration unknown. 'req_per_hour' for IPs set to 0.")

            # Add Subnet Information
            basic_agg['subnet'] = basic_agg.index.map(get_subnet)
            rows_before = len(basic_agg)
            basic_agg = basic_agg.dropna(subset=['subnet'])
            if rows_before > len(basic_agg):
                logger.warning(f"Dropped {rows_before - len(basic_agg)} IPs due to missing subnet.")

            self.ip_metrics_df = basic_agg
            logger.info(f"Calculated simplified metrics for {len(self.ip_metrics_df)} IPs.")
            return True

        except Exception as e:
            logger.error(f"Error during IP metrics calculation: {e}", exc_info=True)
            return False

    def _calculate_subnet_rpm_metrics(self):
        """Calculates total RPM metrics per Subnet. (REMOVED - No longer needed for current strategies)"""
        logger.debug("Subnet total RPM calculation skipped (metrics removed).")
        # Return empty DataFrame with expected columns (or None)
        # Returning empty DF to avoid breaking join logic downstream if it expects a DF
        return pd.DataFrame(columns=[]) # No columns needed anymore

    def _aggregate_subnet_metrics(self, analysis_duration_seconds=None):
        """Aggregates simplified metrics by subnet."""
        if self.ip_metrics_df is None or self.ip_metrics_df.empty:
            logger.warning("IP metrics DataFrame not available. Cannot aggregate subnet metrics.")
            return False

        logger.info("Aggregating simplified metrics by subnet...")
        
        if 'subnet' not in self.ip_metrics_df.columns:
            logger.error("'subnet' column missing from ip_metrics_df.")
            return False

        try:
            grouped = self.ip_metrics_df.groupby('subnet', observed=True)

            # Calculate essential subnet metrics only
            subnet_agg = grouped.agg({
                'total_requests': 'sum'
            })
            
            # Add IP count
            subnet_agg['ip_count'] = grouped.size()

            # Get first and last seen for timespan calculation
            if isinstance(self.log_df.index, pd.DatetimeIndex):
                log_indexed = self.log_df
            else:
                log_indexed = self.log_df.set_index('timestamp')
            
            # Calculate timespan per subnet from log data
            subnet_times = log_indexed.groupby('subnet').agg(
                first_seen=('ip', lambda x: x.index.min()),
                last_seen=('ip', lambda x: x.index.max())
            )
            subnet_agg = subnet_agg.join(subnet_times)
            subnet_agg['subnet_time_span'] = (
                subnet_agg['last_seen'] - subnet_agg['first_seen']
            ).dt.total_seconds().fillna(0).clip(lower=0)
            subnet_agg = subnet_agg.drop(columns=['first_seen', 'last_seen'])

            # Calculate RPM over analysis window
            if analysis_duration_seconds and analysis_duration_seconds > 0:
                subnet_agg['subnet_req_per_min_window'] = (
                    subnet_agg['total_requests'] / (analysis_duration_seconds / 60.0)
                )
            else:
                subnet_agg['subnet_req_per_min_window'] = 0.0

            # Ensure correct data types
            subnet_agg['total_requests'] = subnet_agg['total_requests'].astype(int)
            subnet_agg['ip_count'] = subnet_agg['ip_count'].astype(int)
            subnet_agg['subnet_time_span'] = subnet_agg['subnet_time_span'].astype(float)
            subnet_agg['subnet_req_per_min_window'] = subnet_agg['subnet_req_per_min_window'].astype(float)

            # Convert index to ipaddress objects
            from ipaddress import ip_network, IPv4Network, IPv6Network
            subnet_agg.index = subnet_agg.index.map(
                lambda x: ip_network(x, strict=False) if not isinstance(x, (IPv4Network, IPv6Network)) else x
            )

            self.subnet_metrics_df = subnet_agg
            logger.info(f"Aggregated metrics for {len(self.subnet_metrics_df)} subnets.")
            return True

        except Exception as e:
            logger.error(f"Error aggregating subnet metrics: {e}", exc_info=True)
            return False

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
        except ImportError:
            logger.error(f"Could not load strategy module: strategies.{strategy_name}.py")
            return None
        except AttributeError:
            logger.error(f"Strategy module strategies.{strategy_name}.py does not contain a 'Strategy' class.")
            return None
        except Exception as e:
             logger.error(f"An unexpected error occurred loading strategy '{strategy_name}': {e}", exc_info=True)
             return None

        # --- Calculate Maximums from self.subnet_metrics_df for strategy context ---
        strategy_context = shared_context_params.copy()

        if self.subnet_metrics_df is not None and not self.subnet_metrics_df.empty:
            logger.debug("Calculating maximums for strategy context...")
            # Only calculate max for essential metrics
            metrics_for_max = {
                'total_requests': 0,
                'ip_count': 0,
                'subnet_time_span': 0.0,
                'subnet_req_per_min_window': 0.0
            }
            for metric_key, default_value in metrics_for_max.items():
                if metric_key in self.subnet_metrics_df.columns:
                    max_val = self.subnet_metrics_df[metric_key].max()
                    if pd.notna(max_val):
                        if isinstance(default_value, int):
                            strategy_context[f'max_{metric_key}'] = int(max_val)
                        else:
                            strategy_context[f'max_{metric_key}'] = float(max_val)
                    else:
                        strategy_context[f'max_{metric_key}'] = default_value
                else:
                    strategy_context[f'max_{metric_key}'] = default_value
        else:
            logger.warning("Subnet metrics DataFrame is empty.")
            for key in ['max_total_requests', 'max_ip_count', 'max_subnet_time_span', 'max_subnet_req_per_min_window']:
                if key not in strategy_context:
                    strategy_context[key] = 0 if 'count' in key or 'requests' in key else 0.0


        # --- Apply strategy and build results list ---
        results = []
        if self.subnet_metrics_df is None or self.subnet_metrics_df.empty:
            logger.warning("Subnet metrics DataFrame is empty. Skipping strategy application.")
        else:
            logger.info(f"Applying '{strategy_name}' strategy to {len(self.subnet_metrics_df)} subnets...")
            start_time = time.time()
            for subnet_obj, metrics_row in self.subnet_metrics_df.iterrows():
                threat_data = metrics_row.to_dict()
                threat_data['id'] = subnet_obj

                # Calculate score and block decision using the strategy
                score, should_block, reason = strategy_instance.calculate_threat_score_and_block(
                    threat_data=threat_data,
                    config=config,
                    effective_min_requests=effective_min_requests,
                    shared_context_params=strategy_context
                )

                # Build simplified result
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
        """Exports the identified threats to a specified format (simplified)."""
        if threats is None:
            threats = self.unified_threats
            if not threats:
                logger.error("No threat data available. Cannot export.")
                return False

        logger.info(f"Exporting {len(threats)} threats to {output_file} in {format_type} format.")

        # Convert threat data for export
        export_data = []
        for threat in threats:
            threat_copy = threat.copy()
            # Convert ipaddress objects to strings
            for key, value in threat_copy.items():
                if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network, 
                                     ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    threat_copy[key] = str(value)
                elif isinstance(value, (np.integer, np.int64)):
                    threat_copy[key] = int(value)
                elif isinstance(value, (np.floating, np.float64)):
                    threat_copy[key] = float(value)
                elif isinstance(value, np.bool_):
                    threat_copy[key] = bool(value)
            export_data.append(threat_copy)

        try:
            df_export = pd.DataFrame(export_data)
            # Simplified column ordering
            cols_order = [
                'id', 'strategy_score', 'should_block', 'block_reason',
                'total_requests', 'ip_count',
                'subnet_req_per_min_window', 'subnet_time_span'
            ]
            cols_present = [col for col in cols_order if col in df_export.columns]
            remaining_cols = [col for col in df_export.columns if col not in cols_present]
            df_export = df_export[cols_present + remaining_cols]

            if format_type == 'csv':
                df_export.to_csv(output_file, index=False, quoting=csv.QUOTE_NONNUMERIC)
            elif format_type == 'json':
                df_export.to_json(output_file, orient='records', indent=4)
            elif format_type == 'text':
                with open(output_file, 'w') as f:
                    f.write(df_export.to_string(index=False, max_colwidth=100))
            else:
                logger.error(f"Unsupported export format: {format_type}")
                return False
            return True
        except Exception as e:
            logger.error(f"Failed to export results: {e}", exc_info=True)
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