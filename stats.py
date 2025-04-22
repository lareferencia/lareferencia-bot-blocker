#!/usr/bin/env python3
"""
Main script for log analysis and bot threat detection using Pandas and configurable strategies.
"""
import argparse
import re
from datetime import datetime, timedelta, timezone
import sys
import os
import logging
import ipaddress
import pandas as pd
import importlib # For dynamic strategy loading
from collections import defaultdict # For grouping /16s
import time # Import time module

# Import own modules
# Remove LogParser from import, keep functions
from parser import get_subnet, is_ip_in_whitelist, load_log_into_dataframe
# Import UFWManager and COMMENT_PREFIX directly if needed
import ufw_handler
from threat_analyzer import ThreatAnalyzer

# Logging configuration
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

def setup_logging(log_file=None, log_level=logging.INFO):
    """
    Configure the logging system.
    
    Args:
        log_file (str, optional): Path to the log file
        log_level (int): Logging level
    """
    handlers = []
    
    # Always add console handler
    console = logging.StreamHandler()
    console.setLevel(log_level)
    console.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
    handlers.append(console)
    
    # Add file handler if specified
    if (log_file):
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
        handlers.append(file_handler)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        handlers=handlers
    )

def calculate_start_date(time_window):
    """
    Calculate the start date according to the specified time window.
    
    Args:
        time_window (str): 'hour', '6hour', 'day', or 'week'
    
    Returns:
        datetime: Datetime object corresponding to the start date
    """
    now = datetime.now()
    if time_window == 'hour':
        return now - timedelta(hours=1)
    elif time_window == '6hour': # Add new option
        return now - timedelta(hours=6)
    elif time_window == 'day':
        return now - timedelta(days=1)
    elif time_window == 'week':
        return now - timedelta(weeks=1)
    return None

def main():
    parser = argparse.ArgumentParser(
        description='Analyzes logs using Pandas and configurable strategies, optionally blocks threats with UFW.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Show defaults in help
    )
    # --- File/Time Args ---
    parser.add_argument(
        '--file', '-f', required=False,
        help='Path of the log file to analyze (required unless --clean-rules is used).'
    )
    parser.add_argument(
        '--start-date', '-s', required=False, default=None,
        help='Analyze logs from this date. Format: dd/mmm/yyyy:HH:MM:SS.'
    )
    parser.add_argument(
        '--time-window', '-tw', required=False,
        choices=['hour', '6hour', 'day', 'week'], # Add '6hour' choice
        help='Analyze logs from the last hour, 6 hours, day, or week (overrides --start-date).'
    )
    # --- Analysis Args ---
    parser.add_argument(
        '--top', '-n', type=int, default=10,
        help='Number of top threats (/24 or /64) to display/consider for blocking.'
    )
    parser.add_argument(
        '--whitelist', '-w',
        help='File with IPs/subnets to exclude from analysis.'
    )
    # --- Blocking Strategy Args ---
    parser.add_argument(
        '--block', action='store_true',
        help='Enable blocking of detected threats using UFW.'
    )
    parser.add_argument('--block-strategy', type=str, default='combined',
                        choices=[
                            'combined',
                            'volume_coordination',
                            ],
                        help='Strategy to use for scoring and blocking decisions.')
    parser.add_argument(
        '--block-relative-threshold-percent', type=float, default=1, # Default might need adjustment based on typical max requests
        help='Base threshold for initial consideration (most strategies). '
             'For "combined" strategy, used as the MANDATORY threshold percentage against the SUM of ALL requests in the window (Condition 2).' # UPDATED help
    )
    parser.add_argument(
        '--block-ip-count-threshold', type=int, default=10,
        help='Strategy threshold: Minimum unique IPs (used by volume_coordination). Ignored by "combined" blocking logic.' # Clarified usage
    )
    parser.add_argument(
        '--block-max-rpm-threshold', type=float, default=10,
        help='Strategy threshold: Minimum peak RPM from any IP (used by volume_peak_rpm). Ignored by "combined" blocking logic.' # Clarified usage
    )
    parser.add_argument(
        '--block-total-max-rpm-threshold', type=float, default=20, # Default might need adjustment
        help='Strategy threshold: Minimum peak TOTAL SUBNET RPM (used by peak_total_rpm). '
             'For "combined" strategy, used as the MANDATORY threshold for average Req/Min(Win) (Condition 3).' # Correcto
    )
    # --- Add argument for combined strategy ---
    parser.add_argument(
        '--block-trigger-count', type=int, default=2,
        help='Strategy threshold: Minimum number of original triggers met. Ignored by "combined" blocking logic.' # Clarified usage for scoring only
    )
    # --- End of removed arguments ---
    parser.add_argument(
        '--block-duration', type=int, default=60,
        help='Duration of the UFW block in minutes (used for all blocks).'
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Show UFW commands without executing them.'
    )
    # --- Output Args ---
    parser.add_argument(
        '--output', '-o',
        help='File to save the analysis results.'
    )
    parser.add_argument(
        '--format', choices=['json', 'csv', 'text'], default='text',
        help='Output format for the results file.'
    )
    parser.add_argument(
        '--log-file', help='File to save execution logs.'
    )
    parser.add_argument(
        '--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO',
        help='Log detail level.'
    )
    # --- Utility Args ---
    parser.add_argument(
        '--clean-rules', action='store_true',
        help='Run cleanup of expired UFW rules and exit.'
    )
    parser.add_argument(
        '--silent', action='store_true',
        help='Suppress most output, only show blocked targets.'
    )
    args = parser.parse_args()

    # --- Logging Setup ---
    log_level = getattr(logging, args.log_level)
    # If silent, force log level to WARNING for console unless DEBUG is explicitly set
    if args.silent and log_level < logging.WARNING and log_level != logging.DEBUG:
        log_level_console = logging.WARNING
    else:
        log_level_console = log_level
    # Setup logging (adjust setup_logging if needed or handle console level here)
    # Assuming setup_logging primarily sets the root logger level and file handler level
    # We might need to adjust the console handler level specifically
    setup_logging(args.log_file, log_level) # Setup root and file logger
    logger = logging.getLogger('botstats.main')

    # Adjust console handler level if silent mode is active
    for handler in logging.root.handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
             if args.silent and log_level < logging.WARNING and log_level != logging.DEBUG:
                 logger.debug(f"Silent mode: Setting console log level to WARNING (was {logging.getLevelName(log_level)})")
                 handler.setLevel(logging.WARNING)
             else:
                 # Ensure console handler respects the requested log_level if not silent
                 handler.setLevel(log_level)


    # --- Clean Rules Mode ---
    if args.clean_rules:
        logger.info("Starting cleanup of expired UFW rules...")
        # Instance is already created here for cleanup
        ufw_manager_instance = ufw_handler.UFWManager(args.dry_run)
        count = ufw_manager_instance.clean_expired_rules()
        logger.info("Cleanup completed. Rules deleted: %d", count)
        return

    # --- File Validation ---
    if not args.file:
        parser.error("the following arguments are required: --file/-f (unless --clean-rules is used)")
        sys.exit(1)
    if not os.path.exists(args.file):
        logger.error(f"Error: File not found {args.file}")
        sys.exit(1)

    # --- Date Calculation ---
    start_date_utc = None
    analysis_duration_seconds = 0 # Default to 0 if no window specified
    now_utc = datetime.now(timezone.utc) # Get current time once

    if args.time_window:
        start_date_naive_local = calculate_start_date(args.time_window)
        if start_date_naive_local:
             start_date_aware_local = start_date_naive_local.astimezone()
             start_date_utc = start_date_aware_local.astimezone(timezone.utc)
             analysis_duration_seconds = (now_utc - start_date_utc).total_seconds()
             logger.info(f"Using time window: {args.time_window} (from {start_date_utc}, duration: {analysis_duration_seconds:.0f}s)")
    elif args.start_date:
        try:
            start_date_naive_local = datetime.strptime(args.start_date, '%d/%b/%Y:%H:%M:%S')
            # Assume the start date is in the local timezone of the server logs
            # Convert it to aware local time, then to UTC
            start_date_aware_local = start_date_naive_local.astimezone() # Make it timezone-aware using local system tz
            start_date_utc = start_date_aware_local.astimezone(timezone.utc) # Convert to UTC
            analysis_duration_seconds = (now_utc - start_date_utc).total_seconds()
            logger.info(f"Using start date: {start_date_utc} (duration until now: {analysis_duration_seconds:.0f}s)")
        except ValueError:
            logger.error("Error: Invalid date format. Use dd/mmm/yyyy:HH:MM:SS")
            sys.exit(1)
    else:
        logger.info("No time window or start date specified. Analyzing entire file. Dynamic timespan check in 'coordinated_sustained' will be skipped.")


    # --- Load Strategy ---
    strategy_name = args.block_strategy
    try:
        strategy_module = importlib.import_module(f"strategies.{strategy_name}")
        # Assumes each strategy module has a class named 'Strategy'
        strategy_instance = strategy_module.Strategy()
        logger.info(f"Using blocking strategy: {strategy_name}")
        # Optional: Validate required config keys?
        # required_keys = strategy_instance.get_required_config_keys()
        # Check if args has all required_keys...
    except ImportError:
        logger.error(f"Could not load strategy module: strategies.{strategy_name}.py")
        sys.exit(1)
    except AttributeError:
        logger.error(f"Strategy module strategies.{strategy_name}.py does not contain a 'Strategy' class.")
        sys.exit(1)


    # --- Analysis ---
    # Pass rpm_threshold? Currently unused by analyzer directly.
    analyzer = ThreatAnalyzer(whitelist=None) # Whitelist loaded separately
    if args.whitelist:
        analyzer.load_whitelist_from_file(args.whitelist)

    logger.info(f"Starting analysis of {args.file}...")
    total_overall_requests = 0 # Initialize
    log_df = None # Initialize log_df

    try:
        # --- Load and Parse Log Data using the function ---
        logger.info(f"Loading and parsing log file: {args.file}")
        # Call the function directly instead of using a class
        log_df = load_log_into_dataframe(
            log_file=args.file,
            start_date_utc=start_date_utc,
            whitelist=analyzer.whitelist # Pass the loaded whitelist from analyzer
        )

        if log_df is None or log_df.empty:
             logger.error("Failed to load or parse log data, or DataFrame is empty. Exiting.")
             sys.exit(1) # Exit if log loading failed

        # Assign the loaded DataFrame to the analyzer instance
        analyzer.log_df = log_df
        logger.info(f"Successfully loaded {len(log_df)} log entries into DataFrame for analyzer.")

        total_overall_requests = len(log_df)
        logger.info(f"Total requests in analysis window: {total_overall_requests}")

    except Exception as e:
        logger.error(f"Error loading/parsing log file: {e}", exc_info=True)
        sys.exit(1)

    # --- Determine Effective Request Threshold ---
    effective_min_requests = 1 # Start with a minimum of 1
    if total_overall_requests > 0:
        # Calculate based on the relative threshold - This is now primarily for strategies OTHER than 'combined'
        effective_min_requests = max(1, int(total_overall_requests * (args.block_relative_threshold_percent / 100.0)))
        # UPDATED log message (removed note about combined ignoring it)
        logger.info(f"Calculated effective_min_requests = {effective_min_requests} (based on {args.block_relative_threshold_percent}% of {total_overall_requests}). Used by most strategies.")
    else:
        # If no requests, the threshold remains 1, but analysis likely stops anyway
        logger.warning(f"Total requests in analysis window is 0. Effective minimum request threshold set to {effective_min_requests}.")


    # --- Identify Threats ---
    # Pass the config object (args) to identify_threats
    threats = analyzer.identify_threats(
        strategy_name=args.block_strategy,
        effective_min_requests=effective_min_requests,
        analysis_duration_seconds=analysis_duration_seconds,
        total_overall_requests=total_overall_requests,
        config=args # Pass the config object here
    )

    # Check if threats list is valid
    if threats is None:
        logger.error("Threat identification failed.")
        sys.exit(1)
    if not threats:
        logger.info("No threats identified after analysis.")
        # threats is an empty list, proceed to reporting section which will handle it
    # else: # threats is a list of dictionaries

    # --- Get DataFrame for Reporting ---
    # Use the analyzer's method to get the DataFrame after threats are identified
    threats_df = analyzer.get_threats_df() # Returns DF indexed by string representation of subnet ID

    # --- Calculate Overall Maximums using DataFrame ---
    max_metrics_data = {}
    # Define metrics to track and their display names - REMOVED metrics
    metrics_to_track = [
        'total_requests', 'ip_count',
        # Removed IP RPMs
        # Removed Subnet Total RPMs
        'subnet_time_span',
        # Removed subnet_req_per_min
        'subnet_req_per_min_window'
    ]
    metric_names_map = {
        'total_requests': 'Total Requests',
        'ip_count': 'IP Count',
        # Removed IP RPMs
        # Removed Subnet Total RPMs
        'subnet_time_span': 'Subnet Activity Timespan (%)',
        # Removed subnet_req_per_min
        'subnet_req_per_min_window': 'Subnet Req/Min (Window Avg)'
    }

    if not threats_df.empty:
        for metric in metrics_to_track:
            if metric in threats_df.columns:
                try:
                    max_value = threats_df[metric].max()
                    # Find all subnets (index values) that achieved this max value
                    max_subnets = threats_df[threats_df[metric] == max_value].index.tolist()
                    max_metrics_data[metric] = {'value': max_value, 'subnets': max_subnets}
                except Exception as e:
                    logger.warning(f"Could not calculate max for metric '{metric}': {e}")
                    max_metrics_data[metric] = {'value': -1, 'subnets': []} # Indicate error or absence
            else:
                logger.warning(f"Metric '{metric}' not found in threats DataFrame for max calculation.")
                max_metrics_data[metric] = {'value': -1, 'subnets': []}
    else:
        logger.info("Threats DataFrame is empty. Cannot calculate overall maximums.")
        # Initialize max_metrics_data with defaults if needed elsewhere
        for metric in metrics_to_track:
             max_metrics_data[metric] = {'value': -1, 'subnets': []}

    # --- End Calculate Overall Maximums ---


    # --- Blocking Logic ---
    blocked_targets_count = 0
    blocked_subnets_via_supernet = set() # Keep track of /24s blocked via /16

    if args.block:
        if not args.silent:
            print("-" * 30)
        logger.info(f"Processing blocks (Dry Run: {args.dry_run})...")
        ufw_manager_instance = ufw_handler.UFWManager(args.dry_run)

        # 1. Identify and Block /16 Supernets (Simplified Logic)
        supernets_to_block = defaultdict(list)
        # Iterate through the original threats list (dictionaries) as it contains the ipaddress objects needed for supernetting
        for threat in threats: # Use the original list here
            if threat.get('should_block'):
                subnet = threat.get('id') # This is the ipaddress object
                if isinstance(subnet, ipaddress.IPv4Network) and subnet.prefixlen == 24:
                    try:
                        supernet = subnet.supernet(new_prefix=16)
                        supernets_to_block[supernet].append(threat) # Store the threat dict
                    except ValueError:
                        continue # Skip if supernet calculation fails

        # Process potential /16 blocks
        logger.info(f"Checking {len(supernets_to_block)} /16 supernets for potential blocking (>= 2 contained blockable /24s)...")
        for supernet, contained_blockable_threats in supernets_to_block.items():
            if len(contained_blockable_threats) >= 2:
                target_to_block_obj = supernet
                target_type = "Supernet /16"
                block_duration = args.block_duration
                contained_ids_str = ", ".join([str(t['id']) for t in contained_blockable_threats])
                reason = f"contains >= 2 blockable /24 subnets ({contained_ids_str})"

                logger.info(f"Processing block for {target_type}: {target_to_block_obj}. Reason: {reason}")
                success = ufw_manager_instance.block_target(
                    subnet_or_ip_obj=target_to_block_obj,
                    block_duration_minutes=block_duration
                )
                if success:
                    blocked_targets_count += 1
                    action = "Blocked" if not args.dry_run else "Dry Run - Blocked"
                    # ALWAYS PRINT block actions
                    print(f" -> {action} {target_type}: {target_to_block_obj} for {block_duration} minutes.")
                    for contained_threat in contained_blockable_threats:
                        # Store the ipaddress object in the set
                        blocked_subnets_via_supernet.add(contained_threat['id'])
                else:
                    action = "Failed to block" if not args.dry_run else "Dry Run - Failed"
                    # Print failures only if not silent
                    if not args.silent:
                        print(f" -> {action} {target_type}: {target_to_block_obj}.")


        # 2. Process individual /24 or /64 Blocks (Top N from the *original* sorted list)
        logger.info(f"Processing top {args.top} individual threat blocks (/24 or /64)...")
        top_threats_to_consider = threats[:args.top] # Use the original list for blocking logic
        for threat in top_threats_to_consider:
            target_id_obj = threat['id'] # ipaddress object

            # Skip if this subnet was already covered by a /16 block (compare ipaddress objects)
            if target_id_obj in blocked_subnets_via_supernet:
                # Attempt to find the blocking supernet for logging
                blocking_supernet_str = "Unknown"
                if isinstance(target_id_obj, ipaddress.IPv4Network) and target_id_obj.prefixlen == 24:
                    try:
                        blocking_supernet_str = str(target_id_obj.supernet(new_prefix=16))
                    except ValueError: pass
                logger.info(f"Skipping block for {target_id_obj}: Already covered by blocked supernet {blocking_supernet_str}.")
                continue

            if threat.get('should_block'):
                target_to_block_obj = target_id_obj
                target_type = "Subnet"
                block_duration = args.block_duration

                # Check for single IP subnet
                if threat.get('ip_count') == 1 and threat.get('details'):
                    try:
                        # Details IP should be string already
                        single_ip_str = threat['details'][0]['ip']
                        target_to_block_obj = ipaddress.ip_address(single_ip_str) # Convert back to object for UFW
                        target_type = "Single IP"
                        logger.info(f"Threat {threat['id']} has only 1 IP. Targeting IP {target_to_block_obj} instead of the whole subnet.")
                    except (IndexError, KeyError, ValueError, TypeError) as e:
                        logger.warning(f"Could not extract/convert single IP from details for subnet {threat['id']} despite ip_count=1: {e}. Blocking subnet instead.")
                        target_type = "Subnet"
                        target_to_block_obj = threat['id']

                logger.info(f"Processing block for {target_type}: {target_to_block_obj}. Reason: {threat.get('block_reason')}")
                success = ufw_manager_instance.block_target(
                    subnet_or_ip_obj=target_to_block_obj,
                    block_duration_minutes=block_duration
                )
                if success:
                    blocked_targets_count += 1
                    action = "Blocked" if not args.dry_run else "Dry Run - Blocked"

                    # --- Construct metrics summary string for block message ---
                    try:
                        metrics_summary = (
                            f"Metrics: "
                            f"{int(threat.get('total_requests', 0)):d} reqs, "
                            f"{threat.get('ip_count', 0):d} IPs, "
                            f"Score: {threat.get('strategy_score', 0):.1f}, "
                            f"Req/Min(Win): {threat.get('subnet_req_per_min_window', 0):.1f}, "
                            f"TimeSpan: {threat.get('subnet_time_span', 0):.0f}s"
                        )
                    except Exception as e:
                         logger.warning(f"Could not format metrics for block message of {target_to_block_obj}: {e}")
                         metrics_summary = "Metrics: N/A"
                    # --- End metrics summary string ---

                    # Append the metrics_summary to the print statement
                    print(f" -> {action} {target_type}: {target_to_block_obj} for {block_duration} minutes. Reason: {threat.get('block_reason')}. {metrics_summary}")
                else:
                    action = "Failed to block" if not args.dry_run else "Dry Run - Failed"
                    print(f" -> {action} {target_type}: {target_to_block_obj}.")
        if not args.silent:
            print(f"Block processing complete. {blocked_targets_count} targets {'would be' if args.dry_run else 'were'} processed for blocking.")
            print("-" * 30)
    else:
        logger.info("Blocking is disabled (--block not specified).")


    # --- Reporting Logic ---
    # Suppress reporting if silent mode is active
    if not args.silent:
        top_count = min(args.top, len(threats))
        print(f"\n=== TOP {top_count} INDIVIDUAL THREATS DETECTED (/24 or /64) (Sorted by Strategy Score: '{strategy_name}') ===")
        if args.block:
            action = "Blocked" if not args.dry_run else "[DRY RUN] Marked for blocking"
            print(f"--- {action} based on strategy '{strategy_name}' criteria applied to top {args.top} threats ---")
            print(f"--- NOTE: /16 supernets containing >= 2 blockable /24s may have been blocked instead ---")

        top_threats_report = threats[:top_count] # Use original list for reporting top N

        for i, threat in enumerate(top_threats_report, 1):
            target_id_obj = threat['id'] # ipaddress object
            target_id_str = str(target_id_obj)
            strat_score_str = f"Score: {threat.get('strategy_score', 0):.2f}"

            # Construct detailed metrics summary string (using .get() on the threat dict) - REMOVED metrics
            total_req_val = threat.get('total_requests', 0)
            if total_req_val is None or pd.isna(total_req_val): total_req_val = 0
            total_req_val = int(total_req_val)

            metrics_summary = (
                f"{total_req_val:d} reqs, "
                f"{threat.get('ip_count', 0):d} IPs, "
                # Removed IP RPMs
                # Removed Subnet Total RPMs
                f"Req/Min(Win): {threat.get('subnet_req_per_min_window', 0):.1f}, "
                f"TimeSpan: {threat.get('subnet_time_span', 0):.0f}s"
            )

            block_info = ""
            # Determine block status for reporting (using ipaddress object for check)
            is_blockable = threat.get('should_block', False)
            is_top_n = i <= args.top
            covered_by_supernet = target_id_obj in blocked_subnets_via_supernet # Check using object

            if args.block:
                if covered_by_supernet:
                    block_info = f" [COVERED BY /16 BLOCK]"
                elif is_blockable and is_top_n:
                    # Block status is already printed during the blocking phase, maybe add reason here?
                    block_reason_str = f" ({threat.get('block_reason', 'No reason')})" if threat.get('block_reason') else ""
                    # Indicate it was processed for blocking
                    block_info = f" [PROCESSED FOR BLOCKING]{block_reason_str}"


            print(f"\n#{i} Subnet: {target_id_str} - {strat_score_str}{block_info}")
            print(f"  Metrics: {metrics_summary}")

            # Use details from the threat dictionary
            if threat.get('details'):
                print("  -> Top IPs (by Max RPM):")
                # Limit details shown in console report if desired
                max_details_to_show = 5
                for ip_detail in threat['details'][:max_details_to_show]:
                     print(f"     - IP: {ip_detail['ip']} ({ip_detail['total_requests']} reqs, AvgRPM: {ip_detail['avg_rpm']:.2f}, MaxRPM: {ip_detail['max_rpm']:.0f})")
                if len(threat['details']) > max_details_to_show:
                     print(f"     ... and {len(threat['details']) - max_details_to_show} more.")
            else:
                 print("  -> No IP details available.")

    # --- Export Results ---
    if args.output:
        # Pass the main threats list (list of dicts) to export
        if analyzer.export_results(args.format, args.output, config=args, threats=threats):
            logger.info(f"Results exported to {args.output} in {args.format} format")
        else:
            logger.error(f"Error exporting results to {args.output}")

    # --- Final Summary ---
    # Print simplified summary in silent mode
    if not args.silent:
        print(f"\nAnalysis completed using strategy '{strategy_name}'.")
    # Always print the blocked count summary
    print(f"{blocked_targets_count} unique targets (subnets/IPs or /16 supernets) {'blocked' if not args.dry_run else 'marked for blocking'} in this execution.")
    if not args.silent:
        # Use len(threats) which is the original list count
        print(f"From a total of {len(threats)} detected individual threats.")
        if args.block:
            print(f"Use '--clean-rules' periodically to remove expired rules.")

    # --- Report Overall Maximums ---
    # Suppress if silent
    if not args.silent:
        print(f"\n=== OVERALL MAXIMUMS OBSERVED ===")
        if not max_metrics_data or all(data['value'] == -1 for data in max_metrics_data.values()):
            print("  No threat data available or maximums could not be determined.")
        else:
            for metric_key, data in max_metrics_data.items():
                metric_name = metric_names_map.get(metric_key, metric_key) # Uses updated map
                value = data['value']
                subnets = data['subnets'] # List of subnet ID strings
                value_str = "N/A"

                if value != -1 and pd.notna(value): # Check if metric was found and is valid
                    if metric_key == 'subnet_time_span':
                        if analysis_duration_seconds > 0:
                            percentage = (value / analysis_duration_seconds) * 100
                            value_str = f"{percentage:.1f}% ({value:.0f}s raw)"
                        else:
                            value_str = f"N/A ({value:.0f}s raw)"
                    elif isinstance(value, float):
                        value_str = f"{value:.2f}"
                    else: # Should be int or similar
                        value_str = str(int(value)) # Ensure integer representation if applicable

                print(f"  {metric_name}: {value_str} (Achieved by: {', '.join(subnets)})")

    # --- Report Details for Subnets Achieving Maximums ---
    # Suppress if silent
    if not args.silent:
        print(f"\n=== DETAILS FOR SUBNETS ACHIEVING MAXIMUMS ===")
        if threats_df.empty:
            print("  No data available to report maximum-achieving subnets.")
        else:
            # Collect unique subnet IDs (strings) that achieved any maximum
            max_achieving_subnet_ids = set()
            for metric_key, data in max_metrics_data.items():
                if data['value'] != -1 and pd.notna(data['value']):
                    max_achieving_subnet_ids.update(data['subnets'])

            if not max_achieving_subnet_ids:
                print("  No subnets achieved any maximum values.")
            else:
                logger.info(f"Reporting details for {len(max_achieving_subnet_ids)} subnets that achieved at least one maximum.")
                # Filter the DataFrame to get only the rows for these subnets
                max_subnets_df = threats_df[threats_df.index.isin(max_achieving_subnet_ids)]

                # Sort by index (subnet string) for consistent reporting order
                max_subnets_df = max_subnets_df.sort_index()

                for subnet_id_str, threat_row in max_subnets_df.iterrows():
                    # Find which maximums this subnet achieved
                    achieved_max_metrics = []
                    for metric_key, data in max_metrics_data.items():
                        if subnet_id_str in data['subnets']:
                            achieved_max_metrics.append(metric_names_map.get(metric_key, metric_key))
                    achieved_max_str = f" [Achieved Max: {', '.join(achieved_max_metrics)}]" if achieved_max_metrics else ""

                    # Reuse the metrics summary string generation from the DataFrame row - REMOVED metrics
                    total_req_val = threat_row.get('total_requests', 0)
                    if total_req_val is None or pd.isna(total_req_val): total_req_val = 0
                    total_req_val = int(total_req_val)

                    metrics_summary = (
                        f"{total_req_val:d} reqs, "
                        f"{threat_row.get('ip_count', 0):d} IPs, "
                        # Removed IP RPMs
                        # Removed Subnet Total RPMs
                        # Removed subnet_req_per_min
                        f"Req/Min(Win): {threat_row.get('subnet_req_per_min_window', 0):.1f}, "
                        f"TimeSpan: {threat_row.get('subnet_time_span', 0):.0f}s"
                    )

                    print(f"\nSubnet: {subnet_id_str}{achieved_max_str}")
                    print(f"  Metrics: {metrics_summary}")
                    # Optionally print top IPs again if desired, accessing 'details' from the row
                    details = threat_row.get('details', [])
                    if details and isinstance(details, list):
                        print("  -> Top IPs (by Max RPM):")
                        max_details_to_show = 3 # Show fewer details here?
                        for ip_detail in details[:max_details_to_show]:
                             # Ensure ip_detail is a dict before accessing keys
                             if isinstance(ip_detail, dict):
                                 print(f"     - IP: {ip_detail.get('ip','N/A')} ({ip_detail.get('total_requests',0)} reqs, AvgRPM: {ip_detail.get('avg_rpm',0):.2f}, MaxRPM: {ip_detail.get('max_rpm',0):.0f})")
                             else:
                                 print(f"     - Invalid detail format: {ip_detail}")
                        if len(details) > max_details_to_show:
                             # Corrected f-string: removed extra '}' inside len()
                             print(f"     ... and {len(details) - max_details_to_show} more.")
                    # else:
                    #      print("  -> No IP details available.") # Redundant if details is empty list

    # --- End Report Details for Subnets Achieving Maximums ---


if __name__ == '__main__':
    main()

