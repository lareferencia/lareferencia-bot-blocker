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
from log_parser import get_subnet, is_ip_in_whitelist # Keep imports minimal
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
    parser.add_argument(
        '--block-strategy', default='combined', # UPDATED default
        choices=['volume_coordination', 'volume_peak_rpm', 'peak_total_rpm', 'coordinated_sustained', 'combined'], # ADDED combined
        help='Strategy used to score threats and decide on blocking.'
    )
    parser.add_argument(
        '--block-relative-threshold-percent', type=float, default=1, # ADDED default
        help='Base threshold: Minimum percentage of total requests in the analysis window for a subnet to be considered a potential threat (e.g., 0.1 for 0.1%%). Acts as an initial filter before strategy-specific thresholds are applied.' # UPDATED help
    )
    parser.add_argument(
        '--block-ip-count-threshold', type=int, default=10,
        help='Strategy threshold: Minimum number of unique IPs (used by volume_coordination, combined).'
    )
    parser.add_argument(
        '--block-max-rpm-threshold', type=float, default=10,
        help='Strategy threshold: Minimum peak RPM from any IP (used by volume_peak_rpm, combined).'
    )
    parser.add_argument(
        '--block-total-max-rpm-threshold', type=float, default=20,
        help='Strategy threshold: Minimum peak TOTAL SUBNET RPM (max requests per minute for the entire subnet) (used by peak_total_rpm, combined).'
    )
    # --- Add argument for combined strategy ---
    parser.add_argument(
        '--block-trigger-count', type=int, default=2,
        help='Strategy threshold: Minimum number of triggers (IP count, Max IP RPM, Peak Subnet RPM, Timespan) that must be met for the combined strategy to block.'
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
    args = parser.parse_args()

    # --- Logging Setup ---
    log_level = getattr(logging, args.log_level)
    setup_logging(args.log_file, log_level)
    logger = logging.getLogger('botstats.main')

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
    try:
        processed_count = analyzer.analyze_log_file(args.file, start_date_utc)
        if processed_count <= 0: # Check for < 0 (error) or == 0 (no data)
             logger.warning("No log entries processed or error during loading. Exiting.")
             sys.exit(0 if processed_count == 0 else 1)
        # Get total requests for relative threshold calculation
        if analyzer.log_df is not None and not analyzer.log_df.empty:
             total_overall_requests = len(analyzer.log_df)
             logger.info(f"Total requests in analysis window: {total_overall_requests}")
        else:
             logger.warning("Log DataFrame is empty or None after analysis, cannot calculate relative threshold.")

    except Exception as e:
        logger.error(f"Error analyzing log file: {e}", exc_info=True)
        sys.exit(1)

    # --- Determine Effective Request Threshold ---
    effective_min_requests = 1 # Start with a minimum of 1
    if total_overall_requests > 0:
        # Always calculate based on the relative threshold
        effective_min_requests = max(1, int(total_overall_requests * (args.block_relative_threshold_percent / 100.0)))
        logger.info(f"Using relative request threshold: {args.block_relative_threshold_percent}% of {total_overall_requests} = {effective_min_requests} requests")
    else:
        # If no requests, the threshold remains 1, but analysis likely stops anyway
        logger.warning(f"Total requests in analysis window is 0. Effective minimum request threshold set to {effective_min_requests}.")


    # Identify threats (/24 or /64)
    threats = analyzer.identify_threats()
    if not threats:
         logger.info("No threats identified based on initial aggregation.")
         sys.exit(0)

    # --- Calculate Maximums for Normalization ---
    max_total_requests = 0
    max_subnet_time_span = 0
    if threats:
        # Use max() with a generator expression for efficiency
        max_total_requests = max(threat.get('total_requests', 0) for threat in threats)
        max_subnet_time_span = max(threat.get('subnet_time_span', 0) for threat in threats)
        logger.debug(f"Calculated maximums for normalization: max_total_requests={max_total_requests}, max_subnet_time_span={max_subnet_time_span}")
    # --- End Calculate Maximums ---


    # --- Apply Strategy, Score, and Sort (/24 or /64) ---
    logger.info(f"Applying '{strategy_name}' strategy to {len(threats)} potential threats...")
    # Keep track of threats marked for blocking
    blockable_threats = []
    for threat in threats:
        # Pass analysis_duration_seconds and effective_min_requests to the strategy
        # Pass the calculated maximums for normalization
        score, should_block, reason = strategy_instance.calculate_threat_score_and_block(
            threat,
            config=args,
            effective_min_requests=effective_min_requests, # Pass the calculated threshold
            analysis_duration_seconds=analysis_duration_seconds,
            max_total_requests=max_total_requests, # Pass max requests
            max_subnet_time_span=max_subnet_time_span # Pass max timespan
        )
        threat['strategy_score'] = score
        threat['should_block'] = should_block
        threat['block_reason'] = reason
        if should_block:
            blockable_threats.append(threat) # Add to list if marked for blocking

    # Sort all threats by the calculated strategy score (descending) for reporting
    threats.sort(key=lambda x: x.get('strategy_score', 0), reverse=True)
    logger.info("Threats scored and sorted.")

    # --- Calculate Overall Maximums ---
    max_metrics = defaultdict(lambda: {'value': -1, 'subnets': []})
    metrics_to_track = [
        'total_requests', 'ip_count', 
        'subnet_avg_ip_rpm', 'subnet_max_ip_rpm',
        'subnet_total_avg_rpm', 'subnet_total_max_rpm',
        'subnet_time_span', 'subnet_req_per_min'
    ]
    metric_names_map = { # For clearer reporting
        'total_requests': 'Total Requests',
        'ip_count': 'IP Count',
        'subnet_avg_ip_rpm': 'Average IP RPM (Subnet Avg)',
        'subnet_max_ip_rpm': 'Maximum IP RPM (Subnet Max)',
        'subnet_total_avg_rpm': 'Average Total Subnet RPM',
        'subnet_total_max_rpm': 'Maximum Total Subnet RPM',
        'subnet_time_span': 'Subnet Activity Timespan (%)',
        'subnet_req_per_min': 'Subnet Requests/Min (Overall)' # ADDED new metric name
    }

    if threats: # Only calculate if there are threats
        for threat in threats:
            subnet_id_str = str(threat['id'])
            for metric in metrics_to_track:
                current_value = threat.get(metric, 0)
                # Handle potential None values just in case
                if current_value is None:
                    current_value = 0

                # Use a tolerance for float comparisons if needed, but direct comparison is often fine here
                if current_value > max_metrics[metric]['value']:
                    max_metrics[metric]['value'] = current_value
                    max_metrics[metric]['subnets'] = [subnet_id_str]
                elif current_value == max_metrics[metric]['value']:
                    # Avoid adding duplicates if a subnet appears multiple times (shouldn't happen with current logic)
                    if subnet_id_str not in max_metrics[metric]['subnets']:
                        max_metrics[metric]['subnets'].append(subnet_id_str)
    # --- End Calculate Overall Maximums ---


    # --- Blocking Logic ---
    blocked_targets_count = 0
    blocked_subnets_via_supernet = set() # Keep track of /24s blocked via /16

    if args.block:
        print("-" * 30)
        logger.info(f"Processing blocks (Dry Run: {args.dry_run})...")
        ufw_manager_instance = ufw_handler.UFWManager(args.dry_run)

        # 1. Identify and Block /16 Supernets (Simplified Logic)
        supernets_to_block = defaultdict(list)
        # Group blockable IPv4 /24 threats by their /16 supernet
        for threat in blockable_threats: # Iterate only through threats marked for blocking
            subnet = threat.get('id')
            if isinstance(subnet, ipaddress.IPv4Network) and subnet.prefixlen == 24:
                try:
                    supernet = subnet.supernet(new_prefix=16)
                    supernets_to_block[supernet].append(threat) # Store the actual threat dict
                except ValueError:
                    continue # Skip if supernet calculation fails

        # Process potential /16 blocks
        logger.info(f"Checking {len(supernets_to_block)} /16 supernets for potential blocking (>= 2 contained blockable /24s)...")
        for supernet, contained_blockable_threats in supernets_to_block.items():
            # Block /16 if it contains >= 2 blockable /24 subnets
            if len(contained_blockable_threats) >= 2:
                target_to_block_obj = supernet
                target_type = "Supernet /16"
                block_duration = args.block_duration # Use standard duration
                # Create a reason based on contained threats
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
                    print(f" -> {action} {target_type}: {target_to_block_obj} for {block_duration} minutes.")
                    # Add contained /24 subnets to the set to prevent double blocking
                    for contained_threat in contained_blockable_threats:
                        blocked_subnets_via_supernet.add(contained_threat['id'])
                else:
                    action = "Failed to block" if not args.dry_run else "Dry Run - Failed"
                    print(f" -> {action} {target_type}: {target_to_block_obj}.")
            # else: # No need for debug log if only 1 threat, it will be handled individually if in top N
            #      logger.debug(f"Supernet {supernet} only contained 1 blockable /24 subnet. Not blocking /16.")


        # 2. Process individual /24 or /64 Blocks (Top N from the *original* sorted list)
        logger.info(f"Processing top {args.top} individual threat blocks (/24 or /64)...")
        top_threats_to_consider = threats[:args.top] # Use the overall top N threats
        for threat in top_threats_to_consider:
            target_id_obj = threat['id'] # ipaddress.ip_network object

            # Skip if this subnet was already covered by a /16 block
            if target_id_obj in blocked_subnets_via_supernet:
                logger.info(f"Skipping block for {target_id_obj}: Already covered by blocked supernet {target_id_obj.supernet(new_prefix=16)}.")
                continue

            # Check if this specific threat (within the top N) was marked for blocking
            if threat.get('should_block'):
                target_to_block_obj = target_id_obj # Default to the subnet object
                target_type = "Subnet"
                block_duration = args.block_duration # Use standard duration

                # Check if it's a single IP subnet (existing logic)
                if threat.get('ip_count') == 1 and threat.get('details'):
                    try:
                        single_ip_str = threat['details'][0]['ip']
                        target_to_block_obj = ipaddress.ip_address(single_ip_str)
                        target_type = "Single IP"
                        logger.info(f"Threat {threat['id']} has only 1 IP. Targeting IP {target_to_block_obj} instead of the whole subnet.")
                    except (IndexError, KeyError, ValueError) as e:
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
                    print(f" -> {action} {target_type}: {target_to_block_obj} for {block_duration} minutes.")
                else:
                    action = "Failed to block" if not args.dry_run else "Dry Run - Failed"
                    print(f" -> {action} {target_type}: {target_to_block_obj}.")
            # else: # No need to log if a top N threat wasn't blockable, it just wasn't
            #    logger.debug(f"Threat {threat['id']} in top {args.top} did not meet blocking criteria for strategy '{strategy_name}'.")

        print(f"Block processing complete. {blocked_targets_count} targets {'would be' if args.dry_run else 'were'} processed for blocking.")
        print("-" * 30)
    else:
        logger.info("Blocking is disabled (--block not specified).")


    # --- Reporting Logic ---
    # Report Top /24 or /64 Threats
    top_count = min(args.top, len(threats))
    print(f"\n=== TOP {top_count} INDIVIDUAL THREATS DETECTED (/24 or /64) (Sorted by Strategy Score: '{strategy_name}') ===")
    if args.block:
        action = "Blocked" if not args.dry_run else "[DRY RUN] Marked for blocking"
        print(f"--- {action} based on strategy '{strategy_name}' criteria applied to top {args.top} threats ---")
        print(f"--- NOTE: /16 supernets containing >= 2 blockable /24s may have been blocked instead ---")


    top_threats_report = threats[:top_count]

    for i, threat in enumerate(top_threats_report, 1):
        target_id_obj = threat['id']
        target_id_str = str(target_id_obj)
        strat_score_str = f"Score: {threat.get('strategy_score', 0):.2f}"
        
        # --- Construct detailed metrics summary string ---
        # Use .get() and explicit format specifiers for robustness
        metrics_summary = (
            f"{threat.get('total_requests', 0):d} reqs, "
            f"{threat.get('ip_count', 0):d} IPs, " # REMOVED bot name
            f"AvgIPRPM: {threat.get('subnet_avg_ip_rpm', 0):.1f}, "
            f"MaxIPRPM: {threat.get('subnet_max_ip_rpm', 0):.0f}, "
            f"AvgTotalRPM: {threat.get('subnet_total_avg_rpm', 0):.1f}, "
            f"MaxTotalRPM: {threat.get('subnet_total_max_rpm', 0):.0f}, "
            f"Req/Min: {threat.get('subnet_req_per_min', 0):.1f}, "
            f"TimeSpan: {threat.get('subnet_time_span', 0):.0f}s"
        )
        # --- End of detailed metrics summary string ---

        block_info = ""
        # Determine block status for reporting
        is_blockable = threat.get('should_block', False)
        is_top_n = i <= args.top
        covered_by_supernet = target_id_obj in blocked_subnets_via_supernet

        if args.block:
            if covered_by_supernet:
                # Indicate it was blocked via its /16 parent, regardless of top N or its own block status
                block_info = f" [COVERED BY /16 BLOCK]"
            elif is_blockable and is_top_n:
                # Show BLOCKED status only if it was blockable, in top N, and NOT covered by /16
                block_status = "[BLOCKED]" if not args.dry_run else "[DRY RUN - BLOCKED]"
                block_reason_str = f" ({threat.get('block_reason', 'No reason')})" if threat.get('block_reason') else ""
                block_info = f" {block_status}{block_reason_str}"
            # No special indicator if it wasn't blockable or wasn't in top N (and not covered by /16)

        # --- Updated print statement with all metrics ---
        print(f"\n#{i} Subnet: {target_id_str} - {strat_score_str}{block_info}")
        print(f"  Metrics: {metrics_summary}")
        # --- End of updated print statement ---

        if threat['details']:
            print("  -> Top IPs (by Max RPM):")
            for ip_detail in threat['details']:
                 print(f"     - IP: {ip_detail['ip']} ({ip_detail['total_requests']} reqs, AvgRPM: {ip_detail['avg_rpm']:.2f}, MaxRPM: {ip_detail['max_rpm']:.0f})")
        else:
             print("  -> No IP details available.")

    # --- Export Results ---
    if args.output:
        # Pass the main threats list to export
        if analyzer.export_results(args.format, args.output, config=args, threats=threats):
            logger.info(f"Results exported to {args.output} in {args.format} format")
        else:
            logger.error(f"Error exporting results to {args.output}")

    # --- Final Summary ---
    print(f"\nAnalysis completed using strategy '{strategy_name}'.")
    print(f"{blocked_targets_count} unique targets (subnets/IPs or /16 supernets) {'blocked' if not args.dry_run else 'marked for blocking'} in this execution.")
    print(f"From a total of {len(threats)} detected individual threats.")
    if args.block:
        print(f"Use '--clean-rules' periodically to remove expired rules.")

    # --- Report Overall Maximums ---
    print(f"\n=== OVERALL MAXIMUMS OBSERVED ===")
    if not max_metrics:
        print("  No threat data available to determine maximums.")
    else:
        for metric_key, data in max_metrics.items():
            metric_name = metric_names_map.get(metric_key, metric_key)
            value = data['value']
            subnets = data['subnets']
            value_str = "N/A" # Default value string

            if value != -1: # Check if metric was found
                # Special handling for timespan percentage
                if metric_key == 'subnet_time_span':
                    if analysis_duration_seconds > 0:
                        percentage = (value / analysis_duration_seconds) * 100
                        # Show percentage with one decimal place
                        value_str = f"{percentage:.1f}% ({value:.0f}s raw)"
                    else:
                        # Show raw seconds if no analysis duration is available
                        value_str = f"N/A ({value:.0f}s raw)"
                # Format other float values (including the new req/min)
                elif isinstance(value, float):
                    value_str = f"{value:.2f}"
                # Format integer values
                else:
                    value_str = str(value)

            print(f"  {metric_name}: {value_str} (Achieved by: {', '.join(subnets)})")

    # --- End Report Overall Maximums ---

    # --- Report Details for Subnets Achieving Maximums ---
    print(f"\n=== DETAILS FOR SUBNETS ACHIEVING MAXIMUMS ===")
    if not max_metrics or not threats:
        print("  No data available to report maximum-achieving subnets.")
    else:
        # Create a lookup dictionary for faster access to threat data
        threat_lookup = {str(threat['id']): threat for threat in threats}
        
        # Collect unique subnet IDs that achieved any maximum
        max_achieving_subnet_ids = set()
        for metric_key, data in max_metrics.items():
            if data['value'] != -1: # Only consider metrics where a max was found
                max_achieving_subnet_ids.update(data['subnets'])

        if not max_achieving_subnet_ids:
            print("  No subnets achieved any maximum values.")
        else:
            logger.info(f"Reporting details for {len(max_achieving_subnet_ids)} subnets that achieved at least one maximum.")
            # Sort the IDs for consistent reporting order
            sorted_max_subnet_ids = sorted(list(max_achieving_subnet_ids))

            for subnet_id_str in sorted_max_subnet_ids:
                threat = threat_lookup.get(subnet_id_str)
                if not threat:
                    logger.warning(f"Could not find threat data for max-achieving subnet ID: {subnet_id_str}")
                    continue

                # Find which maximums this subnet achieved
                achieved_max_metrics = []
                for metric_key, data in max_metrics.items():
                    if subnet_id_str in data['subnets']:
                        achieved_max_metrics.append(metric_names_map.get(metric_key, metric_key))
                
                achieved_max_str = f" [Achieved Max: {', '.join(achieved_max_metrics)}]"

                # Reuse the metrics summary string generation
                metrics_summary = (
                    f"{threat.get('total_requests', 0):d} reqs, "
                    f"{threat.get('ip_count', 0):d} IPs, " # REMOVED bot name
                    f"AvgIPRPM: {threat.get('subnet_avg_ip_rpm', 0):.1f}, "
                    f"MaxIPRPM: {threat.get('subnet_max_ip_rpm', 0):.0f}, "
                    f"AvgTotalRPM: {threat.get('subnet_total_avg_rpm', 0):.1f}, "
                    f"MaxTotalRPM: {threat.get('subnet_total_max_rpm', 0):.0f}, "
                    f"Req/Min: {threat.get('subnet_req_per_min', 0)::.1f}, "
                    f"TimeSpan: {threat.get('subnet_time_span', 0):.0f}s"
                )

                print(f"\nSubnet: {subnet_id_str}{achieved_max_str}")
                print(f"  Metrics: {metrics_summary}")
                # Optionally print top IPs again if desired
                # if threat['details']:
                #     print("  -> Top IPs (by Max RPM):")
                #     for ip_detail in threat['details']:
                #          print(f"     - IP: {ip_detail['ip']} ({ip_detail['total_requests']} reqs, AvgRPM: {ip_detail['avg_rpm']:.2f}, MaxRPM: {ip_detail['max_rpm']:.0f})")
                # else:
                #      print("  -> No IP details available.")

    # --- End Report Details for Subnets Achieving Maximums ---


if __name__ == '__main__':
    main()

