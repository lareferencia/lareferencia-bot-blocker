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
        time_window (str): 'hour', 'day', or 'week'
    
    Returns:
        datetime: Datetime object corresponding to the start date
    """
    now = datetime.now()
    if time_window == 'hour':
        return now - timedelta(hours=1)
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
        choices=['hour', 'day', 'week'],
        help='Analyze logs from the last hour, day, or week (overrides --start-date).'
    )
    # --- Analysis Args ---
    parser.add_argument(
        '--top', '-n', type=int, default=10,
        help='Number of top threats to display/consider for blocking.'
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
        '--block-strategy', default='volume_danger',
        choices=['volume_danger', 'volume_coordination', 'volume_peak_rpm', 'combined', 'sustained_avg_rpm'],
        help='Strategy used to score threats and decide on blocking.'
    )
    parser.add_argument(
        '--block-threshold', type=int, default=50, # Increased default
        help='Base threshold: Minimum total requests for a subnet to be considered for blocking.'
    )
    parser.add_argument(
        '--block-danger-threshold', type=float, default=20.0, # Default for volume_danger, combined
        help='Strategy threshold: Minimum aggregated IP danger score (used by volume_danger, combined).'
    )
    parser.add_argument(
        '--block-ip-count-threshold', type=int, default=5, # Default for volume_coordination, combined
        help='Strategy threshold: Minimum number of unique IPs (used by volume_coordination, combined).'
    )
    parser.add_argument(
        '--block-max-rpm-threshold', type=float, default=300.0, # Default for volume_peak_rpm
        help='Strategy threshold: Minimum peak RPM from any IP (used by volume_peak_rpm).'
    )
    parser.add_argument(
        '--block-avg-rpm-threshold', type=float, default=60.0,
        help='Strategy threshold: Minimum average TOTAL SUBNET RPM (requests per minute for the entire subnet) (used by sustained_avg_rpm).'
    )
    parser.add_argument(
        '--block-duration', type=int, default=60,
        help='Duration of the UFW block in minutes.'
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
        ufw = ufw_handler.UFWManager(args.dry_run)
        count = ufw.clean_expired_rules()
        # Use original f-string if Python version >= 3.6
        # logger.info(f"Cleanup completed. {count} rules deleted.")
        logger.info("Cleanup completed. Rules deleted: %d", count) # Safer for compatibility
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
    # ... (logic to calculate start_date_utc from args.time_window or args.start_date - unchanged) ...
    now_local = datetime.now()
    if args.time_window:
        start_date_naive_local = calculate_start_date(args.time_window)
        if start_date_naive_local:
             start_date_aware_local = start_date_naive_local.astimezone()
             start_date_utc = start_date_aware_local.astimezone(timezone.utc)
             logger.info(f"Using time window: {args.time_window} (from {start_date_utc})")
    elif args.start_date:
        try:
            start_date_naive_local = datetime.strptime(args.start_date, '%d/%b/%Y:%H:%M:%S')
            start_date_aware_local = start_date_naive_local.astimezone()
            start_date_utc = start_date_aware_local.astimezone(timezone.utc)
            logger.info(f"Using start date: {start_date_utc}")
        except ValueError:
            logger.error("Error: Invalid date format. Use dd/mmm/yyyy:HH:MM:SS")
            sys.exit(1)


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
    try:
        processed_count = analyzer.analyze_log_file(args.file, start_date_utc)
        if processed_count <= 0: # Check for < 0 (error) or == 0 (no data)
             logger.warning("No log entries processed or error during loading. Exiting.")
             sys.exit(0 if processed_count == 0 else 1)
    except Exception as e:
        logger.error(f"Error analyzing log file: {e}", exc_info=True)
        sys.exit(1)

    # Identify threats (gets base metrics, pre-strategy)
    threats = analyzer.identify_threats()
    if not threats:
         logger.info("No threats identified based on initial aggregation.")
         sys.exit(0)

    # --- Apply Strategy, Score, and Sort ---
    logger.info(f"Applying '{strategy_name}' strategy to {len(threats)} potential threats...")
    for threat in threats:
        score, should_block, reason = strategy_instance.calculate_threat_score_and_block(threat, args)
        threat['strategy_score'] = score
        threat['should_block'] = should_block
        threat['block_reason'] = reason

    # Sort threats by the calculated strategy score (descending)
    threats.sort(key=lambda x: x.get('strategy_score', 0), reverse=True)
    logger.info("Threats scored and sorted.")

    # --- Blocking Logic ---
    blocked_targets_info = {}
    if args.block:
        ufw = ufw_handler.UFWManager(dry_run=args.dry_run)
        block_duration_minutes = args.block_duration

        # Consider only top N threats AFTER sorting by strategy score
        threats_to_consider_for_blocking = threats[:args.top]
        logger.info(f"Checking top {args.top} threats (by strategy score) for blocking...")

        for threat in threats_to_consider_for_blocking:
            target_id = threat['id'] # ipaddress object

            # Use the decision made by the strategy
            if threat.get('should_block'):
                block_reason = threat.get('block_reason', 'Unknown reason')
                logger.info(f"Threat {str(target_id)} qualifies for blocking: {block_reason}. Attempting block...")
                if ufw.block_target(target_id, block_duration_minutes):
                    # Store info about the block action
                    # Comment is generated inside block_target now
                    blocked_targets_info[str(target_id)] = block_reason # Store reason for summary
            # else: # Optional: Log why top threats were not blocked by strategy
                 # logger.debug(f"Top threat {str(target_id)} did not meet blocking criteria for strategy '{strategy_name}'.")


    # --- Reporting Logic ---
    top_count = min(args.top, len(threats))
    print(f"\n=== TOP {top_count} THREATS DETECTED (Sorted by Strategy Score: '{strategy_name}') ===")
    if args.block:
        action = "Blocked" if not args.dry_run else "[DRY RUN] Marked for blocking"
        # Clarify that blocking applies to top N threats that meet strategy criteria
        print(f"--- {action} based on strategy '{strategy_name}' criteria applied to top {args.top} threats ---")

    top_threats_report = threats[:top_count]

    for i, threat in enumerate(top_threats_report, 1):
        target_id_str = str(threat['id'])
        strat_score_str = f"Score: {threat.get('strategy_score', 0):.2f}"
        req_str = f"{threat['total_requests']} reqs"
        ip_count_str = f"{threat['ip_count']} IPs"
        agg_danger_str = f"AggDanger: {threat.get('aggregated_ip_danger_score', 0):.2f}"
        subnet_total_avg_rpm_str = f"~{threat.get('subnet_total_avg_rpm', 0):.1f} avg_total_rpm"
        subnet_total_max_rpm_str = f"{threat.get('subnet_total_max_rpm', 0):.0f} max_total_rpm"

        metrics_summary = f"{req_str}, {ip_count_str}, {agg_danger_str}, {subnet_total_avg_rpm_str}, {subnet_total_max_rpm_str}"

        block_info = ""
        if args.block and threat.get('should_block') and i <= args.top: # Check if it was among the top N considered
             block_status = "[BLOCKED]" if not args.dry_run else "[DRY RUN - BLOCKED]"
             block_info = f" {block_status}" # Reason is logged during blocking attempt

        print(f"\n#{i} Subnet: {target_id_str} - {strat_score_str} ({metrics_summary}){block_info}")

        if threat['details']:
            print("  -> Top IPs (by Max RPM):") # Changed header
            for ip_detail in threat['details']:
                 print(f"     - IP: {ip_detail['ip']} ({ip_detail['total_requests']} reqs, Score: {ip_detail['danger_score']:.2f}, AvgRPM: {ip_detail['avg_rpm']:.2f}, MaxRPM: {ip_detail['max_rpm']:.0f})")
        else:
             print("  -> No IP details available.")

    # --- Export Results ---
    if args.output:
        if analyzer.export_results(args.format, args.output, config=args):
            logger.info(f"Results exported to {args.output} in {args.format} format")
        else:
            logger.error(f"Error exporting results to {args.output}")

    # --- Final Summary ---
    print(f"\nAnalysis completed using strategy '{strategy_name}'. {len(blocked_targets_info)} unique targets {'blocked' if not args.dry_run else 'marked for blocking'} in this execution.")
    print(f"From a total of {len(threats)} detected threats.")
    if args.block:
        print(f"Use '--clean-rules' periodically to remove expired rules.")

if __name__ == '__main__':
    main()

