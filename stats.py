#!/usr/bin/env python3
"""
Main script for log analysis and bot threat detection using Pandas.
"""
import argparse
import re
from datetime import datetime, timedelta, timezone
import sys
import os
import logging
import ipaddress
import pandas as pd

# Import own modules
from log_parser import get_subnet, is_ip_in_whitelist
from ufw_handler import UFWManager
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
    if log_file:
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
        description='Analyzes a log file using Pandas, generates statistics and optionally blocks threats with UFW.'
    )
    # Make --file not required initially
    parser.add_argument(
        '--file', '-f', required=False,
        help='Path of the log file to analyze (required unless --clean-rules is used).'
    )
    parser.add_argument(
        '--start-date', '-s', required=False, default=None,
        help='Date from which to analyze the log. Format: dd/mmm/yyyy:HH:MM:SS (e.g. 16/Apr/2025:13:16:50). If not provided, analyzes all records.'
    )
    parser.add_argument(
        '--time-window', '-tw', required=False,
        choices=['hour', 'day', 'week'],
        help='Analyze only entries from the last hour, day or week.'
    )
    parser.add_argument(
        '--threshold', '-t', type=float, default=100,
        help='Requests per minute (RPM) threshold to consider an IP suspicious (default: 100).'
    )
    parser.add_argument(
        '--top', '-n', type=int, default=10,
        help='Number of most dangerous threats to display (default: 10).'
    )
    parser.add_argument(
        '--block', action='store_true',
        help='Enable blocking of detected threats using UFW.'
    )
    parser.add_argument(
        '--block-threshold', type=int, default=10,
        help='Threshold of *total requests* in the analyzed period to activate UFW blocking (default: 10).'
    )
    parser.add_argument(
        '--block-duration', type=int, default=60,
        help='Duration of the UFW block in minutes (default: 60).'
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Show the UFW commands that would be executed, but don\'t execute them.'
    )
    parser.add_argument(
        '--whitelist', '-w',
        help='File with list of IPs or subnets that should never be blocked (one per line).'
    )
    parser.add_argument(
        '--output', '-o',
        help='File to save the analysis results.'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'csv', 'text'],
        default='text',
        help='Output format when using --output (default: text).'
    )
    parser.add_argument(
        '--log-file',
        help='File to save execution logs.'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Log detail level (default: INFO).'
    )
    parser.add_argument(
        '--clean-rules', action='store_true',
        help='Run cleanup of expired UFW rules and exit.'
    )
    args = parser.parse_args()

    # Configure logging early
    log_level = getattr(logging, args.log_level)
    setup_logging(args.log_file, log_level)
    logger = logging.getLogger('botstats.main')

    # If we only want to clean rules, do it and exit (check this BEFORE checking --file)
    if args.clean_rules:
        logger.info("Starting cleanup of expired UFW rules...")
        ufw = UFWManager(args.dry_run) # Dry run still applies if specified
        count = ufw.clean_expired_rules()
        # --- TEMPORARY CHANGE FOR DEBUGGING ---
        # Replace the f-string with a simpler format call:
        logger.info("Cleanup completed. Rules deleted: %d", count)
        # --- END TEMPORARY CHANGE ---
        # Ensure this return is correctly indented (same level as logger.info above)
        return

    # Now, if not cleaning rules, --file becomes mandatory
    # Ensure this block starts at the correct indentation level (same as the 'if args.clean_rules:' line)
    if not args.file:
        parser.error("the following arguments are required: --file/-f (unless --clean-rules is used)")
        # Although parser.error usually exits, adding sys.exit for clarity
        sys.exit(1)

    # Validate log file (only if not cleaning)
    if not os.path.exists(args.file):
        logger.error(f"Error: File not found {args.file}")
        sys.exit(1)
        
    # Define start_date (needs to be UTC aware for analyzer)
    start_date_utc = None
    now_local = datetime.now() # Get local time once

    if args.time_window:
        # calculate_start_date returns naive local time
        start_date_naive_local = calculate_start_date(args.time_window)
        if start_date_naive_local:
             # Convert to aware local, then to UTC
             start_date_aware_local = start_date_naive_local.astimezone()
             start_date_utc = start_date_aware_local.astimezone(timezone.utc)
             logger.info(f"Using time window: {args.time_window} (from {start_date_utc})")
    elif args.start_date:
        try:
            # Parse as naive local time
            start_date_naive_local = datetime.strptime(args.start_date, '%d/%b/%Y:%H:%M:%S')
            # Convert to aware local, then to UTC
            start_date_aware_local = start_date_naive_local.astimezone()
            start_date_utc = start_date_aware_local.astimezone(timezone.utc)
            logger.info(f"Using start date: {start_date_utc}")
        except ValueError:
            logger.error("Error: Invalid date format. Use dd/mmm/yyyy:HH:MM:SS")
            sys.exit(1)

    # Initialize analyzer (pass only rpm_threshold, whitelist is loaded from file)
    analyzer = ThreatAnalyzer(rpm_threshold=args.threshold)

    # Load whitelist if specified
    if args.whitelist:
        analyzer.load_whitelist_from_file(args.whitelist)
        # Pass the loaded whitelist to the analyzer instance if needed elsewhere,
        # but load_log_into_dataframe now handles it directly.

    # Analyze log file (loads into DataFrame)
    logger.info(f"Starting analysis of {args.file}...")
    try:
        processed_count = analyzer.analyze_log_file(args.file, start_date_utc)
        if processed_count < 0:
             sys.exit(1) # Error occurred during loading
        elif processed_count == 0:
             logger.warning("No log entries processed. Exiting.")
             sys.exit(0)
    except Exception as e:
        logger.error(f"Error analyzing log file: {e}", exc_info=True)
        sys.exit(1)

    # Identify threats (performs pandas calculations)
    threats = analyzer.identify_threats()

    # --- Blocking Logic ---
    blocked_targets_info = {} # Store {target_str: comment} for blocked targets
    if args.block:
        ufw = UFWManager(dry_run=args.dry_run)
        min_requests_to_block = args.block_threshold
        block_duration_minutes = args.block_duration

        logger.info(f"Checking top {args.top} threats for potential blocking (threshold: {min_requests_to_block} requests)...")

        threats_to_consider_for_blocking = threats[:args.top]

        for threat in threats_to_consider_for_blocking:
            target_id = threat['id'] # ipaddress.ip_network object
            total_requests = threat['total_requests']

            if total_requests >= min_requests_to_block:
                logger.info(f"Threat {str(target_id)} meets block threshold ({total_requests} >= {min_requests_to_block}). Attempting block...")

                # block_target expects ipaddress object and duration
                if ufw.block_target(target_id, block_duration_minutes):
                    # Store info about the block action if successful
                    expiry_time = datetime.now(timezone.utc) + timedelta(minutes=block_duration_minutes)
                    expiry_str = expiry_time.strftime('%Y%m%dT%H%M%SZ')
                    comment = f"blocked_by_stats_py_until_{expiry_str}"
                    blocked_targets_info[str(target_id)] = comment
            else:
                 logger.debug(f"Threat {str(target_id)} does not meet block threshold ({total_requests} < {min_requests_to_block}). Skipping block.")

        # Note: schedule_rule_cleanup is likely not needed if --clean-rules is run periodically via cron
        # if block_duration_minutes > 0:
        #     logger.info(f"Scheduling cleanup task for rules older than {block_duration_minutes} minutes.")
        #     # ufw.schedule_rule_cleanup(...) # This method might be removed or changed

    # --- Reporting Logic ---
    top_count = min(args.top, len(threats))
    print(f"\n=== TOP {top_count} MOST ACTIVE SUBNETS DETECTED (Sorted by Total Requests) ===")
    if args.block:
        action = "Blocked" if not args.dry_run else "[DRY RUN] Marked for blocking"
        print(f"--- {action} based on --block-threshold={args.block_threshold} total requests and --block-duration={args.block_duration} min (applied to top {args.top} subnets by activity) ---")

    top_threats_report = threats[:top_count]

    for i, threat in enumerate(top_threats_report, 1):
        target_id_str = str(threat['id'])
        danger_str = f"Danger: {threat['danger_score']:.2f}"
        # Use the new RPM metrics
        avg_rpm_str = f"~{threat.get('subnet_avg_ip_rpm', 0):.2f} avg_ip_rpm"
        max_rpm_str = f"{threat.get('subnet_max_ip_rpm', 0):.0f} max_ip_rpm"
        rpm_info = f"{avg_rpm_str}, {max_rpm_str}"
        ip_count_str = f"{threat['ip_count']} IP" if threat['ip_count'] == 1 else f"{threat['ip_count']} IPs"

        print(f"\n#{i} Subnet: {target_id_str} - Requests: {threat['total_requests']} ({ip_count_str}, {danger_str}, {rpm_info})")

        # Show details for top IPs using the new structure
        if threat['details']:
            print("  -> Top IPs (by danger score):")
            for ip_detail in threat['details']:
                 print(f"     - IP: {ip_detail['ip']} ({ip_detail['total_requests']} reqs, Danger: {ip_detail['danger_score']:.2f}, AvgRPM: {ip_detail['avg_rpm']:.2f}, MaxRPM: {ip_detail['max_rpm']:.0f})")
        else:
             print("  -> No IP details available.")


        # Indicate if this specific threat target was blocked in this run
        if args.block and target_id_str in blocked_targets_info:
            block_status = "[BLOCKED]" if not args.dry_run else "[DRY RUN - BLOCKED]"
            print(f"  {block_status} (Target was in top {args.top} and met threshold)")

    # Export results if specified
    if args.output:
        if analyzer.export_results(args.format, args.output):
            logger.info(f"Results exported to {args.output} in {args.format} format")
        else:
            logger.error(f"Error exporting results to {args.output}")

    # Run cleanup of expired rules (Optional, if not using cron for --clean-rules)
    # Consider removing this if --clean-rules is the primary method for cleanup.
    # if args.block:
    #     logger.info("Running cleanup of expired UFW rules post-analysis...")
    #     if 'ufw' in locals():
    #         count = ufw.clean_expired_rules()
    #         if count > 0:
    #             logger.info(f"Post-analysis cleanup completed. {count} rules deleted.")

    # Show final summary
    print(f"\nAnalysis completed. {len(blocked_targets_info)} unique targets {'blocked' if not args.dry_run else 'marked for blocking'} in this execution.")
    print(f"From a total of {len(threats)} detected threats.")
    if args.block:
        print(f"Use '--clean-rules' periodically (e.g., via cron) to remove expired rules.")

if __name__ == '__main__':
    main()

