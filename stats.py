#!/usr/bin/env python3
"""
Main script for log analysis and bot threat detection.
Detects suspicious patterns and can block IPs using UFW.

Usage:
    python stats.py -f /path/to/file.log [options]
"""
import argparse
import re
from datetime import datetime, timedelta, timezone
import sys
import os
import logging
import ipaddress

# Import own modules
from log_parser import parse_log_line, get_subnet, is_ip_in_whitelist
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
        description='Analyzes a log file, generates statistics and optionally blocks threats with UFW.'
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
        logger.info(f"Cleanup completed. {count} rules deleted.")
        return # Exit after cleaning

    # Now, if not cleaning rules, --file becomes mandatory
    if not args.file:
        parser.error("the following arguments are required: --file/-f (unless --clean-rules is used)")
        # Although parser.error usually exits, adding sys.exit for clarity
        sys.exit(1)

    # Validate log file (only if not cleaning)
    if not os.path.exists(args.file):
        logger.error(f"Error: File not found {args.file}")
        sys.exit(1)
        
    # Define start_date
    start_date = None
    
    # Prioritize --time-window over --start-date if both are present
    if args.time_window:
        start_date = calculate_start_date(args.time_window)
        logger.info(f"Using time window: {args.time_window} (from {start_date})")
    elif args.start_date:
        try:
            start_date = datetime.strptime(args.start_date, '%d/%b/%Y:%H:%M:%S')
            logger.info(f"Using start date: {start_date}")
        except ValueError:
            logger.error("Error: Invalid date. Use format dd/mmm/yyyy:HH:MM:SS (e.g. 16/Apr/2025:13:16:50)")
            sys.exit(1)
    
    # Initialize analyzer
    analyzer = ThreatAnalyzer(rpm_threshold=args.threshold)
    
    # Load whitelist if specified
    whitelist_count = 0
    if args.whitelist:
        whitelist_count = analyzer.load_whitelist_from_file(args.whitelist)
        if whitelist_count == 0:
            logger.warning(f"Could not load whitelist entries from {args.whitelist}")
    
    # Analyze log file
    logger.info(f"Starting analysis of {args.file}...")
    try:
        analyzer.analyze_log_file(args.file, start_date)
    except Exception as e:
        logger.error(f"Error analyzing log file: {e}")
        sys.exit(1)
    
    # Identify threats
    threats = analyzer.identify_threats()
    
    # --- Blocking Logic ---
    blocked_targets = set() # Store network objects blocked in this run
    if args.block:
        ufw = UFWManager(dry_run=args.dry_run)
        min_requests_to_block = args.block_threshold
        block_duration_minutes = args.block_duration
        comment_prefix = "BOTSTATS"

        logger.info(f"Checking top {args.top} threats for potential blocking (threshold: {min_requests_to_block} requests)...")

        # Determine which threats to consider for blocking (only the top ones)
        threats_to_consider_for_blocking = threats[:args.top] # Use the top N threats

        # Iterate ONLY over the top threats for blocking decisions
        for threat in threats_to_consider_for_blocking:
            target_id = threat['id'] # This is an ipaddress.ip_network object
            target_id_str = str(target_id)
            total_requests = threat['total_requests']

            # Check if the threat meets the blocking threshold
            if total_requests >= min_requests_to_block:
                logger.info(f"Threat {target_id_str} meets block threshold ({total_requests} >= {min_requests_to_block}). Attempting block...")
                comment = f"{comment_prefix} - {total_requests} reqs - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                if block_duration_minutes > 0:
                     comment += f" - Remove after {block_duration_minutes} min"

                # Block the target (IP or Subnet)
                if ufw.block_ip_or_subnet(target_id_str, comment):
                    blocked_targets.add(target_id) # Add the network object to the set
            else:
                 logger.debug(f"Threat {target_id_str} does not meet block threshold ({total_requests} < {min_requests_to_block}). Skipping block.")

        # Schedule cleanup if duration is set
        if block_duration_minutes > 0:
            logger.info(f"Scheduling cleanup task for rules older than {block_duration_minutes} minutes.")
            ufw.schedule_rule_cleanup(comment_prefix, block_duration_minutes)

    # --- Reporting Logic ---
    # Show results in console
    top_count = min(args.top, len(threats))
    print(f"\n=== TOP {top_count} MOST ACTIVE SUBNETS DETECTED (Sorted by Total Requests) ===") # Adjusted title
    if args.block:
        action = "Blocked" if not args.dry_run else "[DRY RUN] Marked for blocking"
        print(f"--- {action} based on --block-threshold={args.block_threshold} total requests and --block-duration={args.block_duration} min (applied to top {args.top} subnets by activity) ---") # Adjusted description

    top_threats_report = threats[:top_count]

    for i, threat in enumerate(top_threats_report, 1):
        target_id_str = str(threat['id'])
        threat_label = "Subnet"
        danger_str = f"Danger: {threat['danger_score']:.2f}"
        rpm_str = f", ~{threat.get('subnet_rpm', 0):.2f} agg RPM" if threat.get('subnet_rpm', 0) > 0 else ""
        ip_count_str = f"{threat['ip_count']} IP" if threat['ip_count'] == 1 else f"{threat['ip_count']} IPs"

        print(f"\n#{i} {threat_label}: {target_id_str} - Requests: {threat['total_requests']} ({ip_count_str}, {danger_str}{rpm_str})")

        # Show list of IPs involved (limited)
        if threat['details']:
            max_details_to_show = 5
            ips_to_show = threat['details'][:max_details_to_show]
            print(f"  -> IPs involved: {', '.join(ips_to_show)}", end="") # Use end="" to potentially add more text
            if threat['ip_count'] > max_details_to_show:
                print(f", ... ({threat['ip_count'] - max_details_to_show} more)", end="")
            print() # Print newline

        # Indicate if this specific threat target was blocked in this run
        target_blocked_in_run = False
        for blocked_net in blocked_targets: # Check against the set of actually blocked targets
             try:
                 # Check if the reported threat ID is exactly the one blocked or is contained within a blocked network
                 if threat['id'] == blocked_net or threat['id'].subnet_of(blocked_net):
                     target_blocked_in_run = True
                     break
                 # Check if the reported threat ID contains a network that was blocked
                 if blocked_net.subnet_of(threat['id']):
                      target_blocked_in_run = True
                      break
             except (TypeError, AttributeError):
                 pass # Ignore comparison errors

        if args.block and target_blocked_in_run:
            block_status = "[BLOCKED]" if not args.dry_run else "[DRY RUN - BLOCKED]"
            print(f"  {block_status} (Target or encompassing/contained subnet was in top {args.top} and met threshold)")

    # Export results if specified
    if args.output:
        if analyzer.export_results(args.format, args.output):
            logger.info(f"Results exported to {args.output} in {args.format} format")
        else:
            logger.error(f"Error exporting results to {args.output}")
    
    # Run cleanup of expired rules
    if args.block:
        logger.info("Running cleanup of expired UFW rules...")
        if ufw:
            count = ufw.clean_expired_rules()
            if count > 0:
                logger.info(f"Cleanup completed. {count} rules deleted.")

    # Show final summary
    print(f"\nAnalysis completed. {len(blocked_targets)} unique targets {'blocked' if not args.dry_run else 'marked for blocking'} in this execution.")
    print(f"From a total of {len(threats)} detected threats.")
    if args.block:
        print(f"Use --clean-rules to remove expired rules in the future.")

if __name__ == '__main__':
    main()

