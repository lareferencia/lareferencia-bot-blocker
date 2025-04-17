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
    parser.add_argument(
        '--file', '-f', required=True,
        help='Path of the log file to analyze.'
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

    # Configure logging
    log_level = getattr(logging, args.log_level)
    setup_logging(args.log_file, log_level)
    logger = logging.getLogger('botstats.main')
    
    # If we only want to clean rules, do it and exit
    if args.clean_rules:
        logger.info("Starting cleanup of expired UFW rules...")
        ufw = UFWManager(args.dry_run)
        count = ufw.clean_expired_rules()
        logger.info(f"Cleanup completed. {count} rules deleted.")
        return
    
    # Validate log file
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
    
    # Check if there are threats
    if not threats:
        logger.info("No suspicious threats found according to the specified criteria.")
        if args.block:
            logger.info("No blocking actions executed.")
        sys.exit(0)
    
    # Initialize UFW manager if blocking is required
    ufw = None
    if args.block:
        ufw = UFWManager(args.dry_run)
    
    # Block threats if the option is activated
    blocked_targets = set()
    if args.block:
        for threat in threats:
            target = threat['id']
            total_requests = threat['total_requests']
            # Check threshold for blocking
            should_block = total_requests >= args.block_threshold
            if should_block and target not in blocked_targets:
                if ufw.block_target(target, args.block_duration):
                    blocked_targets.add(target)
    
    # Show results in console
    top_count = min(args.top, len(threats))
    print(f"\n=== TOP {top_count} MOST DANGEROUS THREATS DETECTED ===")
    if args.block:
        action = "Blocked" if not args.dry_run else "[DRY RUN] Marked for blocking"
        print(f"--- {action} according to --block-threshold={args.block_threshold} total requests and --block-duration={args.block_duration} min ---")

    # Take only the first 'top' threats for the detailed report
    top_threats_report = threats[:top_count]

    for i, threat in enumerate(top_threats_report, 1):
        target_id_str = str(threat['id'])
        # Display Subnet Info including aggregate RPM
        subnet_rpm_str = f", ~{threat.get('subnet_rpm', 0):.2f} agg RPM" if threat.get('subnet_rpm', 0) > 0 else ""
        print(f"\n#{i} Subnet: {target_id_str} - Total Danger: {threat['danger_score']:.2f} ({threat['ip_count']} IPs, {threat['total_requests']} reqs{subnet_rpm_str})")
        
        # Show details of the most dangerous IPs within the subnet
        for ip_detail in threat['details'][:3]:  # Show up to 3 IPs
            # Indicate if this specific IP triggered the RPM suspicion flag
            rpm_flag_str = "*" if ip_detail.get('is_suspicious_by_rpm', False) else ""
            rpm_str = f"~{ip_detail['rpm']:.2f} rpm{rpm_flag_str}" if ip_detail['rpm'] > 0 else "RPM N/A"
            ua_str = f" | UA: {ip_detail['suspicious_ua']}" if ip_detail['has_suspicious_ua'] else ""
            print(f"  -> IP: {ip_detail['ip']} ({ip_detail['total_requests']} reqs, Danger: {ip_detail['danger_score']:.2f}, {rpm_str}{ua_str})")
        if threat['ip_count'] > 3:
            print(f"  ... and {threat['ip_count'] - 3} more IPs in this subnet.")

        # Indicate if this specific threat was blocked
        if args.block and threat['id'] in blocked_targets:
            block_status = "[BLOCKED]" if not args.dry_run else "[DRY RUN - BLOCK]"
            print(f"  {block_status}")
    
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

