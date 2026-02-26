#!/usr/bin/env python3
"""
Main script for log analysis and bot threat detection using native Python and configurable strategies.
"""
import argparse
import re
from datetime import datetime, timedelta, timezone
import sys
import os
import logging
import ipaddress
import importlib
from collections import defaultdict
import time
import json
import psutil
import fcntl  # For file locking (UNIX systems)


# Import own modules
from parser import get_subnet, is_ip_in_whitelist, stream_log_entries
# Import UFWManager and COMMENT_PREFIX directly if needed
import ufw_handler
from threat_analyzer import ThreatAnalyzer

# Logging configuration
LOG_FORMAT = '%(asctime)s %(levelname)s %(name)s: %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

# --- Helper Functions for Strike History ---

# Default value for strike history max age (can be overridden via CLI)
DEFAULT_STRIKE_HISTORY_MAX_AGE_HOURS = 48
DEFAULT_IP_MIN_RPM_THRESHOLD = 20.0
DEFAULT_IP_MIN_SUSTAINED_PERCENT = 35.0
DEFAULT_IP_MIN_REQUESTS = 120

def load_strike_history(filepath, max_age_hours=DEFAULT_STRIKE_HISTORY_MAX_AGE_HOURS):
    """Loads strike history from JSON, cleans old entries.
    
    Args:
        filepath: Path to the strike history JSON file.
        max_age_hours: Strike entries older than this are purged.
    """
    logger = logging.getLogger('botstats.strike_history')
    history = {}
    if not filepath or not os.path.exists(filepath):
        logger.info(f"Strike history file not found or not specified ('{filepath}'). Starting fresh.")
        return history

    try:
        with open(filepath, 'r') as f:
            fcntl.flock(f, fcntl.LOCK_SH)  # Shared lock for reading
            try:
                history = json.load(f)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        logger.info(f"Loaded strike history for {len(history)} targets from {filepath}.")
    except json.JSONDecodeError:
        logger.warning(f"Could not decode JSON from strike history file: {filepath}. Starting fresh.")
        return {}
    except Exception as e:
        logger.error(f"Error loading strike history file {filepath}: {e}. Starting fresh.")
        return {}

    # Clean old timestamps
    cleaned_history = {}
    now_utc = datetime.now(timezone.utc)
    cutoff_time = now_utc - timedelta(hours=max_age_hours)
    cleaned_count = 0
    kept_count = 0

    for target_id, timestamps in history.items():
        valid_timestamps = []
        if isinstance(timestamps, list):
            for ts_str in timestamps:
                try:
                    ts_utc = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    if ts_utc >= cutoff_time:
                        valid_timestamps.append(ts_str)
                        kept_count += 1
                    else:
                        cleaned_count += 1
                except (ValueError, TypeError):
                    logger.warning(f"Invalid timestamp format '{ts_str}' for target '{target_id}' in history. Skipping.")
        if valid_timestamps:
            cleaned_history[target_id] = valid_timestamps

    if cleaned_count > 0:
        logger.info(f"Removed {cleaned_count} strike entries older than {max_age_hours} hours.")
    logger.debug(f"Strike history loaded and cleaned. Kept {kept_count} recent strikes for {len(cleaned_history)} targets.")
    return cleaned_history

def save_strike_history(filepath, history):
    """Saves strike history to JSON safely with file locking."""
    logger = logging.getLogger('botstats.strike_history')
    if not filepath:
        logger.warning("Strike history file path not specified. Cannot save history.")
        return False
    
    try:
        with open(filepath, 'w') as f:
            fcntl.flock(f, fcntl.LOCK_EX)  # Exclusive lock for writing
            try:
                json.dump(history, f, indent=2)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        logger.info(f"Successfully saved strike history for {len(history)} targets to {filepath}.")
        return True
    except Exception as e:
        logger.error(f"Error saving strike history to {filepath}: {e}")
        return False

# --- End Helper Functions ---


def setup_logging(log_file=None, log_level=logging.INFO):
    """
    Configure the logging system.
    
    Args:
        log_file (str, optional): Path to the log file
        log_level (int): Logging level
    """
    handlers = []
    
    # UTC ISO timestamps for clearer operational correlation.
    formatter = logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT)
    formatter.converter = time.gmtime

    # Always add console handler
    console = logging.StreamHandler()
    console.setLevel(log_level)
    console.setFormatter(formatter)
    handlers.append(console)
    
    # Add file handler if specified
    if (log_file):
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        handlers=handlers
    )


def utc_now_str():
    """Returns current UTC timestamp in compact ISO format."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def compact_block_line(action, target_type, target, duration_minutes, strike_count,
                       req=None, ips=None, rpm=None, span=None, mode_tag=None):
    """Build a compact single-line block event message."""
    parts = [
        utc_now_str(),
        action,
        target_type,
        str(target),
        f"dur={duration_minutes}m",
        f"strikes={strike_count}"
    ]
    if req is not None:
        parts.append(f"req={int(req)}")
    if ips is not None:
        parts.append(f"ips={int(ips)}")
    if rpm is not None:
        parts.append(f"rpm={float(rpm):.2f}")
    if span is not None:
        parts.append(f"span={float(span):.0f}s")
    if mode_tag:
        parts.append(mode_tag)
    return " ".join(parts)

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


def calculate_effective_thresholds(cpu_load_percent, base_min_rpm_threshold, base_min_sustained_percent, max_cpu_load_threshold):
    """
    Calculates effective RPM and sustained thresholds after dynamic CPU adjustment.

    Mirrors the unified strategy logic so blocker-side decisions can reuse
    exactly the same effective thresholds.
    """
    min_rpm_threshold = float(base_min_rpm_threshold)
    min_sustained_percent = float(base_min_sustained_percent)

    if cpu_load_percent >= max_cpu_load_threshold:
        # RPM: 50% at threshold, down to 25% at 90%, then fixed.
        if cpu_load_percent >= 90.0:
            rpm_factor = 0.25
        else:
            rpm_factor = 0.5 - ((cpu_load_percent - max_cpu_load_threshold) / 10.0) * 0.25

        # Sustained: 50% at threshold, 25% at 90%, down to 12% at 100%.
        if cpu_load_percent >= 90.0:
            sustained_factor = 0.25 - ((cpu_load_percent - 90.0) / 10.0) * 0.13
            sustained_factor = max(0.12, sustained_factor)
        else:
            sustained_factor = 0.5 - ((cpu_load_percent - max_cpu_load_threshold) / 10.0) * 0.25

        min_rpm_threshold = base_min_rpm_threshold * rpm_factor
        min_sustained_percent = base_min_sustained_percent * sustained_factor

    return min_rpm_threshold, min_sustained_percent


def aggregate_ipv4_supernet_pressure(threats):
    """
    Aggregates /24 threat metrics into /16 distributed-pressure metrics.

    Returns:
        dict: supernet -> metrics dict with total requests, total ips, total rpm,
              max subnet timespan, and member /24 subnet objects.
    """
    supernet_metrics = defaultdict(lambda: {
        'total_requests': 0,
        'total_ips': 0,
        'total_rpm': 0.0,
        'max_subnet_time_span': 0.0,
        'member_subnets': []
    })

    for threat in threats:
        subnet = threat.get('id')
        if not isinstance(subnet, ipaddress.IPv4Network) or subnet.prefixlen != 24:
            continue

        try:
            supernet = subnet.supernet(new_prefix=16)
        except ValueError:
            continue

        m = supernet_metrics[supernet]
        m['total_requests'] += int(threat.get('total_requests', 0) or 0)
        m['total_ips'] += int(threat.get('ip_count', 0) or 0)
        m['total_rpm'] += float(threat.get('subnet_req_per_min_window', 0.0) or 0.0)
        m['max_subnet_time_span'] = max(m['max_subnet_time_span'], float(threat.get('subnet_time_span', 0.0) or 0.0))
        m['member_subnets'].append(subnet)

    return supernet_metrics


def build_ip_pressure_metrics(ip_metrics, analysis_duration_seconds):
    """
    Builds per-IP pressure metrics normalized to the analysis window.

    Returns:
        list[dict]: entries with ip_obj, subnet_obj, total_requests, time_span, req_per_min_window.
    """
    entries = []
    if not ip_metrics:
        return entries

    window_minutes = (analysis_duration_seconds / 60.0) if analysis_duration_seconds and analysis_duration_seconds > 0 else 0.0
    for ip_str, metrics in ip_metrics.items():
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        total_requests = int(metrics.get('total_requests', 0) or 0)
        time_span = float(metrics.get('time_span_seconds', 0.0) or 0.0)
        req_per_min_window = (total_requests / window_minutes) if window_minutes > 0 else 0.0
        subnet_obj = metrics.get('subnet') or get_subnet(ip_str)

        entries.append({
            'ip_obj': ip_obj,
            'subnet_obj': subnet_obj,
            'total_requests': total_requests,
            'time_span_seconds': time_span,
            'req_per_min_window': req_per_min_window,
        })

    return entries

def main():
    # --- Determine script directory for default strike file path ---
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_strike_file_path = os.path.join(script_dir, 'strike_history.json')
    # --- End determine script directory ---

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
        '--time-window', '-tw', required=False, default=None,
        choices=['hour', '6hour', 'day', 'week'], # Add '6hour' choice
        help='Analyze logs from the last hour (default if --start-date is not set), 6 hours, day, or week (overrides --start-date).'
    )
    # --- Analysis Args ---
    parser.add_argument(
        '--top', '-n', type=int, default=10,
        help='Number of threats to display in report (0 = show all). All threats exceeding thresholds are processed for blocking.'
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
    # Unified strategy parameters
    parser.add_argument(
        '--min-rpm-threshold', type=float, default=10.0,
        help='Minimum requests per minute threshold for blocking.'
    )
    parser.add_argument(
        '--min-sustained-percent', type=float, default=25.0,
        help='Minimum percentage of analysis window duration a subnet must be active for blocking.'
    )
    parser.add_argument(
        '--max-cpu-load-threshold', type=float, default=80.0,
        help='CPU load percentage threshold for aggressive mode (80-100%% triggers dynamic threshold reduction).'
    )
    parser.add_argument(
        '--ip-swarm-threshold', type=int, default=40,
        help='Minimum unique IP count in a subnet to consider swarm behavior.'
    )
    parser.add_argument(
        '--ip-swarm-rpm-factor', type=float, default=0.60,
        help='RPM factor over effective threshold used by swarm condition (0.60 = 60%%).'
    )
    parser.add_argument(
        '--ip-swarm-bonus-max', type=float, default=1.50,
        help='Maximum IP diversity bonus added to strategy score.'
    )
    parser.add_argument(
        '--ip-min-rpm-threshold', type=float, default=DEFAULT_IP_MIN_RPM_THRESHOLD,
        help='Per-IP persistence layer: minimum req/min (window-normalized) required to block a single IP.'
    )
    parser.add_argument(
        '--ip-min-sustained-percent', type=float, default=DEFAULT_IP_MIN_SUSTAINED_PERCENT,
        help='Per-IP persistence layer: minimum %% of analysis window an IP must stay active.'
    )
    parser.add_argument(
        '--ip-min-requests', type=int, default=DEFAULT_IP_MIN_REQUESTS,
        help='Per-IP persistence layer: minimum total requests required to block a single IP.'
    )
    parser.add_argument(
        '--supernet-min-rpm-total', type=float, default=6.0,
        help='Principal /16 distributed-pressure threshold: minimum total req/min aggregated across /24 subnets in the /16.'
    )
    parser.add_argument(
        '--supernet-min-ip-count', type=int, default=120,
        help='Principal /16 distributed-pressure threshold: minimum total unique IP count aggregated across /24 subnets in the /16.'
    )
    parser.add_argument(
        '--supernet-min-requests', type=int, default=200,
        help='Principal /16 distributed-pressure threshold: minimum total request volume in the /16.'
    )
    parser.add_argument(
        '--block-duration', type=int, default=60,
        help='Default duration of the UFW block in minutes (used if strike count < block_escalation_strikes).'
    )
    parser.add_argument(
        '--block-escalation-strikes', type=int, default=4,
        help='Number of strikes within the history window required to trigger escalated block duration (1440 min).'
    )
    parser.add_argument(
        '--strike-file', default=default_strike_file_path,
        help='Path to the JSON file for storing strike history (for escalating block duration).'
    )
    parser.add_argument(
        '--strike-max-age-hours', type=int, default=48,
        help='Strike history entries older than this many hours are purged on load.'
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
    if args.time_window is None and not args.start_date:
        args.time_window = 'hour'

    if args.supernet_min_rpm_total <= 0:
        parser.error("--supernet-min-rpm-total must be > 0.")
    if args.supernet_min_ip_count <= 0:
        parser.error("--supernet-min-ip-count must be > 0.")
    if args.supernet_min_requests <= 0:
        parser.error("--supernet-min-requests must be > 0.")
    if args.ip_swarm_threshold < 2:
        parser.error("--ip-swarm-threshold must be >= 2.")
    if not (0.0 < args.ip_swarm_rpm_factor <= 1.0):
        parser.error("--ip-swarm-rpm-factor must be > 0 and <= 1.")
    if args.ip_swarm_bonus_max <= 0:
        parser.error("--ip-swarm-bonus-max must be > 0.")
    if args.ip_min_rpm_threshold <= 0:
        parser.error("--ip-min-rpm-threshold must be > 0.")
    if not (0.0 < args.ip_min_sustained_percent <= 100.0):
        parser.error("--ip-min-sustained-percent must be > 0 and <= 100.")
    if args.ip_min_requests <= 0:
        parser.error("--ip-min-requests must be > 0.")

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


    # Strategy name used for analysis (loaded by ThreatAnalyzer internally)
    strategy_name = 'unified'


    # --- Analysis ---
    # Pass rpm_threshold? Currently unused by analyzer directly.
    analyzer = ThreatAnalyzer(whitelist=None) # Whitelist loaded separately
    if args.whitelist:
        analyzer.load_whitelist_from_file(args.whitelist)

    logger.info(f"Starting analysis of {args.file}...")
    total_overall_requests = 0 # Initialize

    try:
        # --- Load and Parse Log Data using the analyzer directly ---
        # The analyzer now handles streaming and metric calculation internally
        total_overall_requests = analyzer.analyze_log_file(
            log_file=args.file,
            start_date_utc=start_date_utc
        )

        if total_overall_requests == -1:
             logger.error("Failed to analyze log data. Exiting.")
             sys.exit(1)
        
        if total_overall_requests == 0:
             logger.warning("No log entries found or all filtered out. Exiting.")
             sys.exit(0)

        logger.info(f"Total requests in analysis window: {total_overall_requests}")


    except Exception as e:
        logger.error(f"Error during analysis execution: {e}", exc_info=True)
        sys.exit(1)


    # --- Get System Load Average and CPU Load Percentage ---
    system_load_avg = -1.0 # Default if psutil fails or not available
    cpu_load_percent = 0.0 # Default CPU load percentage
    try:
        # getloadavg() returns a tuple of (1min, 5min, 15min) load averages
        load_averages = psutil.getloadavg()
        system_load_avg = load_averages[2] # 15-min avg for logging/reference
        load_avg_1min = load_averages[0]   # 1-min avg for dynamic threshold calculation
        
        # Get CPU count to normalize load average to a percentage
        cpu_count = psutil.cpu_count()
        if cpu_count and cpu_count > 0:
            # Calculate percentage: (Load Avg / CPU Count) * 100
            # This represents the system load relative to capacity.
            # It can exceed 100% if the system is overloaded.
            cpu_load_percent = (load_avg_1min / cpu_count) * 100.0
            logger.info(f"System Load Avg (1min): {load_avg_1min:.2f}, CPUs: {cpu_count}")
            logger.info(f"CPU Load Percentage (Normalized Load Avg): {cpu_load_percent:.1f}%")
        else:
            logger.warning("Could not determine CPU count. Defaulting CPU load to 0%.")
            cpu_load_percent = 0.0

    except Exception as e:
        logger.warning(f"Could not retrieve system load average using psutil: {e}. Proceeding without it.")
        cpu_load_percent = 0.0
    
    # Always print system load average, format based on silent mode
    if system_load_avg != -1.0:
        load_avg_message = f"System load average (15-min): {system_load_avg:.2f}"
        if args.silent:
            print(f"{utc_now_str()} INFO: {load_avg_message}")
        else:
            pass # logger.info already covers non-silent
    elif args.silent: # If psutil failed and in silent mode, print a message
        print(f"{utc_now_str()} WARNING: Could not retrieve system load average.")

    # --- End Get System Load Average and CPU Load Percentage ---

    # Calculate effective thresholds once, reusing unified strategy logic.
    effective_rpm_threshold, effective_sustained_percent = calculate_effective_thresholds(
        cpu_load_percent=cpu_load_percent,
        base_min_rpm_threshold=args.min_rpm_threshold,
        base_min_sustained_percent=args.min_sustained_percent,
        max_cpu_load_threshold=args.max_cpu_load_threshold
    )
    effective_ip_rpm_threshold, effective_ip_sustained_percent = calculate_effective_thresholds(
        cpu_load_percent=cpu_load_percent,
        base_min_rpm_threshold=args.ip_min_rpm_threshold,
        base_min_sustained_percent=args.ip_min_sustained_percent,
        max_cpu_load_threshold=args.max_cpu_load_threshold
    )
    logger.info(
        "Effective thresholds: RPM=%.2f req/min, Sustained=%.2f%% (CPU load %.1f%%, trigger %.1f%%)",
        effective_rpm_threshold, effective_sustained_percent, cpu_load_percent, args.max_cpu_load_threshold
    )
    logger.info(
        "Effective IP-layer thresholds: RPM=%.2f req/min, Sustained=%.2f%%, MinReq=%d",
        effective_ip_rpm_threshold, effective_ip_sustained_percent, args.ip_min_requests
    )

    # --- Define metrics_to_track_for_max and metric_names_map earlier for use later ---
    metrics_to_track_for_max = [
        'total_requests', 'ip_count',
        'subnet_time_span',
        'subnet_req_per_min_window'
    ]
    metric_names_map = {
        'total_requests': 'Total Requests',
        'ip_count': 'IP Count',
        'subnet_time_span': 'Subnet Activity Timespan (s)',
        'subnet_req_per_min_window': 'Subnet Req/Min (Window Avg)'
    }
    # --- End Define metrics_to_track_for_max ---

    # --- Create Shared Context Parameters for Strategies (Initial) ---
    # This context will be enriched by ThreatAnalyzer with specific maximums
    shared_context_params = {
        'analysis_duration_seconds': analysis_duration_seconds,
        'total_overall_requests': total_overall_requests,
        'system_load_avg': system_load_avg,
        'cpu_load_percent': cpu_load_percent,
        # Maximums like 'max_total_requests' will be calculated and added by ThreatAnalyzer
    }
    logger.debug(f"Initial shared context parameters for ThreatAnalyzer: {shared_context_params}")
    # --- End Create Shared Context Parameters ---

    # --- Identify Threats ---
    # ThreatAnalyzer will use the initial shared_context_params, calculate detailed metrics,
    # then calculate maximums from those metrics, and pass an enriched context to the strategies.
    threats = analyzer.identify_threats(
        strategy_name='unified',
        shared_context_params=shared_context_params,
        config=args
    )

    # Check if threats list is valid
    if threats is None:
        logger.error("Threat identification failed.")
        sys.exit(1)
    if not threats:
        logger.info("No threats identified after analysis.")
        # threats is an empty list, proceed to reporting section which will handle it

    # --- Get threats dict for Reporting (after threats are identified) ---
    threats_dict = analyzer.get_threats_dict()

    # --- Calculate Overall Maximums for FINAL REPORTING (using the final threats) ---
    max_metrics_data_for_reporting = {}
    if threats:
        for metric_key in metrics_to_track_for_max:
            try:
                values = [t.get(metric_key, None) for t in threats if t.get(metric_key) is not None]
                if values:
                    max_value = max(values)
                    # Find subnets with this max value
                    max_subnets = [str(t.get('id')) for t in threats if t.get(metric_key) == max_value]
                    max_metrics_data_for_reporting[metric_key] = {'value': max_value, 'subnets': max_subnets}
                else:
                    max_metrics_data_for_reporting[metric_key] = {'value': -1, 'subnets': []}
            except Exception as e:
                logger.warning(f"Could not calculate max for reporting metric '{metric_key}': {e}")
                max_metrics_data_for_reporting[metric_key] = {'value': -1, 'subnets': []}
    else:
        logger.info("Threats list is empty. Cannot calculate overall maximums for reporting.")
        for metric_key in metrics_to_track_for_max:
             max_metrics_data_for_reporting[metric_key] = {'value': -1, 'subnets': []}
    # --- End Calculate Overall Maximums for FINAL REPORTING ---

    # --- Blocking Logic ---
    blocked_targets_count = 0
    blocked_subnets_via_supernet = set() # Keep track of /24s blocked via /16
    blocked_subnets_individual = set() # Keep track of /24-/64 subnets blocked directly
    blocked_ips_individual = set() # Keep track of IPs blocked directly
    blocked_supernets = set() # Keep track of /16 networks blocked in this execution
    strike_history = {} # Initialize strike history dict
    distributed_supernets_checked = 0
    distributed_supernets_blocked = 0
    ip_layer_checked = 0
    ip_layer_blocked = 0

    if args.block:
        if not args.silent:
            print("-" * 30)
        logger.info(f"Processing blocks (Dry Run: {args.dry_run})...")
        ufw_manager_instance = ufw_handler.UFWManager(args.dry_run)

        # --- Load Strike History ---
        strike_history = load_strike_history(args.strike_file, args.strike_max_age_hours)
        # --- End Load Strike History ---

        # High-rate IP blocking removed in simplified version

        # 1. Principal /16 distributed-pressure blocking (always active in block mode)
        if analysis_duration_seconds <= 0:
            logger.warning("Distributed /16 blocking skipped: analysis duration is 0 seconds.")
        elif cpu_load_percent < args.max_cpu_load_threshold:
            logger.info(
                "Distributed /16 blocking skipped: CPU load %.1f%% is below trigger %.1f%%.",
                cpu_load_percent, args.max_cpu_load_threshold
            )
        else:
            min_sustained_seconds = analysis_duration_seconds * (effective_sustained_percent / 100.0)
            supernet_pressure = aggregate_ipv4_supernet_pressure(threats)
            distributed_supernets_checked = len(supernet_pressure)

            logger.info(
                "Checking %d /16 supernets for distributed-pressure blocking: total_rpm >= %.2f, total_ips >= %d, total_requests >= %d, max_timespan >= %.0fs (%.1f%%).",
                distributed_supernets_checked,
                args.supernet_min_rpm_total,
                args.supernet_min_ip_count,
                args.supernet_min_requests,
                min_sustained_seconds,
                effective_sustained_percent
            )

            for supernet, data in supernet_pressure.items():
                if data['total_rpm'] < args.supernet_min_rpm_total:
                    continue
                if data['total_ips'] < args.supernet_min_ip_count:
                    continue
                if data['total_requests'] < args.supernet_min_requests:
                    continue
                if data['max_subnet_time_span'] < min_sustained_seconds:
                    continue

                target_to_block_obj = supernet
                target_id_str = str(target_to_block_obj)
                target_type = "Supernet /16 (Distributed Pressure)"
                previous_strikes = len(strike_history.get(target_id_str, []))
                strike_count = previous_strikes + 1
                escalated = strike_count >= args.block_escalation_strikes
                block_duration = 1440 if escalated else args.block_duration
                duration_info = f"(Escalated: {strike_count} strikes)" if escalated else f"({strike_count} strikes)"

                sample_ids = [str(s) for s in data['member_subnets'][:5]]
                sample_text = ", ".join(sample_ids)
                if len(data['member_subnets']) > 5:
                    sample_text += ", ..."

                reason = (
                    f"distributed pressure: total_rpm={data['total_rpm']:.2f}, total_ips={data['total_ips']}, "
                    f"total_requests={data['total_requests']}, max_timespan={data['max_subnet_time_span']:.0f}s. "
                    f"Sample members: {sample_text}"
                )

                logger.info(
                    "Processing block for %s: %s. Duration: %dm %s",
                    target_type, target_to_block_obj, block_duration, duration_info
                )
                logger.debug("Block reason detail: %s", reason)
                success = ufw_manager_instance.block_target(
                    subnet_or_ip_obj=target_to_block_obj,
                    block_duration_minutes=block_duration
                )
                if success:
                    distributed_supernets_blocked += 1
                    blocked_targets_count += 1
                    action = "Blocked" if not args.dry_run else "Dry Run - Blocked"
                    compact_line = compact_block_line(
                        action=action,
                        target_type=target_type,
                        target=target_to_block_obj,
                        duration_minutes=block_duration,
                        strike_count=strike_count,
                        req=data.get('total_requests'),
                        ips=data.get('total_ips'),
                        rpm=data.get('total_rpm'),
                        span=data.get('max_subnet_time_span'),
                        mode_tag="distributed"
                    )
                    if args.silent:
                        print(compact_line)
                    else:
                        print(f" -> {compact_line}")

                    if not args.dry_run:
                        now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                        if target_id_str not in strike_history:
                            strike_history[target_id_str] = []
                        strike_history[target_id_str].append(now_iso)

                    blocked_supernets.add(target_to_block_obj)
                    for member_subnet in data['member_subnets']:
                        blocked_subnets_via_supernet.add(member_subnet)
                else:
                    if not args.silent:
                        action = "Failed to block" if not args.dry_run else "Dry Run - Failed"
                        print(f" -> {action} {target_type}: {target_to_block_obj}.")


        # 2. Process individual /24 or /64 Blocks (ALL threats that should be blocked)
        blockable_threats = [t for t in threats if t.get('should_block')]
        logger.info(f"Processing {len(blockable_threats)} individual threat blocks (/24 or /64) that exceed thresholds based on strategy '{strategy_name}'...")
        for threat in blockable_threats:
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
                block_duration = args.block_duration # Use general block duration here

                # Check for single IP subnet
                single_ip_obj_for_check = None # Store potential single IP object
                if threat.get('ip_count') == 1:
                    try:
                        single_ip_str = threat.get('single_ip')
                        if not single_ip_str:
                            raise ValueError("single_ip not available in threat data")
                        target_to_block_obj = ipaddress.ip_address(single_ip_str) # Convert back to object for UFW
                        single_ip_obj_for_check = target_to_block_obj # Keep the object for high RPM check
                        target_type = "Single IP"
                        logger.info(
                            "Threat %s has only 1 IP. Targeting IP %s instead of the whole subnet.",
                            threat['id'],
                            target_to_block_obj
                        )
                    except (IndexError, KeyError, ValueError, TypeError) as e:
                        logger.warning(
                            "Could not extract/convert single IP for subnet %s despite ip_count=1: %s. Blocking subnet instead.",
                            threat['id'],
                            e
                        )
                        target_type = "Subnet"
                        target_to_block_obj = threat['id']

                # Skip duplicates for already blocked IPs
                if single_ip_obj_for_check and single_ip_obj_for_check in blocked_ips_individual:
                    logger.info(
                        "Skipping block for %s %s: already blocked in this execution.",
                        target_type,
                        target_to_block_obj
                    )
                    continue

                # --- Strike Logic for Individual Threats ---
                target_id_str = str(target_to_block_obj) # String for strike history key
                previous_strikes = len(strike_history.get(target_id_str, []))
                strike_count = previous_strikes + 1
                escalated = strike_count >= args.block_escalation_strikes # Use new arg
                block_duration = 1440 if escalated else args.block_duration
                duration_info = f"(Escalated: {strike_count} strikes)" if escalated else f"({strike_count} strikes)"
                # --- End Strike Logic ---

                block_reason = threat.get('block_reason', 'Strategy threshold met') # Get reason

                logger.info(f"Processing block for {target_type}: {target_to_block_obj}. Duration: {block_duration}m {duration_info}")
                logger.debug("Block reason detail: %s", block_reason)
                success = ufw_manager_instance.block_target(
                    subnet_or_ip_obj=target_to_block_obj,
                    block_duration_minutes=block_duration # Use general duration for strategy blocks
                )
                if success:
                    blocked_targets_count += 1
                    if isinstance(target_to_block_obj, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                        blocked_ips_individual.add(target_to_block_obj)
                    elif isinstance(target_to_block_obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                        blocked_subnets_individual.add(target_to_block_obj)
                    action = "Blocked" if not args.dry_run else "Dry Run - Blocked"
                    compact_line = compact_block_line(
                        action=action,
                        target_type=target_type,
                        target=target_to_block_obj,
                        duration_minutes=block_duration,
                        strike_count=strike_count,
                        req=threat.get('total_requests'),
                        ips=threat.get('ip_count'),
                        rpm=threat.get('subnet_req_per_min_window'),
                        span=threat.get('subnet_time_span')
                    )
                    if args.silent:
                        print(compact_line)
                    else:
                        print(f" -> {compact_line}")

                    # --- Record Strike (only if not dry run) ---
                    if not args.dry_run:
                        now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                        if target_id_str not in strike_history:
                            strike_history[target_id_str] = []
                        strike_history[target_id_str].append(now_iso)
                    # --- End Record Strike ---

                else:
                    # Only print failure if not silent
                    if not args.silent:
                        action = "Failed to block" if not args.dry_run else "Dry Run - Failed"
                        print(f" -> {action} {target_type}: {target_to_block_obj}.")

        # 3. Per-IP persistence layer (complements /24 and /16 logic)
        if analysis_duration_seconds <= 0:
            logger.warning("IP persistence layer skipped: analysis duration is 0 seconds.")
        else:
            min_ip_sustained_seconds = analysis_duration_seconds * (effective_ip_sustained_percent / 100.0)
            ip_pressure_entries = build_ip_pressure_metrics(analyzer.ip_metrics, analysis_duration_seconds)
            logger.info(
                "Evaluating %d IPs in persistence layer: req >= %d, rpm >= %.2f, timespan >= %.0fs (%.1f%%).",
                len(ip_pressure_entries),
                args.ip_min_requests,
                effective_ip_rpm_threshold,
                min_ip_sustained_seconds,
                effective_ip_sustained_percent
            )

            for ip_entry in ip_pressure_entries:
                ip_obj = ip_entry['ip_obj']
                subnet_obj = ip_entry['subnet_obj']
                total_requests = ip_entry['total_requests']
                req_per_min_window = ip_entry['req_per_min_window']
                time_span_seconds = ip_entry['time_span_seconds']
                ip_layer_checked += 1

                # Redundant if parent subnet is already blocked in this execution.
                if subnet_obj in blocked_subnets_via_supernet or subnet_obj in blocked_subnets_individual:
                    continue
                if ip_obj in blocked_ips_individual:
                    continue
                if total_requests < args.ip_min_requests:
                    continue
                if req_per_min_window < effective_ip_rpm_threshold:
                    continue
                if time_span_seconds < min_ip_sustained_seconds:
                    continue

                target_to_block_obj = ip_obj
                target_type = "Single IP (Persistence Layer)"
                target_id_str = str(target_to_block_obj)
                previous_strikes = len(strike_history.get(target_id_str, []))
                strike_count = previous_strikes + 1
                escalated = strike_count >= args.block_escalation_strikes
                block_duration = 1440 if escalated else args.block_duration
                duration_info = f"(Escalated: {strike_count} strikes)" if escalated else f"({strike_count} strikes)"

                reason = (
                    f"ip-layer: req={total_requests}, rpm={req_per_min_window:.2f}, "
                    f"timespan={time_span_seconds:.0f}s over {analysis_duration_seconds:.0f}s window"
                )
                logger.info(
                    "Processing block for %s: %s. Duration: %dm %s",
                    target_type, target_to_block_obj, block_duration, duration_info
                )
                logger.debug("Block reason detail: %s", reason)
                success = ufw_manager_instance.block_target(
                    subnet_or_ip_obj=target_to_block_obj,
                    block_duration_minutes=block_duration
                )
                if not success:
                    if not args.silent:
                        action = "Failed to block" if not args.dry_run else "Dry Run - Failed"
                        print(f" -> {action} {target_type}: {target_to_block_obj}.")
                    continue

                ip_layer_blocked += 1
                blocked_targets_count += 1
                blocked_ips_individual.add(target_to_block_obj)
                action = "Blocked" if not args.dry_run else "Dry Run - Blocked"
                compact_line = compact_block_line(
                    action=action,
                    target_type=target_type,
                    target=target_to_block_obj,
                    duration_minutes=block_duration,
                    strike_count=strike_count,
                    req=total_requests,
                    ips=1,
                    rpm=req_per_min_window,
                    span=time_span_seconds,
                    mode_tag="ip-layer"
                )
                if args.silent:
                    print(compact_line)
                else:
                    print(f" -> {compact_line}")

                if not args.dry_run:
                    now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                    if target_id_str not in strike_history:
                        strike_history[target_id_str] = []
                    strike_history[target_id_str].append(now_iso)

        # --- Save Strike History (only if not dry run) ---
        if not args.dry_run:
            save_strike_history(args.strike_file, strike_history)
        else:
            logger.info("Dry run mode: Strike history not saved.")
        # --- End Save Strike History ---

        if not args.silent:
            print(f"Block processing complete. {blocked_targets_count} targets {'would be' if args.dry_run else 'were'} processed for blocking.")
            action_word = "would be blocked" if args.dry_run else "were blocked"
            print(
                f"Distributed /16 mode: checked {distributed_supernets_checked} supernets, "
                f"{distributed_supernets_blocked} {action_word}."
            )
            print(
                f"IP persistence mode: checked {ip_layer_checked} IPs, "
                f"{ip_layer_blocked} {action_word}."
            )
            print("-" * 30)
    else:
        logger.info("Blocking is disabled (--block not specified).")

    # --- Export Results ---
    if args.output:
        logger.info(f"Exporting results to {args.output} in {args.format} format...")
        export_success = analyzer.export_results(
            format_type=args.format,
            output_file=args.output,
            config=args,
            threats=threats
        )
        if export_success:
            logger.info(f"Successfully exported results to {args.output}")
        else:
            logger.error(f"Failed to export results to {args.output}")

    # --- Reporting Logic ---
    # Suppress reporting if silent mode is active
    if not args.silent:
        # Show threats that should be blocked (exceeding thresholds), limited by --top for display
        blockable_threats_for_display = [t for t in threats if t.get('should_block')]
        display_count = min(args.top, len(blockable_threats_for_display)) if args.top else len(blockable_threats_for_display)
        threats_to_display = blockable_threats_for_display[:display_count]
        
        print(f"\n=== THREATS EXCEEDING THRESHOLDS (Sorted by Strategy Score: '{strategy_name}') ===")
        print(f"Total threats exceeding thresholds: {len(blockable_threats_for_display)}")
        print(f"Displaying: {display_count} (use --top to limit display)")
        if args.block:
            action = "Blocked" if not args.dry_run else "[DRY RUN] Marked for blocking"
            print(f"--- {action} based on strategy '{strategy_name}' criteria applied to ALL {len(blockable_threats_for_display)} threats exceeding thresholds ---")
            print(f"--- NOTE: /16 supernets may have been blocked by distributed-pressure mode ---")

        for i, threat in enumerate(threats_to_display, 1):
            target_id_obj = threat['id'] # ipaddress object
            target_id_str = str(target_id_obj)
            strat_score_str = f"Score: {threat.get('strategy_score', 0):.2f}"

            # Construct detailed metrics summary string (using .get() on the threat dict) - ADDED Req/Hour
            total_req_val = threat.get('total_requests', 0)
            if total_req_val is None or (isinstance(total_req_val, float) and total_req_val != total_req_val): total_req_val = 0
            total_req_val = int(total_req_val)

            metrics_summary = (
                f"{total_req_val:d} reqs, "
                f"{threat.get('ip_count', 0):d} IPs, "
                f"Req/Min(Win): {threat.get('subnet_req_per_min_window', 0):.1f}, "
                f"TimeSpan: {threat.get('subnet_time_span', 0):.0f}s"
            )

            block_info = ""
            # Determine block status for reporting (using ipaddress object for check)
            is_blockable = threat.get('should_block', False)
            covered_by_supernet = target_id_obj in blocked_subnets_via_supernet # Check using object

            if args.block:
                if covered_by_supernet:
                    block_info = f" [COVERED BY /16 BLOCK]"
                elif is_blockable:
                    # Block status is already printed during the blocking phase, maybe add reason here?
                    block_reason_str = f" ({threat.get('block_reason', 'No reason')})" if threat.get('block_reason') else ""
                    # Indicate it was processed for blocking
                    block_info = f" [PROCESSED FOR BLOCKING]{block_reason_str}"


            print(f"\n#{i} Subnet: {target_id_str} - {strat_score_str}{block_info}")
            print(f"  Metrics: {metrics_summary}")

    # --- Final Summary ---
    # Print simplified summary in silent mode
    if not args.silent:
        print(f"\nAnalysis completed using strategy '{strategy_name}'.")
    # Always print the blocked count summary
    blockable_count = len([t for t in threats if t.get('should_block')])
    print(f"{blocked_targets_count} unique targets (subnets/IPs or /16 supernets) {'blocked' if not args.dry_run else 'marked for blocking'} in this execution.")
    if not args.silent:
        # Use len(threats) which is the original list count
        print(f"From a total of {len(threats)} analyzed subnets, {blockable_count} exceeded thresholds.")
        if args.block:
            print(f"Use '--clean-rules' periodically to remove expired rules.")

    # --- Report Overall Maximums ---
    # Suppress if silent
    if not args.silent:
        print(f"\n=== OVERALL MAXIMUMS OBSERVED ===")
        if not max_metrics_data_for_reporting or all(data['value'] == -1 for data in max_metrics_data_for_reporting.values()): # MODIFIED to use new dict name
            print("  No threat data available or maximums could not be determined.")
        else:
            for metric_key, data in max_metrics_data_for_reporting.items():
                metric_name = metric_names_map.get(metric_key, metric_key)
                value = data['value']
                subnets = data['subnets'] # List of subnet ID strings
                value_str = "N/A"

                if value != -1 and value is not None and not (isinstance(value, float) and value != value):
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
        if not threats_dict:
            print("  No data available to report maximum-achieving subnets.")
        else:
            # Collect unique subnet IDs (strings) that achieved any maximum
            max_achieving_subnet_ids = set()
            for metric_key, data in max_metrics_data_for_reporting.items():
                if data['value'] != -1 and data['value'] is not None and not (isinstance(data['value'], float) and data['value'] != data['value']):
                    max_achieving_subnet_ids.update(data['subnets'])

            if not max_achieving_subnet_ids:
                print("  No subnets achieved any maximum values.")
            else:
                logger.info(f"Reporting details for {len(max_achieving_subnet_ids)} subnets that achieved at least one maximum.")
                # Filter the threats to get only the ones for these subnets
                max_subnets = [threats_dict[sid] for sid in max_achieving_subnet_ids if sid in threats_dict]

                # Sort by subnet ID string for consistent reporting order
                max_subnets.sort(key=lambda x: str(x['id']))

                for threat in max_subnets:
                    subnet_id_str = str(threat['id'])
                    # Find which maximums this subnet achieved
                    achieved_max_metrics = []
                    for metric_key, data in max_metrics_data_for_reporting.items():
                        if subnet_id_str in data['subnets']:
                            achieved_max_metrics.append(metric_names_map.get(metric_key, metric_key))
                    achieved_max_str = f" [Achieved Max: {', '.join(achieved_max_metrics)}]" if achieved_max_metrics else ""

                    # Reuse the metrics summary string generation from the threat dict - ADDED Req/Hour
                    total_req_val = threat.get('total_requests', 0)
                    if total_req_val is None or (isinstance(total_req_val, float) and total_req_val != total_req_val): total_req_val = 0
                    total_req_val = int(total_req_val)

                    metrics_summary = (
                        f"{total_req_val:d} reqs, "
                        f"{threat.get('ip_count', 0):d} IPs, "
                        f"Req/Min(Win): {threat.get('subnet_req_per_min_window', 0):.1f}, "
                        f"TimeSpan: {threat.get('subnet_time_span', 0):.0f}s"
                    )

                    print(f"\nSubnet: {subnet_id_str}{achieved_max_str}")
                    print(f"  Metrics: {metrics_summary}")

    # --- End Report Details for Subnets Achieving Maximums ---

    # --- Report Parameters Used (compact single line) ---
    params_parts = [
        f"{utc_now_str()}",
        "PARAMS",
        f"strategy={strategy_name}",
        f"tw={args.time_window if args.time_window else 'start-date'}",
        f"dur_s={analysis_duration_seconds:.0f}" if analysis_duration_seconds > 0 else "dur_s=na",
        f"rpm_base={args.min_rpm_threshold:.2f}",
        f"sust_base={args.min_sustained_percent:.2f}%",
        f"cpu_thr={args.max_cpu_load_threshold:.1f}%",
        f"swarm_ips={args.ip_swarm_threshold}",
        f"swarm_rpmf={args.ip_swarm_rpm_factor:.2f}",
        f"swarm_bonus={args.ip_swarm_bonus_max:.2f}",
        f"ip_rpm_base={args.ip_min_rpm_threshold:.2f}",
        f"ip_sust_base={args.ip_min_sustained_percent:.2f}%",
        f"ip_min_req={args.ip_min_requests}",
        f"rpm_eff={effective_rpm_threshold:.2f}",
        f"sust_eff={effective_sustained_percent:.2f}%",
        f"ip_rpm_eff={effective_ip_rpm_threshold:.2f}",
        f"ip_sust_eff={effective_ip_sustained_percent:.2f}%",
        f"block={'yes' if args.block else 'no'}",
        f"dry_run={'yes' if args.dry_run else 'no'}",
        f"log={args.log_level}"
    ]
    if args.block:
        params_parts.extend([
            f"block_dur_m={args.block_duration}",
            f"esc_strikes={args.block_escalation_strikes}",
            f"super16_rpm={args.supernet_min_rpm_total:.2f}",
            f"super16_ips={args.supernet_min_ip_count}",
            f"super16_req={args.supernet_min_requests}"
        ])
    print(" ".join(params_parts))
    # --- End Report Parameters Used ---


if __name__ == '__main__':
    main()
