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
import importlib # For dynamic strategy loading
from collections import defaultdict # For grouping /16s
import time # Import time module
import json # Import json module
import psutil # Import psutil for system load average
# ADD pyarrow import for parquet export, handle potential ImportError
try:
    import pyarrow
    import pyarrow.parquet as pq
    import pyarrow.lib as pa_lib
except ImportError:
    pyarrow = None


# Import own modules
from parser import get_subnet, is_ip_in_whitelist, stream_log_entries
# Import UFWManager and COMMENT_PREFIX directly if needed
import ufw_handler
from threat_analyzer import ThreatAnalyzer

# Logging configuration
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# --- Helper Functions for Strike History ---

STRIKE_HISTORY_MAX_AGE_HOURS = 48

def load_strike_history(filepath):
    """Loads strike history from JSON, cleans old entries."""
    logger = logging.getLogger('botstats.strike_history') # Get logger instance
    history = {}
    if not filepath or not os.path.exists(filepath):
        logger.info(f"Strike history file not found or not specified ('{filepath}'). Starting fresh.")
        return history

    try:
        with open(filepath, 'r') as f:
            history = json.load(f)
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
    cutoff_time = now_utc - timedelta(hours=STRIKE_HISTORY_MAX_AGE_HOURS)
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
        logger.info(f"Removed {cleaned_count} strike entries older than {STRIKE_HISTORY_MAX_AGE_HOURS} hours.")
    logger.debug(f"Strike history loaded and cleaned. Kept {kept_count} recent strikes for {len(cleaned_history)} targets.")
    return cleaned_history

def save_strike_history(filepath, history):
    """Saves strike history to JSON safely."""
    logger = logging.getLogger('botstats.strike_history') # Get logger instance
    if not filepath:
        logger.warning("Strike history file path not specified. Cannot save history.")
        return False
    temp_filepath = filepath + ".tmp"
    try:
        with open(temp_filepath, 'w') as f:
            json.dump(history, f, indent=2) # Use indent for readability
        # Atomically replace the old file with the new one
        os.replace(temp_filepath, filepath)
        logger.info(f"Successfully saved strike history for {len(history)} targets to {filepath}.")
        return True
    except Exception as e:
        logger.error(f"Error saving strike history to {filepath}: {e}")
        # Clean up temp file if it exists
        if os.path.exists(temp_filepath):
            try:
                os.remove(temp_filepath)
            except OSError as rm_err:
                logger.error(f"Could not remove temporary strike file {temp_filepath}: {rm_err}")
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
        '--time-window', '-tw', required=False, default='hour',
        choices=['hour', '6hour', 'day', 'week'], # Add '6hour' choice
        help='Analyze logs from the last hour (default), 6 hours, day, or week (overrides --start-date).'
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
    parser.add_argument(
        '--dump-data', action='store_true',
        help='Dump the raw log data used for analysis to a Parquet file in the script directory (requires pyarrow).'
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
    strategy_name = 'unified'  # Use unified strategy
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

        # --- Dump data if requested ---
        if args.dump_data:
            if pyarrow is None:
                logger.warning("--dump-data specified, but 'pyarrow' library is not installed. Skipping dump. Please install it (`pip install pyarrow`).")
            else:
                try:
                    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
                    period_str = "full_log" # Default if no time filter
                    if args.time_window:
                        period_str = args.time_window
                    elif args.start_date:
                        period_str = "custom_start"

                    dump_filename = f"log_dump_{timestamp_str}_{period_str}.parquet"
                    dump_filepath = os.path.join(script_dir, dump_filename)

                    logger.info(f"Dumping log data to Parquet file: {dump_filepath}")
                    logger.info("Re-reading log file for dump (streaming mode active)...")
                    
                    # Re-stream for dumping to avoid holding data in memory during analysis
                    # We need to import stream_log_entries locally or ensure it's imported
                    from parser import stream_log_entries
                    
                    dump_stream = stream_log_entries(args.file, start_date_utc, analyzer.whitelist)
                    
                    # Collect data for parquet (this WILL use memory, but only if dump is requested)
                    # For very large files, even this might be risky, but it's an explicit user request.
                    # A better approach for huge files would be writing in batches, but pyarrow table creation usually needs arrays.
                    # We'll collect lists.
                    timestamps = []
                    ips = []
                    
                    count = 0
                    for entry in dump_stream:
                        timestamps.append(entry['timestamp'])
                        ips.append(entry['ip'])
                        count += 1
                    
                    if count > 0:
                        # Create PyArrow table
                        table = pa_lib.table({
                            'timestamp': timestamps,
                            'ip': ips
                        })
                        
                        # Write to parquet
                        pq.write_table(table, dump_filepath)
                        logger.info(f"Successfully dumped {count} entries to {dump_filepath}")
                    else:
                        logger.warning("No entries found to dump.")

                except Exception as dump_err:
                    logger.error(f"Failed to dump data to Parquet file: {dump_err}", exc_info=True)
        # --- End Dump data ---


    except Exception as e:
        logger.error(f"Error during analysis execution: {e}", exc_info=True)
        sys.exit(1)


    except Exception as e:
        logger.error(f"Error loading/parsing log file: {e}", exc_info=True)
        sys.exit(1)

    # --- Determine Effective Request Threshold ---
    # For unified strategy, force to 100
    effective_min_requests = 100
    logger.info(f"Using fixed effective_min_requests = {effective_min_requests} for unified strategy.")

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
            timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"{timestamp_str} INFO: {load_avg_message}")
        else:
            pass # logger.info already covers non-silent
    elif args.silent: # If psutil failed and in silent mode, print a message
        timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"{timestamp_str} WARNING: Could not retrieve system load average.")

    # --- End Get System Load Average and CPU Load Percentage ---

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
        strategy_name='unified',  # Use unified strategy
        effective_min_requests=effective_min_requests,
        shared_context_params=shared_context_params, # Pass the initial context
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
    threats_dict = analyzer.get_threats_df() # Returns dict indexed by string representation of subnet ID

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
    blocked_ips_high_rpm = set() # Keep track of IPs blocked due to high RPM
    strike_history = {} # Initialize strike history dict

    if args.block:
        if not args.silent:
            print("-" * 30)
        logger.info(f"Processing blocks (Dry Run: {args.dry_run})...")
        ufw_manager_instance = ufw_handler.UFWManager(args.dry_run)

        # --- Load Strike History ---
        strike_history = load_strike_history(args.strike_file)
        # --- End Load Strike History ---

        # High-rate IP blocking removed in simplified version

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
                target_id_str = str(target_to_block_obj) # String for strike history key
                target_type = "Supernet /16"
                # --- Strike Logic for Supernets ---
                strike_count = len(strike_history.get(target_id_str, []))
                escalated = strike_count >= args.block_escalation_strikes # Use new arg
                block_duration = 1440 if escalated else args.block_duration
                duration_info = f"(Escalated: {strike_count} strikes)" if escalated else f"({strike_count} strikes)"
                # --- End Strike Logic ---
                contained_ids_str = ", ".join([str(t['id']) for t in contained_blockable_threats])
                reason = f"contains >= 2 blockable /24 subnets ({contained_ids_str})"

                logger.info(f"Processing block for {target_type}: {target_to_block_obj}. Reason: {reason}. Duration: {block_duration}m {duration_info}")
                success = ufw_manager_instance.block_target(
                    subnet_or_ip_obj=target_to_block_obj,
                    block_duration_minutes=block_duration
                )
                if success:
                    blocked_targets_count += 1
                    action = "Blocked" if not args.dry_run else "Dry Run - Blocked"
                    timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    # ALWAYS PRINT block actions, format based on silent mode
                    if args.silent:
                         print(f"{timestamp_str} {action} {target_type}: {target_to_block_obj} for {block_duration}m {duration_info}. Reason: {reason}.")
                    else:
                         print(f" -> {action} {target_type}: {target_to_block_obj} for {block_duration} minutes {duration_info}. Reason: {reason}.")
                    # --- Record Strike (only if not dry run) ---
                    if not args.dry_run:
                        now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                        if target_id_str not in strike_history:
                            strike_history[target_id_str] = []
                        strike_history[target_id_str].append(now_iso)
                    # --- End Record Strike ---
                    for contained_threat in contained_blockable_threats:
                        blocked_subnets_via_supernet.add(contained_threat['id'])
                else:
                    # Only print failure if not silent
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
                if threat.get('ip_count') == 1 and threat.get('details'):
                    try:
                        # Details IP should be string already
                        single_ip_str = threat['details'][0]['ip']
                        target_to_block_obj = ipaddress.ip_address(single_ip_str) # Convert back to object for UFW
                        single_ip_obj_for_check = target_to_block_obj # Keep the object for high RPM check
                        target_type = "Single IP"
                        logger.info(f"Threat {threat['id']} has only 1 IP. Targeting IP {target_to_block_obj} instead of the whole subnet.")
                    except (IndexError, KeyError, ValueError, TypeError) as e:
                        logger.warning(f"Could not extract/convert single IP from details for subnet {threat['id']} despite ip_count=1: {e}. Blocking subnet instead.")
                        target_type = "Subnet"
                        target_to_block_obj = threat['id']

                # Skip if this specific IP was already blocked due to high RPM
                if single_ip_obj_for_check and single_ip_obj_for_check in blocked_ips_high_rpm:
                    logger.info(f"Skipping block for {target_type} {target_to_block_obj}: Already blocked due to high req/hour.")
                    continue

                # --- Strike Logic for Individual Threats ---
                target_id_str = str(target_to_block_obj) # String for strike history key
                strike_count = len(strike_history.get(target_id_str, []))
                escalated = strike_count >= args.block_escalation_strikes # Use new arg
                block_duration = 1440 if escalated else args.block_duration
                duration_info = f"(Escalated: {strike_count} strikes)" if escalated else f"({strike_count} strikes)"
                # --- End Strike Logic ---

                block_reason = threat.get('block_reason', 'Strategy threshold met') # Get reason

                logger.info(f"Processing block for {target_type}: {target_to_block_obj}. Reason: {block_reason}. Duration: {block_duration}m {duration_info}")
                success = ufw_manager_instance.block_target(
                    subnet_or_ip_obj=target_to_block_obj,
                    block_duration_minutes=block_duration # Use general duration for strategy blocks
                )
                if success:
                    blocked_targets_count += 1
                    action = "Blocked" if not args.dry_run else "Dry Run - Blocked"
                    timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    # --- Construct metrics summary string for block message ---
                    try:
                        # Helper functions for safe numeric retrieval and conversion
                        def _safe_get_float(val, default=0.0):
                            if val is None: return default
                            if isinstance(val, (int, float)): return float(val)
                            try: return float(val) # Attempt conversion if string or other
                            except (ValueError, TypeError): return default

                        def _safe_get_int(val, default=0):
                            if val is None: return default
                            if isinstance(val, (int, float)): return int(val) # Handles float to int conversion
                            try: return int(float(val)) # Attempt conversion to float first, then int
                            except (ValueError, TypeError): return default

                        total_requests_val = _safe_get_int(threat.get('total_requests'))
                        ip_count_val = _safe_get_int(threat.get('ip_count'))
                        strategy_score_val = _safe_get_float(threat.get('strategy_score'))
                        subnet_req_min_win_val = _safe_get_float(threat.get('subnet_req_per_min_window'))
                        subnet_time_span_val = _safe_get_float(threat.get('subnet_time_span'))

                        metrics_summary = (
                            f"Metrics: "
                            f"{total_requests_val:d} reqs, "
                            f"{ip_count_val:d} IPs, "
                            f"Score: {strategy_score_val:.1f}, "
                            f"Req/Min(Win): {subnet_req_min_win_val:.1f}, "
                            f"TimeSpan: {subnet_time_span_val:.0f}s"
                        )
                    except Exception as e:
                         logger.warning(f"Could not format metrics for block message of {target_to_block_obj}: {e}", exc_info=True)
                         metrics_summary = "Metrics: N/A"
                    # --- End metrics summary string ---

                    # ALWAYS PRINT block actions, format based on silent mode
                    if args.silent:
                        print(f"{timestamp_str} {action} {target_type}: {target_to_block_obj} for {block_duration}m {duration_info}. Reason: {block_reason}. {metrics_summary}")
                    else:
                        # Append the metrics_summary and duration_info to the print statement for non-silent
                        print(f" -> {action} {target_type}: {target_to_block_obj} for {block_duration} minutes {duration_info}. Reason: {block_reason}. {metrics_summary}")

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

        # --- Save Strike History (only if not dry run) ---
        if not args.dry_run:
            save_strike_history(args.strike_file, strike_history)
        else:
            logger.info("Dry run mode: Strike history not saved.")
        # --- End Save Strike History ---

        if not args.silent:
            print(f"Block processing complete. {blocked_targets_count} targets {'would be' if args.dry_run else 'were'} processed for blocking.")
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
            print(f"--- NOTE: /16 supernets containing >= 2 blockable /24s may have been blocked instead ---")

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

    # --- Report Parameters Used ---
    # Always print parameter summary (even in silent mode for transparency)
    print(f"\n=== PARAMETERS USED ===")
    print(f"  Analysis Strategy: {strategy_name}")
    print(f"  Time Window: {args.time_window}")
    if analysis_duration_seconds > 0:
        print(f"  Analysis Duration: {analysis_duration_seconds:.0f}s ({analysis_duration_seconds/60:.1f} min)")
    print(f"  Base RPM Threshold: {args.min_rpm_threshold:.1f} req/min")
    print(f"  Base Sustained Activity: {args.min_sustained_percent:.1f}%")
    print(f"  CPU Load Threshold: {args.max_cpu_load_threshold:.1f}%")
    if args.block:
        print(f"  Blocking Enabled: Yes")
        print(f"  Block Duration: {args.block_duration} min (default)")
        print(f"  Escalation Threshold: {args.block_escalation_strikes} strikes")
        print(f"  Escalated Duration: 1440 min (24 hours)")
        print(f"  Dry Run: {'Yes' if args.dry_run else 'No'}")
    else:
        print(f"  Blocking Enabled: No")
    print(f"  Log Level: {args.log_level}")
    # --- End Report Parameters Used ---


if __name__ == '__main__':
    main()

