"""
Blocking Strategy: **Combined** (Logic v8 - Configurable TimeSpan)

This strategy evaluates three conditions:
1. TimeSpan >= X% (using --block-min-timespan-percent, default 50%)
2. Total Requests >= effective_min_requests (calculated externally based on --block-relative-threshold-percent)
3. Req/Min(Win) > Y (using --block-total-max-rpm-threshold)

The score (0.0-3.0) reflects the number of conditions met.
Blocking occurs if the score is >= 2.0.
"""

import logging
import pandas as pd # Import pandas for isna check

logger = logging.getLogger(__name__)

# --- REMOVED Hardcoded value for TimeSpan threshold ---
# DEFAULT_MIN_TIMESPAN_PERCENT = 50.0
# --- Threshold for blocking based on score (conditions met) ---
BLOCKING_SCORE_THRESHOLD = 2.0

class Strategy:
    """
    Combined strategy (Updated Logic 8 - Configurable TimeSpan):
    - Score reflects how many blocking conditions are met (0-3):
        1. TimeSpan >= block_min_timespan_percent (default 50%)
        2. TotalReq >= effective_min_requests (calculated externally)
        3. Req/Min(Win) > block_total_max_rpm_threshold
    - Block decision requires score >= BLOCKING_SCORE_THRESHOLD (e.g., >= 2.0).
    - --block-relative-threshold-percent is used *externally* to calculate effective_min_requests.
    """

    def get_required_config_keys(self):
        """Returns a list of config keys required by this strategy."""
        # effective_min_requests (derived from block_relative_threshold_percent) is passed in.
        # block_total_max_rpm_threshold is used for Condition 3.
        # block_min_timespan_percent is used for Condition 1.
        return [
            'block_total_max_rpm_threshold', # Used for Req/Min(Win) threshold (Condition 3)
            'block_min_timespan_percent'     # Used for TimeSpan threshold (Condition 1)
        ]

    def calculate_threat_score_and_block(self,
                                         threat_data,
                                         config,
                                         effective_min_requests, # Now used directly for Condition 2
                                         analysis_duration_seconds,
                                         total_overall_requests, # Received but not used directly in logic
                                         max_total_requests, # Keep receiving, might be useful elsewhere
                                         max_subnet_time_span, # Keep receiving
                                         max_ip_count=None): # ADDED max_ip_count
        """
        Calculates score (0-3) based on meeting conditions:
        1. TimeSpan >= Configured %
        2. TotalReq >= effective_min_requests
        3. Req/Min(Win) > Absolute Threshold
        Decides blocking if score >= BLOCKING_SCORE_THRESHOLD (e.g., 2.0).
        """
        score = 0.0 # Use float for score
        should_block = False
        reason = "Conditions not met"
        conditions_met_count = 0
        block_decision_reasons = [] # Store reasons for each condition check

        # --- Condition 1: Check Mandatory TimeSpan ---
        timespan_condition_met = False
        current_timespan = threat_data.get('subnet_time_span', 0)
        # Get threshold from config
        min_timespan_percent = config.block_min_timespan_percent

        if analysis_duration_seconds and analysis_duration_seconds > 0: # Check if valid duration
            min_timespan_threshold_seconds = analysis_duration_seconds * (min_timespan_percent / 100.0)
            if current_timespan >= min_timespan_threshold_seconds:
                timespan_condition_met = True
                conditions_met_count += 1
                block_decision_reasons.append(f"TimeSpan >= {min_timespan_percent:.1f}% ({current_timespan:.0f}s)")
            else:
                 block_decision_reasons.append(f"TimeSpan < {min_timespan_percent:.1f}% ({current_timespan:.0f}s)")
        else:
             block_decision_reasons.append(f"TimeSpan % condition skipped (duration={analysis_duration_seconds})") # Log the duration value

        # --- Condition 2: Check Mandatory Total Requests vs effective_min_requests ---
        total_req_ok = False
        # Use the externally calculated effective_min_requests
        min_total_req_threshold = effective_min_requests # Use directly
        current_total_req_raw = threat_data.get('total_requests', 0)
        current_total_req = 0
        if current_total_req_raw is not None and not pd.isna(current_total_req_raw):
             current_total_req = int(current_total_req_raw)

        # min_total_req_threshold is already guaranteed >= 1 from external calculation
        if current_total_req >= min_total_req_threshold:
            total_req_ok = True
            conditions_met_count += 1
            # Update reason to reflect comparison with effective_min_requests
            block_decision_reasons.append(f"TotalReq >= effective_min ({current_total_req} >= {min_total_req_threshold})")
        else:
            # Update reason
            block_decision_reasons.append(f"TotalReq < effective_min ({current_total_req} < {min_total_req_threshold})")


        # --- Condition 3: Check Mandatory Req/Min(Win) ---
        req_min_win_ok = False
        # Use block_total_max_rpm_threshold for this condition's threshold
        min_req_win_threshold = config.block_total_max_rpm_threshold
        current_req_min_win = threat_data.get('subnet_req_per_min_window', 0.0)
        if current_req_min_win > min_req_win_threshold:
             req_min_win_ok = True
             conditions_met_count += 1
             block_decision_reasons.append(f"Req/Min(Win) > {min_req_win_threshold:.1f}")
        else:
             block_decision_reasons.append(f"Req/Min(Win) <= {min_req_win_threshold:.1f}")

        # --- Final Block Decision and Score Calculation ---
        # Score is the count of conditions met
        score = float(conditions_met_count)

        # Block if score reaches the threshold (e.g., 2.0 or more conditions met)
        if score >= BLOCKING_SCORE_THRESHOLD:
            should_block = True
            # Construct reason showing which conditions were met
            met_reasons = [r for r in block_decision_reasons if ">=" in r or ">" in r] # Adjusted check
            reason = f"Block: Score {score:.1f} >= {BLOCKING_SCORE_THRESHOLD:.1f}. Met ({', '.join(met_reasons)})"
        else:
            should_block = False
            # Construct reason showing why the score threshold wasn't met
            failed_reasons = [r for r in block_decision_reasons if "<" in r or "<=" in r or "skipped" in r] # Adjusted check
            met_reasons = [r for r in block_decision_reasons if ">=" in r or ">" in r] # Adjusted check
            reason = f"No Block: Score {score:.1f} < {BLOCKING_SCORE_THRESHOLD:.1f}."
            if met_reasons:
                 reason += f" Met ({', '.join(met_reasons)})."
            if failed_reasons:
                 reason += f" Failed ({', '.join(failed_reasons)})."

        # Return the score (0.0-3.0) and the block decision/reason
        return score, should_block, reason
