"""
Blocking Strategy: **Combined** (Logic v6)

This strategy evaluates three conditions:
1. TimeSpan >= 75% (fixed)
2. Total Requests > X% of SUM of ALL Requests in Window (using --block-relative-threshold-percent)
3. Req/Min(Win) > Y (using --block-total-max-rpm-threshold)

The score (0.0-3.0) reflects the number of conditions met.
Blocking occurs if the score is >= 2.0.
"""

import logging
import pandas as pd # Import pandas for isna check

logger = logging.getLogger(__name__)

# --- Hardcoded value for TimeSpan threshold ---
DEFAULT_MIN_TIMESPAN_PERCENT = 75.0
# --- New: Threshold for blocking based on score (conditions met) ---
BLOCKING_SCORE_THRESHOLD = 2.0

class Strategy:
    """
    Combined strategy (Updated Logic 6 - Condition 2 uses % of SUM):
    - Score reflects how many blocking conditions are met (0-3):
        1. Fixed TimeSpan >= 75%
        2. TotalReq > block_relative_threshold_percent of SumTotalReq (overall sum)
        3. Req/Min(Win) > block_total_max_rpm_threshold
    - Block decision requires score >= BLOCKING_SCORE_THRESHOLD (e.g., >= 2.0).
    - Ignores effective_min_requests for its core logic.
    """

    def get_required_config_keys(self):
        """Returns a list of config keys required by this strategy."""
        # block_relative_threshold_percent is used for Condition 2 calculation
        return [
            'block_total_max_rpm_threshold', # Used for Req/Min(Win) threshold (Condition 3)
            'block_relative_threshold_percent' # Used for Total Requests threshold % (Condition 2)
        ]

    def calculate_threat_score_and_block(self,
                                         threat_data,
                                         config,
                                         effective_min_requests, # Received but ignored
                                         analysis_duration_seconds,
                                         total_overall_requests, # Use this for Condition 2
                                         max_total_requests, # Keep receiving, might be useful elsewhere
                                         max_subnet_time_span, # Keep receiving
                                         max_subnet_req_per_min_window):
        """
        Calculates score (0-3) based on meeting conditions:
        1. TimeSpan >= 75%
        2. TotalReq > Relative% of SUM of ALL Requests in Window
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
        if analysis_duration_seconds > 0:
            min_timespan_threshold_seconds = analysis_duration_seconds * (DEFAULT_MIN_TIMESPAN_PERCENT / 100.0)
            if current_timespan >= min_timespan_threshold_seconds:
                timespan_condition_met = True
                conditions_met_count += 1
                block_decision_reasons.append(f"TimeSpan >= {DEFAULT_MIN_TIMESPAN_PERCENT:.1f}% ({current_timespan:.0f}s)")
            else:
                 block_decision_reasons.append(f"TimeSpan < {DEFAULT_MIN_TIMESPAN_PERCENT:.1f}% ({current_timespan:.0f}s)")
        else:
             block_decision_reasons.append("TimeSpan % condition skipped (duration=0)")

        # --- Condition 2: Check Mandatory Total Requests % vs SUM Overall ---
        total_req_ok = False
        # Use the total_overall_requests from the entire analysis window
        if total_overall_requests > 0:
             # Calculate threshold based on the SUM of all requests
             min_total_req_threshold = total_overall_requests * (config.block_relative_threshold_percent / 100.0)
             current_total_req_raw = threat_data.get('total_requests', 0)
             current_total_req = 0
             if current_total_req_raw is not None and not pd.isna(current_total_req_raw):
                  current_total_req = int(current_total_req_raw)

             min_total_req_threshold = max(1, min_total_req_threshold) # Ensure threshold is at least 1
             if current_total_req > min_total_req_threshold:
                 total_req_ok = True
                 conditions_met_count += 1
                 # Update reason to reflect comparison with % of SUM
                 block_decision_reasons.append(f"TotalReq > {config.block_relative_threshold_percent:.1f}% sum ({current_total_req} > {min_total_req_threshold:.0f})")
             else:
                 # Update reason
                 block_decision_reasons.append(f"TotalReq <= {config.block_relative_threshold_percent:.1f}% sum ({current_total_req} <= {min_total_req_threshold:.0f})")
        else:
             # If total_overall_requests is 0, this condition cannot be met
             block_decision_reasons.append("TotalReq % condition skipped (sum=0)")

        # --- Condition 3: Check Mandatory Req/Min(Win) ---
        req_min_win_ok = False
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
            met_reasons = [r for r in block_decision_reasons if ">" in r or ">=" in r]
            reason = f"Block: Score {score:.1f} >= {BLOCKING_SCORE_THRESHOLD:.1f}. Met ({', '.join(met_reasons)})"
        else:
            should_block = False
            # Construct reason showing why the score threshold wasn't met
            failed_reasons = [r for r in block_decision_reasons if "<" in r or "<=" in r or "skipped" in r]
            met_reasons = [r for r in block_decision_reasons if ">" in r or ">=" in r]
            reason = f"No Block: Score {score:.1f} < {BLOCKING_SCORE_THRESHOLD:.1f}."
            if met_reasons:
                 reason += f" Met ({', '.join(met_reasons)})."
            if failed_reasons:
                 reason += f" Failed ({', '.join(failed_reasons)})."

        # Return the score (0.0-3.0) and the block decision/reason
        return score, should_block, reason
