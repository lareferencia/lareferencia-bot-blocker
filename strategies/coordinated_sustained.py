"""
Blocking strategy for coordinated and sustained activity.
MODIFIED AGAIN:
- Blocks based only on volume and timespan percentage.
- Removes dependency on IP count threshold.
- Sorts primarily by Subnet Requests/Min (Overall).
"""
import logging
from .base_strategy import BaseStrategy

logger = logging.getLogger('botstats.strategy.coordinated_sustained')

# Percentage of analysis window the activity must span
TIME_SPAN_PERCENTAGE_THRESHOLD = 0.50 # 50%

class Strategy(BaseStrategy):
    """Implements the Coordinated Sustained Activity strategy using peak subnet RPM."""

    def get_required_config_keys(self):
        # Requires keys for coordination and peak total subnet RPM
        # block_threshold is handled by effective_min_requests
        # No specific thresholds needed beyond effective_min_requests for this strategy's blocking logic
        return ['block_duration'] # Only duration is strictly needed by the base logic

    def calculate_threat_score_and_block(self,
                                         threat_data,
                                         config,
                                         effective_min_requests,
                                         analysis_duration_seconds=None,
                                         total_overall_requests=None, # ADDED
                                         max_total_requests=None,
                                         max_subnet_time_span=None,
                                         max_subnet_req_per_min_window=None, # ADDED
                                         max_ip_count=None): # ADDED max_ip_count
        """Calculates score and block decision based on multiple factors, including peak RPM and dynamic timespan."""
        total_requests = threat_data.get('total_requests', 0)
        # ip_count = threat_data.get('ip_count', 0) # No longer used for blocking logic
        subnet_time_span = threat_data.get('subnet_time_span', 0)
        # subnet_req_per_min = threat_data.get('subnet_req_per_min', 0) # No longer used for scoring
        # Use subnet_req_per_min_window for scoring if desired, or stick to normalized requests/timespan
        subnet_req_per_min_window = threat_data.get('subnet_req_per_min_window', 0.0)

        # --- Score Calculation (Normalized and Weighted) ---
        # Normalize requests and timespan relative to the maximums observed in this run
        normalized_requests = (total_requests / max_total_requests) if max_total_requests and max_total_requests > 0 else 0
        normalized_timespan = (subnet_time_span / max_subnet_time_span) if max_subnet_time_span and max_subnet_time_span > 0 else 0
        # Optional: Normalize req/min window
        normalized_req_min_win = (subnet_req_per_min_window / max_subnet_req_per_min_window) if max_subnet_req_per_min_window and max_subnet_req_per_min_window > 0 else 0


        # Prioritize normalized total_requests, then normalized timespan.
        # Example: score = (normalized_requests * 0.5) + (normalized_timespan * 0.5)
        # Alternative: Use Req/Min(Win) for scoring
        score = (normalized_req_min_win * 0.6) + (normalized_timespan * 0.4) # Example using Req/Min(Win) and TimeSpan

        # --- Blocking Logic ---
        should_block = False
        reason = None
        reason_parts = []

        # 1. Check base volume threshold
        meets_volume_threshold = total_requests >= effective_min_requests
        if meets_volume_threshold:
            reason_parts.append(f"Volume ({total_requests} >= {effective_min_requests})")

            # 2. Check Timespan Percentage Threshold (if analysis window is defined)
            meets_timespan_threshold = False
            timespan_percentage = 0
            if analysis_duration_seconds and analysis_duration_seconds > 0: # Ensure analysis_duration_seconds is not None and > 0
                timespan_percentage = (subnet_time_span / analysis_duration_seconds) * 100
                if timespan_percentage >= TIME_SPAN_PERCENTAGE_THRESHOLD * 100:
                    meets_timespan_threshold = True
                    reason_parts.append(f"Timespan ({timespan_percentage:.1f}% >= {TIME_SPAN_PERCENTAGE_THRESHOLD * 100}%)")
                else:
                     logger.debug(f"Subnet {threat_data.get('id', 'N/A')} met volume but not timespan threshold ({timespan_percentage:.1f}% < {TIME_SPAN_PERCENTAGE_THRESHOLD * 100}%)")
            else:
                # If no analysis window, we cannot check the percentage, skip this check
                logger.debug(f"Subnet {threat_data.get('id', 'N/A')}: Skipping timespan percentage check as analysis_duration_seconds is not valid.")
                # Consider timespan met if no window defined? Or fail the check?
                # Let's require a valid window for this check to pass.
                meets_timespan_threshold = False # Fail check if no valid window duration
                reason_parts.append(f"Timespan check skipped (invalid duration: {analysis_duration_seconds})")


            # 3. Determine block status based ONLY on Volume and Timespan
            # Both conditions must be met
            if meets_volume_threshold and meets_timespan_threshold:
                should_block = True
                # reason_parts already contains the reasons

            # Final reason string
            if should_block:
                reason = " and ".join(reason_parts)
            elif meets_volume_threshold: # Log why it wasn't blocked if volume was met
                 reason = "No Block: " and ".join(reason_parts) # Show reasons checked so far
            # else: # Volume threshold not met - handled below


        else: # Volume threshold not met
            logger.debug(f"Subnet {threat_data.get('id', 'N/A')} did not meet volume threshold ({total_requests} < {effective_min_requests}). Score: {score:.2f}")
            reason = f"No Block: Volume ({total_requests} < {effective_min_requests})"


        return score, should_block, reason
