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
        return ['block_duration', 'block_total_max_rpm_threshold']

    def calculate_threat_score_and_block(self, threat_data, config, effective_min_requests, analysis_duration_seconds=None):
        """Calculates score and block decision based on multiple factors, including peak RPM and dynamic timespan."""
        total_requests = threat_data.get('total_requests', 0)
        # ip_count = threat_data.get('ip_count', 0) # No longer used for blocking logic
        subnet_time_span = threat_data.get('subnet_time_span', 0)
        subnet_req_per_min = threat_data.get('subnet_req_per_min', 0) # For scoring

        # --- Score Calculation (Weighted) ---
        # Prioritize subnet_req_per_min, then volume, then timespan.
        score = (subnet_req_per_min * 0.6) + (total_requests * 0.3) + (subnet_time_span * 0.1)
        # Adjust weights as needed

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
            if analysis_duration_seconds > 0:
                timespan_percentage = (subnet_time_span / analysis_duration_seconds) * 100
                if timespan_percentage >= TIME_SPAN_PERCENTAGE_THRESHOLD * 100:
                    meets_timespan_threshold = True
                    reason_parts.append(f"Timespan ({timespan_percentage:.1f}% >= {TIME_SPAN_PERCENTAGE_THRESHOLD * 100}%)")
                else:
                     logger.debug(f"Subnet {threat_data['id']} met volume but not timespan threshold ({timespan_percentage:.1f}% < {TIME_SPAN_PERCENTAGE_THRESHOLD * 100}%)")
            else:
                # If no analysis window, we cannot check the percentage, skip this check
                logger.debug(f"Subnet {threat_data['id']}: Skipping timespan percentage check as analysis_duration_seconds is 0.")
                # Consider timespan met if no window defined, to allow blocking based only on volume.
                meets_timespan_threshold = True # Allow blocking if volume is met when no window defined


            # 3. Determine block status based ONLY on Volume and Timespan
            if meets_timespan_threshold: # Volume is already met if we are here
                should_block = True
                # No need to check ip_count anymore
                # reason_parts.append("Sustained activity") # Simple reason

            # Final reason string
            if should_block:
                reason = " and ".join(reason_parts)

        # else: # Volume threshold not met
            # logger.debug(f"Subnet {threat_data['id']} did not meet volume threshold ({total_requests} < {effective_min_requests}). Score: {score:.2f}")


        return score, should_block, reason
