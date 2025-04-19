"""
Blocking Strategy: Coordinated Sustained Activity.

Blocks if a subnet shows signs of coordination (minimum IP count),
significant volume, a minimum average total RPM (internal threshold),
and sustained activity relative to the analysis window duration.
"""
import logging
from .base_strategy import BaseStrategy

logger = logging.getLogger('botstats.strategy.coordinated_sustained')

# Internal threshold for average subnet RPM
INTERNAL_MIN_SUBNET_AVG_RPM = 60.0
# Percentage of analysis window the activity must span
TIME_SPAN_PERCENTAGE_THRESHOLD = 0.50 # 50%

class Strategy(BaseStrategy):
    """Implements the Coordinated Sustained Activity strategy with dynamic timespan."""

    def get_required_config_keys(self):
        # Only requires IP count threshold now
        return super().get_required_config_keys() + [
            'block_ip_count_threshold',
        ]

    def calculate_threat_score_and_block(self, threat_data, config, analysis_duration_seconds=None):
        """Calculates score and block decision based on multiple factors, including dynamic timespan."""
        total_requests = threat_data.get('total_requests', 0)
        ip_count = threat_data.get('ip_count', 0)
        subnet_avg_rpm = threat_data.get('subnet_total_avg_rpm', 0)
        time_span_seconds = threat_data.get('subnet_time_span', 0)

        # Score for sorting (remains the same)
        score = (
            (ip_count * 100) +
            (total_requests / 10.0) +
            (subnet_avg_rpm * 5) +
            (time_span_seconds / 60.0)
        )

        should_block = False
        reason_parts = []

        # --- Get thresholds ---
        min_req = getattr(config, 'block_threshold', 100)
        min_ips = getattr(config, 'block_ip_count_threshold', 5) # Default to 5 as per initial request

        # Use internal threshold for subnet RPM
        min_subnet_avg_rpm = INTERNAL_MIN_SUBNET_AVG_RPM

        # Calculate dynamic minimum timespan if analysis duration is available
        min_timespan = 0
        timespan_check_active = False
        if analysis_duration_seconds and analysis_duration_seconds > 0:
            min_timespan = analysis_duration_seconds * TIME_SPAN_PERCENTAGE_THRESHOLD
            timespan_check_active = True
            logger.debug(f"Threat {threat_data.get('id', 'N/A')}: Dynamic min_timespan = {min_timespan:.0f}s ({TIME_SPAN_PERCENTAGE_THRESHOLD*100}% of {analysis_duration_seconds}s)")
        else:
            logger.debug(f"Threat {threat_data.get('id', 'N/A')}: No analysis duration provided, skipping dynamic timespan check.")
        # --- End Get thresholds ---


        # Check base volume first
        if total_requests < min_req:
            logger.debug(f"Threat {threat_data.get('id', 'N/A')} below request threshold ({total_requests} < {min_req})")
            return score, False, None

        # Check other criteria
        meets_ip_count = ip_count >= min_ips
        meets_subnet_rpm = subnet_avg_rpm >= min_subnet_avg_rpm
        # Check timespan only if the check is active
        meets_timespan = (time_span_seconds >= min_timespan) if timespan_check_active else True

        # Build reason string based on met criteria
        if meets_ip_count:
            reason_parts.append(f"IPs>={min_ips}({ip_count})")
        if meets_subnet_rpm:
            reason_parts.append(f"SubnetAvgRPM>={min_subnet_avg_rpm:.1f}({subnet_avg_rpm:.1f})")
        if timespan_check_active: # Only add timespan reason if it was checked
            if meets_timespan:
                reason_parts.append(f"TimeSpan>={min_timespan:.0f}s({time_span_seconds:.0f}s)")
        else:
             reason_parts.append("TimeSpan(skipped)") # Indicate check was skipped


        # Block only if ALL applicable criteria are met
        # (Timespan is implicitly met if timespan_check_active is False)
        if meets_ip_count and meets_subnet_rpm and meets_timespan:
            should_block = True
            reason = f"meets req>={min_req}, " + ", ".join(reason_parts)
            logger.debug(f"Threat {threat_data.get('id', 'N/A')} qualifies: {reason}")
        else:
            # Log why it didn't qualify
            fail_reason = []
            if not meets_ip_count: fail_reason.append(f"IPs({ip_count}<{min_ips})")
            if not meets_subnet_rpm: fail_reason.append(f"SubnetAvgRPM({subnet_avg_rpm:.1f}<{min_subnet_avg_rpm:.1f})")
            if timespan_check_active and not meets_timespan: fail_reason.append(f"TimeSpan({time_span_seconds:.0f}<{min_timespan:.0f}s)")

            logger.debug(f"Threat {threat_data.get('id', 'N/A')} meets req>={min_req} but failed: {', '.join(fail_reason)}")
            reason = None # Ensure reason is None if not blocking

        return score, should_block, reason
