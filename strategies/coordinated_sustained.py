"""
Blocking Strategy: Coordinated Sustained Activity.

Blocks if a subnet shows signs of coordination (minimum IP count),
significant volume, a minimum average total RPM, and sustained activity
over a minimum duration within the analysis window.
"""
import logging
from .base_strategy import BaseStrategy

logger = logging.getLogger('botstats.strategy.coordinated_sustained')

class Strategy(BaseStrategy):
    """Implements the Coordinated Sustained Activity strategy."""

    def get_required_config_keys(self):
        # Requires keys for coordination, subnet RPM, and sustained time
        return super().get_required_config_keys() + [
            'block_ip_count_threshold',
            'block_subnet_avg_rpm_threshold',
            'block_min_timespan_seconds'
        ]

    def calculate_threat_score_and_block(self, threat_data, config):
        """Calculates score and block decision based on multiple factors."""
        total_requests = threat_data.get('total_requests', 0)
        ip_count = threat_data.get('ip_count', 0)
        # Use the average RPM for the entire subnet
        subnet_avg_rpm = threat_data.get('subnet_total_avg_rpm', 0)
        # Use the time span of activity for the subnet
        time_span_seconds = threat_data.get('subnet_time_span', 0)

        # Score for sorting: Weighted sum reflecting priorities
        # Priority: 1. ip_count, 2. total_requests, 3. subnet_avg_rpm, 4. time_span_seconds
        score = (
            (ip_count * 100) +                 # High weight for coordination
            (total_requests / 10.0) +          # Moderate weight for volume
            (subnet_avg_rpm * 5) +             # Lower weight for average subnet rate
            (time_span_seconds / 60.0)         # Lowest weight for duration (scaled)
        )

        should_block = False
        reason_parts = []

        # Check blocking criteria
        min_req = getattr(config, 'block_threshold', 100)
        min_ips = getattr(config, 'block_ip_count_threshold', 10) # Default from args
        min_subnet_avg_rpm = getattr(config, 'block_subnet_avg_rpm_threshold', 60.0) # New arg
        min_timespan = getattr(config, 'block_min_timespan_seconds', 1800) # New arg (30 mins default)

        # Check base volume first
        if total_requests < min_req:
            logger.debug(f"Threat {threat_data.get('id', 'N/A')} below request threshold ({total_requests} < {min_req})")
            return score, False, None

        # Check all other criteria
        meets_ip_count = ip_count >= min_ips
        meets_subnet_rpm = subnet_avg_rpm >= min_subnet_avg_rpm
        meets_timespan = time_span_seconds >= min_timespan

        if meets_ip_count:
            reason_parts.append(f"IPs>={min_ips}({ip_count})")
        if meets_subnet_rpm:
            reason_parts.append(f"SubnetAvgRPM>={min_subnet_avg_rpm:.1f}({subnet_avg_rpm:.1f})")
        if meets_timespan:
            reason_parts.append(f"TimeSpan>={min_timespan}s({time_span_seconds:.0f}s)")

        # Block only if ALL criteria (Coordination, Subnet RPM, Time Span) are met
        if meets_ip_count and meets_subnet_rpm and meets_timespan:
            should_block = True
            reason = f"meets req>={min_req}, " + ", ".join(reason_parts)
            logger.debug(f"Threat {threat_data.get('id', 'N/A')} qualifies: {reason}")
        else:
            # Log why it didn't qualify even if it met the request threshold
            logger.debug(f"Threat {threat_data.get('id', 'N/A')} meets req>={min_req} but not all criteria: "
                         f"IPs ({ip_count}<{min_ips})?={not meets_ip_count}, "
                         f"SubnetAvgRPM ({subnet_avg_rpm:.1f}<{min_subnet_avg_rpm:.1f})?={not meets_subnet_rpm}, "
                         f"TimeSpan ({time_span_seconds:.0f}<{min_timespan}s)?={not meets_timespan}")
            reason = None # Ensure reason is None if not blocking

        return score, should_block, reason
