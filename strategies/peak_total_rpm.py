"""
Blocking Strategy: Peak Total Subnet RPM.

Blocks if total requests exceed a threshold AND the maximum RPM reached by the entire subnet
(considering all requests in any single minute) exceeds another threshold.
"""
import logging
from .base_strategy import BaseStrategy

# Update logger name
logger = logging.getLogger('botstats.strategy.peak_total_rpm')

class Strategy(BaseStrategy):
    """Implements the Peak Total Subnet RPM strategy."""

    def get_required_config_keys(self):
        # Define a new threshold key specific to this strategy
        # block_threshold is handled by effective_min_requests
        return ['block_duration', 'block_total_max_rpm_threshold']

    def calculate_threat_score_and_block(self,
                                         threat_data,
                                         config,
                                         effective_min_requests,
                                         analysis_duration_seconds=None,
                                         total_overall_requests=None, # ADDED for signature consistency
                                         max_total_requests=None,
                                         max_subnet_time_span=None,
                                         max_subnet_req_per_min_window=None, # ADDED for signature consistency
                                         max_ip_count=None): # ADDED max_ip_count
        """Calculates score and block decision based on subnet total maximum RPM."""
        total_requests = threat_data.get('total_requests', 0)
        # Use the metric for subnet total maximum RPM
        max_total_rpm = threat_data.get('subnet_total_max_rpm', 0)

        # Score for sorting: Primarily based on the subnet's peak total RPM.
        score = (max_total_rpm * 5) + (total_requests / 100.0) # Example weighting, emphasize peak

        should_block = False
        reason = None

        # Check blocking criteria
        min_req = effective_min_requests # Use the passed effective threshold
        # Use the new threshold defined for total maximum RPM
        min_total_max_rpm = getattr(config, 'block_total_max_rpm_threshold', 300) # Default higher, like individual peak

        if total_requests >= min_req and max_total_rpm >= min_total_max_rpm:
            should_block = True
            reason = (f"meets request threshold ({total_requests}>={min_req}) "
                      f"and subnet total maximum RPM threshold ({max_total_rpm:.0f}>={min_total_max_rpm})") # Use .0f for integer RPM
            logger.debug(f"Threat {threat_data.get('id', 'N/A')} qualifies: {reason}")
        elif total_requests >= min_req:
             logger.debug(f"Threat {threat_data.get('id', 'N/A')} meets request threshold ({total_requests}>={min_req}) but not subnet total maximum RPM "
                          f"({max_total_rpm:.0f} < {min_total_max_rpm})")
        else: # Log if below request threshold
             logger.debug(f"Threat {threat_data.get('id', 'N/A')} below request threshold ({total_requests} < {min_req})")

        return score, should_block, reason
