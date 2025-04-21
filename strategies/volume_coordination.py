"""
Blocking Strategy: Volume + Coordination (IP Count).

Blocks if total requests exceed a threshold AND the number of unique IPs
within the subnet exceeds another threshold.
"""
import logging
from .base_strategy import BaseStrategy

logger = logging.getLogger('botstats.strategy.volume_coordination')

class Strategy(BaseStrategy):
    """Implements the Volume + IP Count strategy."""

    def get_required_config_keys(self):
        # block_threshold is handled by effective_min_requests
        return ['block_duration', 'block_ip_count_threshold']

    def calculate_threat_score_and_block(self,
                                         threat_data,
                                         config,
                                         effective_min_requests,
                                         analysis_duration_seconds=None,
                                         total_overall_requests=None, # ADDED for signature consistency
                                         max_total_requests=None,
                                         max_subnet_time_span=None,
                                         max_subnet_req_per_min_window=None): # ADDED for signature consistency
        """Calculates score and block decision."""
        total_requests = threat_data.get('total_requests', 0)
        ip_count = threat_data.get('ip_count', 0)

        # Score for sorting: Primarily based on IP count, secondarily on requests.
        score = (ip_count * 10) + (total_requests / 100.0) # Example weighting

        should_block = False
        reason = None

        # Check blocking criteria
        min_req = effective_min_requests # Use the passed effective threshold
        min_ips = getattr(config, 'block_ip_count_threshold', 0) # Get from config

        if total_requests >= min_req and ip_count >= min_ips:
            should_block = True
            reason = (f"meets request threshold ({total_requests}>={min_req}) "
                      f"and IP count threshold ({ip_count}>={min_ips})")
            logger.debug(f"Threat {threat_data.get('id', 'N/A')} qualifies: {reason}")
        elif total_requests >= min_req:
             logger.debug(f"Threat {threat_data.get('id', 'N/A')} meets request threshold ({total_requests}>={min_req}) but not IP count "
                          f"({ip_count} < {min_ips})")
        else: # Log if below request threshold
             logger.debug(f"Threat {threat_data.get('id', 'N/A')} below request threshold ({total_requests} < {min_req})")

        return score, should_block, reason
