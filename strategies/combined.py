"""
Blocking Strategy: Combined Criteria.

Blocks if total requests exceed a threshold AND EITHER the aggregated IP danger score
OR the IP count exceeds their respective thresholds.
"""
import logging
from .base_strategy import BaseStrategy

logger = logging.getLogger('botstats.strategy.combined')

class Strategy(BaseStrategy):
    """Implements the Combined blocking strategy."""

    def get_required_config_keys(self):
        # Requires keys from both danger and coordination strategies
        # block_threshold is handled by effective_min_requests
        return ['block_duration', 'block_danger_threshold', 'block_ip_count_threshold']

    def calculate_threat_score_and_block(self, threat_data, config, effective_min_requests, analysis_duration_seconds=None):
        """Calculates score and block decision."""
        total_requests = threat_data.get('total_requests', 0)
        ip_count = threat_data.get('ip_count', 0)
        # Use the pre-calculated aggregated score
        aggregated_ip_danger_score = threat_data.get('aggregated_ip_danger_score', 0)

        # Score for sorting: Weighted sum of danger score, ip_count, and requests
        score = (aggregated_ip_danger_score * 0.6) + (ip_count * 2) + (total_requests / 100.0) # Example weighting

        should_block = False
        reason = None

        # Check blocking criteria
        min_req = effective_min_requests # Use the passed effective threshold
        min_danger = getattr(config, 'block_danger_threshold', 0)
        min_ips = getattr(config, 'block_ip_count_threshold', 0)

        if total_requests >= min_req:
            meets_req_threshold = True
            if aggregated_ip_danger_score >= min_danger:
                should_block = True
                reason = (f"meets request threshold ({total_requests}>={min_req}) "
                          f"and danger threshold ({aggregated_ip_danger_score:.2f}>={min_danger})")
            elif ip_count >= min_ips:
                should_block = True
                reason = (f"meets request threshold ({total_requests}>={min_req}) "
                          f"and IP count threshold ({ip_count}>={min_ips})")

            if should_block:
                 logger.debug(f"Threat {threat_data.get('id', 'N/A')} qualifies: {reason}")
            else: # Meets request threshold but not secondary criteria
                 logger.debug(f"Threat {threat_data.get('id', 'N/A')} meets request threshold ({total_requests}>={min_req}) but not secondary criteria "
                              f"(Danger: {aggregated_ip_danger_score:.2f}<{min_danger}, IPs: {ip_count}<{min_ips})")
        else: # Below request threshold
             logger.debug(f"Threat {threat_data.get('id', 'N/A')} below request threshold ({total_requests} < {min_req})")


        return score, should_block, reason
