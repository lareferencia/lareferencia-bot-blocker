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
        return super().get_required_config_keys() + ['block_ip_count_threshold']

    def calculate_threat_score_and_block(self, threat_data, config):
        """Calculates score and block decision."""
        total_requests = threat_data.get('total_requests', 0)
        ip_count = threat_data.get('ip_count', 0)

        # Score for sorting: Primarily based on IP count, secondarily on requests.
        score = (ip_count * 10) + (total_requests / 100.0) # Example weighting

        should_block = False
        reason = None

        # Check blocking criteria
        min_req = getattr(config, 'block_threshold', 10)
        min_ips = getattr(config, 'block_ip_count_threshold', 0) # Get from config

        if total_requests >= min_req and ip_count >= min_ips:
            should_block = True
            reason = (f"meets request threshold ({total_requests}>={min_req}) "
                      f"and IP count threshold ({ip_count}>={min_ips})")
            logger.debug(f"Threat {threat_data.get('id', 'N/A')} qualifies: {reason}")
        elif total_requests >= min_req:
             logger.debug(f"Threat {threat_data.get('id', 'N/A')} meets request threshold but not IP count "
                          f"({ip_count} < {min_ips})")

        return score, should_block, reason
