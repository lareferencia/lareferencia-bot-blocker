"""
Blocking Strategy: Volume + Aggregated IP Danger Score.

Blocks if total requests exceed a threshold AND the sum of individual IP
danger scores (calculated based on their RPM and request count) exceeds another threshold.
"""
import logging
from .base_strategy import BaseStrategy

logger = logging.getLogger('botstats.strategy.volume_danger')

class Strategy(BaseStrategy):
    """Implements the Volume + Aggregated Danger Score strategy."""

    def get_required_config_keys(self):
        # block_threshold is handled by effective_min_requests
        return ['block_duration', 'block_danger_threshold']

    def calculate_threat_score_and_block(self, threat_data, config, effective_min_requests, analysis_duration_seconds=None):
        """Calculates score and block decision."""
        total_requests = threat_data.get('total_requests', 0)
        # ip_count = threat_data.get('ip_count', 0) # Not directly used here
        # details = threat_data.get('details', []) # Not needed for score/block decision

        # Use the pre-calculated aggregated score from threat_analyzer
        aggregated_ip_danger_score = threat_data.get('aggregated_ip_danger_score', 0)

        # Score for sorting: Use the aggregated danger score primarily, break ties with requests.
        score = aggregated_ip_danger_score + (total_requests / 1000.0)

        should_block = False
        reason = None

        # Check blocking criteria
        min_req = effective_min_requests # Use the passed effective threshold
        min_danger = getattr(config, 'block_danger_threshold', 0)

        if total_requests >= min_req and aggregated_ip_danger_score >= min_danger:
            should_block = True
            reason = (f"meets request threshold ({total_requests}>={min_req}) "
                      f"and danger threshold ({aggregated_ip_danger_score:.2f}>={min_danger})")
            logger.debug(f"Threat {threat_data.get('id', 'N/A')} qualifies: {reason}")
        elif total_requests >= min_req:
             logger.debug(f"Threat {threat_data.get('id', 'N/A')} meets request threshold ({total_requests}>={min_req}) but not danger "
                          f"({aggregated_ip_danger_score:.2f} < {min_danger})")
        else: # Log if below request threshold
             logger.debug(f"Threat {threat_data.get('id', 'N/A')} below request threshold ({total_requests} < {min_req})")

        return score, should_block, reason

