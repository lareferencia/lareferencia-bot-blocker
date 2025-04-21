"""
Blocking Strategy: Volume + Coordination (IP Count).

Blocks if total requests exceed a threshold AND the number of unique IPs
within the subnet exceeds another threshold.
"""
import logging
from .base_strategy import BaseStrategy

logger = logging.getLogger('botstats.strategy.volume_coordination')

class Strategy(BaseStrategy):
    """Implements the Volume + Coordination strategy with normalized scoring."""

    def get_required_config_keys(self):
        # block_threshold is handled by effective_min_requests
        return ['block_duration', 'block_ip_count_threshold']

    def calculate_threat_score_and_block(self,
                                         threat_data,
                                         config,
                                         effective_min_requests,
                                         analysis_duration_seconds=None,
                                         total_overall_requests=None,
                                         max_total_requests=None,
                                         max_subnet_time_span=None,
                                         # max_subnet_req_per_min_window=None, # REMOVED
                                         max_ip_count=None): # ADDED max_ip_count
        """Calculates normalized score and block decision."""
        total_requests = threat_data.get('total_requests', 0)
        ip_count = threat_data.get('ip_count', 0)

        # --- Normalized Score Calculation (0-1 range) ---
        # Normalize ip_count and total_requests relative to the maximums observed
        normalized_ip_count = (ip_count / max_ip_count) if max_ip_count and max_ip_count > 0 else 0
        normalized_requests = (total_requests / max_total_requests) if max_total_requests and max_total_requests > 0 else 0

        # Combine normalized values. Example: Weighted average (adjust weights as needed)
        # Giving more weight to coordination (ip_count)
        weight_ip_count = 0.7
        weight_requests = 0.3
        score = (normalized_ip_count * weight_ip_count) + (normalized_requests * weight_requests)
        # Ensure score is within 0-1 range just in case
        score = max(0.0, min(1.0, score))

        # --- Blocking Logic (Unchanged) ---
        should_block = False
        reason = None

        # Check blocking criteria
        min_req = effective_min_requests # Use the passed effective threshold
        min_ip_count = getattr(config, 'block_ip_count_threshold', 0) # Get from config

        if total_requests >= min_req and ip_count >= min_ip_count:
            should_block = True
            reason = (f"meets request threshold ({total_requests}>={min_req}) "
                      f"and IP count threshold ({ip_count}>={min_ip_count})")
            logger.debug(f"Threat {threat_data.get('id', 'N/A')} qualifies: {reason}")
        elif total_requests >= min_req:
             logger.debug(f"Threat {threat_data.get('id', 'N/A')} meets request threshold ({total_requests}>={min_req}) but not IP count "
                          f"({ip_count} < {min_ip_count})")
        else: # Log if below request threshold
             logger.debug(f"Threat {threat_data.get('id', 'N/A')} below request threshold ({total_requests} < {min_req})")

        return score, should_block, reason
