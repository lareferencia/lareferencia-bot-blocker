"""
Blocking Strategy: Volume + Peak RPM.

Blocks if total requests exceed a threshold AND the maximum RPM observed
from any single IP within the subnet exceeds another threshold.
"""
import logging
from .base_strategy import BaseStrategy

logger = logging.getLogger('botstats.strategy.volume_peak_rpm')

class Strategy(BaseStrategy):
    """Implements the Volume + Peak RPM strategy."""

    def get_required_config_keys(self):
        return super().get_required_config_keys() + ['block_max_rpm_threshold']

    def calculate_threat_score_and_block(self, threat_data, config):
        """Calculates score and block decision."""
        total_requests = threat_data.get('total_requests', 0)
        max_rpm = threat_data.get('subnet_max_ip_rpm', 0)

        # Score for sorting: Primarily based on max RPM, secondarily on requests.
        score = (max_rpm * 5) + (total_requests / 100.0) # Example weighting

        should_block = False
        reason = None

        # Check blocking criteria
        min_req = getattr(config, 'block_threshold', 10)
        min_max_rpm = getattr(config, 'block_max_rpm_threshold', 0) # Get from config

        if total_requests >= min_req and max_rpm >= min_max_rpm:
            should_block = True
            reason = (f"meets request threshold ({total_requests}>={min_req}) "
                      f"and max RPM threshold ({max_rpm:.0f}>={min_max_rpm})")
            logger.debug(f"Threat {threat_data.get('id', 'N/A')} qualifies: {reason}")
        elif total_requests >= min_req:
             logger.debug(f"Threat {threat_data.get('id', 'N/A')} meets request threshold but not max RPM "
                          f"({max_rpm:.0f} < {min_max_rpm})")

        return score, should_block, reason
