"""
Blocking Strategy: Sustained Average Total Subnet RPM.

Blocks if total requests exceed a threshold AND the average RPM of the entire subnet
(considering all requests) exceeds another threshold (e.g., 60 RPM for 1 RPS).
"""
import logging
from .base_strategy import BaseStrategy

logger = logging.getLogger('botstats.strategy.sustained_avg_rpm')

class Strategy(BaseStrategy):
    """Implements the Sustained Average Total Subnet RPM strategy."""

    def get_required_config_keys(self):
        # Uses the same threshold name, but its meaning is now subnet total avg RPM
        return super().get_required_config_keys() + ['block_avg_rpm_threshold']

    def calculate_threat_score_and_block(self, threat_data, config):
        """Calculates score and block decision based on subnet total average RPM."""
        total_requests = threat_data.get('total_requests', 0)
        # Use the new metric for subnet total average RPM
        avg_total_rpm = threat_data.get('subnet_total_avg_rpm', 0)

        # Score for sorting: Primarily based on the subnet's total average RPM.
        score = (avg_total_rpm * 10) + (total_requests / 100.0) # Example weighting

        should_block = False
        reason = None

        # Check blocking criteria
        min_req = getattr(config, 'block_threshold', 50)
        # Use the threshold defined for average RPM
        min_avg_total_rpm = getattr(config, 'block_avg_rpm_threshold', 60)

        if total_requests >= min_req and avg_total_rpm >= min_avg_total_rpm:
            should_block = True
            reason = (f"meets request threshold ({total_requests}>={min_req}) "
                      f"and subnet total average RPM threshold ({avg_total_rpm:.2f}>={min_avg_total_rpm})")
            logger.debug(f"Threat {threat_data.get('id', 'N/A')} qualifies: {reason}")
        elif total_requests >= min_req:
             logger.debug(f"Threat {threat_data.get('id', 'N/A')} meets request threshold but not subnet total average RPM "
                          f"({avg_total_rpm:.2f} < {min_avg_total_rpm})")

        return score, should_block, reason
