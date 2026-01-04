"""
Base class or interface definition for blocking strategies.
"""
from abc import ABC, abstractmethod

class BaseStrategy(ABC):
    """Abstract base class for threat scoring and blocking strategies."""

    @abstractmethod
    def calculate_threat_score_and_block(self,
                                         threat_data,
                                         config,
                                         shared_context_params):
        """
        Calculates a threat score and determines if the threat should be blocked.

        Args:
            threat_data (dict): Dictionary containing aggregated metrics for the threat (subnet).
                                Expected keys: 'total_requests', 'ip_count',
                                'subnet_avg_ip_rpm', 'subnet_max_ip_rpm', 'details' (list of top IP dicts), etc.
            config (argparse.Namespace): Parsed command-line arguments containing strategy-specific thresholds
                                         (e.g., config.block_danger_threshold).
            shared_context_params (dict): Dictionary containing shared parameters and overall maximums/context.
                                          Expected keys like 'analysis_duration_seconds', 'total_overall_requests',
                                          'system_load_avg', 'max_total_requests', 'max_ip_count', etc.

        Returns:
            tuple: (score, should_block, reason)
                   - score (float): A numerical score for sorting threats. Higher is generally worse.
                   - should_block (bool): True if the threat meets blocking criteria.
                   - reason (str or None): Explanation if should_block is True, otherwise None.
        """
        pass

    def get_required_config_keys(self):
        """
        Returns a list of config keys (argparse args) expected by this strategy.
        Used for validation or help messages.
        """
        # block_threshold is no longer a direct dependency for the strategy logic itself
        return ['block_duration'] # Base requirements
