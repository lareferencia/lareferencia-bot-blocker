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
                                         effective_min_requests,
                                         analysis_duration_seconds=None,
                                         total_overall_requests=None,
                                         max_total_requests=None,
                                         max_subnet_time_span=None,
                                         max_ip_count=None):
        """
        Calculates a threat score and determines if the threat should be blocked.

        Args:
            threat_data (dict): Dictionary containing aggregated metrics for the threat (subnet).
                                Expected keys: 'total_requests', 'ip_count',
                                'subnet_avg_ip_rpm', 'subnet_max_ip_rpm', 'details' (list of top IP dicts), etc.
            config (argparse.Namespace): Parsed command-line arguments containing strategy-specific thresholds
                                         (e.g., config.block_danger_threshold).
            effective_min_requests (int): The calculated minimum request threshold (absolute or relative).
            analysis_duration_seconds (float, optional): The duration of the analysis window in seconds. Defaults to None.
            total_overall_requests (int, optional): The total number of requests observed in the analysis window.
            max_total_requests (int, optional): The maximum total_requests observed across all threats in this run.
            max_subnet_time_span (float, optional): The maximum subnet_time_span observed across all threats in this run.
            max_ip_count (int, optional): The maximum ip_count observed across all threats in this run.

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
