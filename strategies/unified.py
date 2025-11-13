"""
Unified Simplified Strategy.

This strategy evaluates:
1. Request rate per minute over the analysis window
2. Sustained activity over the last 30 minutes (or analysis window if shorter)
3. System CPU load (15-minute average)

Simpler scoring and blocking logic based on these three factors.
"""

import logging
import pandas as pd

logger = logging.getLogger(__name__)

# Default thresholds
DEFAULT_MIN_RPM = 20.0  # Minimum requests per minute
DEFAULT_MIN_SUSTAINED_PERCENT = 50.0  # Minimum % of window that must be active
DEFAULT_MAX_CPU_LOAD = 5.0  # Maximum CPU load threshold (higher load = stricter filtering)

class Strategy:
    """
    Unified simplified strategy:
    - Evaluates RPM (requests per minute)
    - Checks if activity is sustained (timespan % of window)
    - Considers CPU load to adjust filtering threshold
    
    Blocks if:
    - RPM > threshold AND
    - Activity sustained for required % of window AND
    - CPU load is above threshold (indicating system under stress)
    """

    def get_required_config_keys(self):
        """Returns a list of config keys required by this strategy."""
        return [
            'min_rpm_threshold',
            'min_sustained_percent', 
            'max_cpu_load_threshold'
        ]

    def calculate_threat_score_and_block(self,
                                         threat_data,
                                         config,
                                         effective_min_requests,
                                         shared_context_params):
        """
        Calculates score and blocking decision based on:
        1. RPM (requests per minute)
        2. Sustained activity percentage
        3. CPU load
        """
        score = 0.0
        should_block = False
        reason = "Conditions not met"
        conditions_met = []
        conditions_failed = []

        # Get configuration thresholds
        min_rpm = getattr(config, 'min_rpm_threshold', DEFAULT_MIN_RPM)
        min_sustained = getattr(config, 'min_sustained_percent', DEFAULT_MIN_SUSTAINED_PERCENT)
        max_cpu_load = getattr(config, 'max_cpu_load_threshold', DEFAULT_MAX_CPU_LOAD)

        # Get context parameters
        analysis_duration_seconds = shared_context_params.get('analysis_duration_seconds', 0)
        system_load_avg = shared_context_params.get('system_load_avg', -1.0)

        # Get threat metrics
        total_requests = threat_data.get('total_requests', 0)
        if total_requests is not None and not pd.isna(total_requests):
            total_requests = int(total_requests)
        else:
            total_requests = 0

        subnet_rpm = threat_data.get('subnet_req_per_min_window', 0.0)
        subnet_timespan = threat_data.get('subnet_time_span', 0)

        # --- Condition 1: Check RPM threshold ---
        rpm_ok = False
        if subnet_rpm > min_rpm:
            rpm_ok = True
            score += 1.0
            conditions_met.append(f"RPM {subnet_rpm:.1f} > {min_rpm:.1f}")
        else:
            conditions_failed.append(f"RPM {subnet_rpm:.1f} <= {min_rpm:.1f}")

        # --- Condition 2: Check sustained activity ---
        sustained_ok = False
        if analysis_duration_seconds > 0:
            min_timespan_seconds = analysis_duration_seconds * (min_sustained / 100.0)
            if subnet_timespan >= min_timespan_seconds:
                sustained_ok = True
                score += 1.0
                sustained_pct = (subnet_timespan / analysis_duration_seconds) * 100
                conditions_met.append(f"Sustained {sustained_pct:.1f}% >= {min_sustained:.1f}%")
            else:
                sustained_pct = (subnet_timespan / analysis_duration_seconds) * 100
                conditions_failed.append(f"Sustained {sustained_pct:.1f}% < {min_sustained:.1f}%")
        else:
            conditions_failed.append("Duration unknown, sustained check skipped")

        # --- Condition 3: Check CPU load (system under stress) ---
        cpu_stressed = False
        if system_load_avg >= 0:  # Valid load average
            if system_load_avg >= max_cpu_load:
                cpu_stressed = True
                score += 1.0
                conditions_met.append(f"CPU load {system_load_avg:.2f} >= {max_cpu_load:.2f}")
            else:
                conditions_failed.append(f"CPU load {system_load_avg:.2f} < {max_cpu_load:.2f}")
        else:
            conditions_failed.append("CPU load unavailable")

        # --- Blocking decision ---
        # Block if ALL three conditions are met (score == 3.0)
        # OR if RPM and sustained are met (score >= 2.0) for basic blocking
        if score >= 2.0 and rpm_ok and sustained_ok:
            should_block = True
            reason = f"Block: {', '.join(conditions_met)}"
            if conditions_failed:
                reason += f" | Not met: {', '.join(conditions_failed)}"
        else:
            should_block = False
            reason = f"No Block: Score {score:.1f}/3.0"
            if conditions_met:
                reason += f" | Met: {', '.join(conditions_met)}"
            if conditions_failed:
                reason += f" | Failed: {', '.join(conditions_failed)}"

        return score, should_block, reason
