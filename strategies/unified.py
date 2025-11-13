"""
Unified Blocking Strategy

This simplified strategy evaluates three conditions:
1. RPM (Requests per Minute) threshold - sustained rate check
2. Sustained activity % over analysis window - persistence check
3. System CPU load (15-minute average) - resource impact check

Blocks when RPM AND sustained activity conditions are met (score >= 2.0).
CPU load is considered but not required for blocking.
"""

import logging
import psutil

logger = logging.getLogger(__name__)

# Default thresholds
DEFAULT_MIN_RPM_THRESHOLD = 20.0
DEFAULT_MIN_SUSTAINED_PERCENT = 50.0
DEFAULT_MAX_CPU_LOAD_THRESHOLD = 5.0
BLOCKING_SCORE_THRESHOLD = 2.0

class Strategy:
    """
    Unified strategy evaluating:
    - Request rate per minute (RPM)
    - Sustained activity percentage over analysis window
    - System CPU load (15-minute average)
    
    Blocks when score >= 2.0 (RPM AND sustained conditions met).
    """

    def get_required_config_keys(self):
        """Returns config keys required by this strategy."""
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
        Calculates score (0-3) based on meeting conditions:
        1. RPM >= min_rpm_threshold
        2. Sustained activity >= min_sustained_percent
        3. CPU load <= max_cpu_load_threshold (informational, not blocking)
        
        Decides blocking if score >= 2.0 (conditions 1 AND 2 met).
        """
        score = 0.0
        should_block = False
        reason = "Conditions not met"
        conditions_met_count = 0
        block_decision_reasons = []

        # Retrieve necessary context params
        analysis_duration_seconds = shared_context_params.get('analysis_duration_seconds', 0)

        # Get thresholds from config
        min_rpm_threshold = getattr(config, 'min_rpm_threshold', DEFAULT_MIN_RPM_THRESHOLD)
        min_sustained_percent = getattr(config, 'min_sustained_percent', DEFAULT_MIN_SUSTAINED_PERCENT)
        max_cpu_load_threshold = getattr(config, 'max_cpu_load_threshold', DEFAULT_MAX_CPU_LOAD_THRESHOLD)

        # --- Condition 1: Check RPM threshold ---
        rpm_condition_met = False
        current_rpm = threat_data.get('subnet_req_per_min_window', 0.0)
        
        if current_rpm >= min_rpm_threshold:
            rpm_condition_met = True
            conditions_met_count += 1
            block_decision_reasons.append(f"RPM >= {min_rpm_threshold:.1f} ({current_rpm:.1f})")
        else:
            block_decision_reasons.append(f"RPM < {min_rpm_threshold:.1f} ({current_rpm:.1f})")

        # --- Condition 2: Check sustained activity percentage ---
        sustained_condition_met = False
        current_timespan = threat_data.get('subnet_time_span', 0)
        
        if analysis_duration_seconds and analysis_duration_seconds > 0:
            min_timespan_threshold_seconds = analysis_duration_seconds * (min_sustained_percent / 100.0)
            if current_timespan >= min_timespan_threshold_seconds:
                sustained_condition_met = True
                conditions_met_count += 1
                block_decision_reasons.append(
                    f"Sustained >= {min_sustained_percent:.1f}% ({current_timespan:.0f}s)"
                )
            else:
                block_decision_reasons.append(
                    f"Sustained < {min_sustained_percent:.1f}% ({current_timespan:.0f}s)"
                )
        else:
            block_decision_reasons.append(
                f"Sustained % check skipped (duration={analysis_duration_seconds})"
            )

        # --- Condition 3: Check CPU load (15-minute average) ---
        cpu_condition_met = False
        try:
            # Get 15-minute load average (index 2 of getloadavg)
            load_15min = psutil.getloadavg()[2]
            
            if load_15min <= max_cpu_load_threshold:
                cpu_condition_met = True
                conditions_met_count += 1
                block_decision_reasons.append(
                    f"CPU load <= {max_cpu_load_threshold:.1f} ({load_15min:.2f})"
                )
            else:
                block_decision_reasons.append(
                    f"CPU load > {max_cpu_load_threshold:.1f} ({load_15min:.2f})"
                )
        except (AttributeError, OSError) as e:
            # getloadavg() might not be available on all systems (e.g., Windows)
            logger.warning(f"Could not get system load average: {e}")
            block_decision_reasons.append("CPU load check unavailable")

        # --- Final Block Decision and Score Calculation ---
        score = float(conditions_met_count)

        # Block if RPM AND sustained conditions are met (score >= 2.0)
        # This means at minimum conditions 1 and 2 must be satisfied
        if rpm_condition_met and sustained_condition_met:
            should_block = True
            met_reasons = [r for r in block_decision_reasons if ">=" in r or "<=" in r]
            reason = f"Block: Score {score:.1f} >= {BLOCKING_SCORE_THRESHOLD:.1f}. Met ({', '.join(met_reasons)})"
        else:
            should_block = False
            failed_reasons = [r for r in block_decision_reasons if "<" in r and ">=" not in r and "<=" not in r]
            met_reasons = [r for r in block_decision_reasons if ">=" in r or "<=" in r]
            reason = f"No Block: Score {score:.1f}. "
            if met_reasons:
                reason += f"Met ({', '.join(met_reasons)}). "
            if failed_reasons:
                reason += f"Failed ({', '.join(failed_reasons)})"

        return score, should_block, reason
