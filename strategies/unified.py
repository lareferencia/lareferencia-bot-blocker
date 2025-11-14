"""
Unified Blocking Strategy

This simplified strategy evaluates two conditions with CPU-based dynamic adjustment:
1. RPM (Requests per Minute) threshold - sustained rate check
2. Sustained activity % over analysis window - persistence check

CPU-Based Dynamic Thresholds:
- Base defaults (CPU load <= 80%): 10 req/min, 25% time window
- At 80% CPU: 5 req/min (50%), 12.5% time window (50%)
- At 90% CPU: 2.5 req/min (25%), 6.25% time window (25%)
- At 100% CPU: 0 req/min (0%), 0% time window (0%)
- Linear interpolation between 80-100% CPU load

Blocks when RPM AND sustained activity conditions are met (score >= 2.0).
"""

import logging
import psutil

logger = logging.getLogger(__name__)

# Default thresholds (base values when CPU load <= 80%)
DEFAULT_MIN_RPM_THRESHOLD = 10.0
DEFAULT_MIN_SUSTAINED_PERCENT = 25.0
DEFAULT_MAX_CPU_LOAD_THRESHOLD = 80.0  # CPU load threshold for aggressive mode
BLOCKING_SCORE_THRESHOLD = 2.0

# CPU-based dynamic threshold parameters
CPU_AGGRESSIVE_THRESHOLD = 80.0  # CPU % at which aggressive mode starts
CPU_MAX_THRESHOLD = 100.0  # CPU % at maximum aggressiveness

class Strategy:
    """
    Unified strategy evaluating:
    - Request rate per minute (RPM) - dynamically adjusted based on CPU load
    - Sustained activity percentage over analysis window - dynamically adjusted based on CPU load
    
    CPU-based dynamic adjustment (80-100% range):
    - At <= 80% CPU: use base defaults (10 req/min, 25% time window)
    - At 80-100% CPU: linearly reduce thresholds from 50% to 0% of base values
    
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
        Calculates score (0-2) based on meeting conditions:
        1. RPM >= min_rpm_threshold (dynamically adjusted based on CPU)
        2. Sustained activity >= min_sustained_percent (dynamically adjusted based on CPU)
        
        CPU-based dynamic adjustment:
        - At CPU <= 80%: use default thresholds (10 req/min, 25% time window)
        - At CPU = 80%: reduce to 50% of defaults (5 req/min, 12.5%)
        - At CPU = 90%: reduce to 25% of defaults (2.5 req/min, 6.25%)
        - At CPU = 100%: reduce to 0% (0 req/min, 0%)
        - Linear interpolation between 80-100% CPU
        
        Decides blocking if score >= 2.0 (conditions 1 AND 2 met).
        """
        score = 0.0
        should_block = False
        reason = "Conditions not met"
        conditions_met_count = 0
        block_decision_reasons = []

        # Retrieve necessary context params
        analysis_duration_seconds = shared_context_params.get('analysis_duration_seconds', 0)

        # Get base thresholds from config
        base_min_rpm_threshold = getattr(config, 'min_rpm_threshold', DEFAULT_MIN_RPM_THRESHOLD)
        base_min_sustained_percent = getattr(config, 'min_sustained_percent', DEFAULT_MIN_SUSTAINED_PERCENT)
        max_cpu_load_threshold = getattr(config, 'max_cpu_load_threshold', DEFAULT_MAX_CPU_LOAD_THRESHOLD)
        
        # Get current CPU load (15-minute average)
        current_cpu_load = 0.0
        try:
            current_cpu_load = psutil.getloadavg()[2]
        except (AttributeError, OSError) as e:
            logger.warning(f"Could not get system load average for dynamic threshold calculation: {e}")
            current_cpu_load = 0.0
        
        # Convert CPU load to percentage (normalize by number of CPU cores)
        try:
            cpu_count = psutil.cpu_count()
            if cpu_count and cpu_count > 0:
                cpu_load_percent = (current_cpu_load / cpu_count) * 100.0
            else:
                cpu_load_percent = 0.0
        except Exception as e:
            logger.warning(f"Could not calculate CPU load percentage: {e}")
            cpu_load_percent = 0.0
        
        # Apply CPU-based dynamic threshold adjustment
        min_rpm_threshold = base_min_rpm_threshold
        min_sustained_percent = base_min_sustained_percent
        
        if cpu_load_percent > max_cpu_load_threshold:
            # Calculate reduction factor based on CPU load
            # At 80%: factor = 1.0 (100% of base = no reduction yet, we apply 50% at the threshold)
            # At 90%: factor = 0.5 (50% reduction from 80% value)
            # At 100%: factor = 0.0 (100% reduction)
            
            # Actually, the requirement states:
            # At 80% CPU: use 5 req/min (50% of default 10) and 12.5% (50% of 25%)
            # At 90% CPU: use 2.5 req/min (25% of default 10) and 6.25% (25% of 25%)
            # At 100% CPU: use 0 req/min and 0%
            
            # So the factor at 80% should be 0.5, at 90% should be 0.25, at 100% should be 0.0
            # Linear interpolation: factor = 1.0 - ((cpu_load_percent - 80) / (100 - 80))
            # But that would give us factor = 0.0 at 100%, 0.5 at 90%, 1.0 at 80%
            # We need: at 80% -> 0.5, at 90% -> 0.25, at 100% -> 0.0
            # So: factor = 1.0 - ((cpu_load_percent - 80) / 40)
            # At 80%: factor = 1.0 - 0 = 1.0, but we want 0.5
            # Let me recalculate:
            # At 80%: factor should be 0.5 (50% of base)
            # At 90%: factor should be 0.25 (25% of base)
            # At 100%: factor should be 0.0 (0% of base)
            # This is: factor = 0.5 * (1 - (cpu_load_percent - 80) / 20)
            # At 80%: factor = 0.5 * (1 - 0/20) = 0.5 ✓
            # At 90%: factor = 0.5 * (1 - 10/20) = 0.5 * 0.5 = 0.25 ✓
            # At 100%: factor = 0.5 * (1 - 20/20) = 0.5 * 0 = 0.0 ✓
            
            reduction_factor = 0.5 * (1.0 - ((cpu_load_percent - max_cpu_load_threshold) / 20.0))
            reduction_factor = max(0.0, min(0.5, reduction_factor))  # Clamp between 0.0 and 0.5
            
            min_rpm_threshold = base_min_rpm_threshold * reduction_factor
            min_sustained_percent = base_min_sustained_percent * reduction_factor
            
            logger.info(f"CPU load {cpu_load_percent:.1f}% > {max_cpu_load_threshold:.1f}%: "
                       f"Applying aggressive thresholds (factor={reduction_factor:.2f}): "
                       f"RPM={min_rpm_threshold:.2f}, Sustained={min_sustained_percent:.1f}%")
        else:
            logger.debug(f"CPU load {cpu_load_percent:.1f}% <= {max_cpu_load_threshold:.1f}%: "
                        f"Using base thresholds: RPM={min_rpm_threshold:.1f}, Sustained={min_sustained_percent:.1f}%")


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

        # --- Final Block Decision and Score Calculation ---
        score = float(conditions_met_count)

        # Block if RPM AND sustained conditions are met (score >= 2.0)
        if rpm_condition_met and sustained_condition_met:
            should_block = True
            met_reasons = [r for r in block_decision_reasons if ">=" in r]
            reason = f"Block: Score {score:.1f} >= {BLOCKING_SCORE_THRESHOLD:.1f}. Met ({', '.join(met_reasons)})"
        else:
            should_block = False
            failed_reasons = [r for r in block_decision_reasons if "<" in r and ">=" not in r]
            met_reasons = [r for r in block_decision_reasons if ">=" in r]
            reason = f"No Block: Score {score:.1f}. "
            if met_reasons:
                reason += f"Met ({', '.join(met_reasons)}). "
            if failed_reasons:
                reason += f"Failed ({', '.join(failed_reasons)})"

        return score, should_block, reason
