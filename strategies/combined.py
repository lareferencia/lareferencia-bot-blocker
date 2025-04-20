"""
Blocking Strategy: **Combined Ensemble**

Esta estrategia integra en una sola decisión los cuatro ejes
principales de abuso sobre los que hemos hablado:

1. **Volumen** total de peticiones en la subred (/24 · /64)
2. **Coordinación** → número de IPs distintas (`ip_count`)
3. **Picos por IP** → máximo RPM observado en un único IP del mismo rango
4. **Pico global del rango** → máximo RPM sumando todas las IPs
5. **Persistencia** → porcentaje del intervalo de análisis en el que la
   subred estuvo enviando tráfico (solo si se delimitó la ventana con
   `--time-window` o `--start-date`)

Decisión de bloqueo (`should_block`):

* La subred supera el *volumen mínimo* dinámico (`effective_min_requests`)
  **y**
* Cumple **al menos `block_trigger_count` disparadores** de la lista
  anterior (por defecto, 2 de 5).

`StrategyScore` (para orden de reporte) es la media ponderada de los
cinco factores, normalizados en cada ejecución.
"""

import logging

logger = logging.getLogger(__name__)

# --- Hardcoded value for TimeSpan threshold ---
DEFAULT_MIN_TIMESPAN_PERCENT = 75.0

class Strategy:
    """
    Combined strategy:
    - Score is based on meeting multiple original thresholds (IP count, Max IP RPM, Peak Subnet RPM).
    - Block decision is based on: Fixed TimeSpan % AND (Req/Min(Win) > block_total_max_rpm_threshold OR TotalReq > block_relative_threshold_percent of MaxTotalReq).
    """

    def get_required_config_keys(self):
        """Returns a list of config keys required by this strategy."""
        # No new keys needed, reusing existing ones
        return [
            'block_ip_count_threshold',
            'block_max_rpm_threshold',
            'block_total_max_rpm_threshold', # Reused for Req/Min(Win) threshold
            'block_trigger_count', # Used for scoring
            'block_relative_threshold_percent' # Reused for Total Requests threshold %
        ]

    def calculate_threat_score_and_block(self,
                                         threat_data,
                                         config,
                                         effective_min_requests,
                                         analysis_duration_seconds,
                                         max_total_requests,
                                         max_subnet_time_span, # Keep receiving for potential future use or context
                                         max_subnet_req_per_min_window):
        """
        Calculates score based on original triggers, but decides blocking based on
        Fixed TimeSpan % AND (Req/Min(Win) vs block_total_max_rpm_threshold OR TotalReq vs block_relative_threshold_percent of Max).
        """
        score = 0
        should_block = False
        reason = "Conditions not met"
        triggers_met = 0
        trigger_reasons = [] # Keep track of original triggers for score

        # --- 1. Calculate Score based on Original Triggers ---
        if threat_data.get('total_requests', 0) < effective_min_requests:
            reason = f"Below effective min requests ({effective_min_requests})"
            return 0, False, reason # Score 0, no block

        # Check original trigger conditions for scoring
        if threat_data.get('ip_count', 0) >= config.block_ip_count_threshold:
            triggers_met += 1
            trigger_reasons.append(f"IP Count >= {config.block_ip_count_threshold}")

        if threat_data.get('subnet_max_ip_rpm', 0) >= config.block_max_rpm_threshold:
            triggers_met += 1
            trigger_reasons.append(f"Max IP RPM >= {config.block_max_rpm_threshold}")

        # Use block_total_max_rpm_threshold in its original sense for scoring
        if threat_data.get('subnet_total_max_rpm', 0) >= config.block_total_max_rpm_threshold:
            triggers_met += 1
            trigger_reasons.append(f"Peak Subnet RPM >= {config.block_total_max_rpm_threshold}")

        # Score is based on the number of original triggers met vs block_trigger_count
        # NOTE: In this version, score is primarily for sorting. Block decision uses different logic below.
        if triggers_met >= config.block_trigger_count:
             score = triggers_met # Assign score based on triggers met
        else:
             score = triggers_met # Assign score even if below trigger count for sorting

        # --- 2. Determine Block Decision based on New Logic ---
        block_decision_reasons = []
        timespan_condition_met = False
        alternative_condition_met = False

        # a) Check Mandatory TimeSpan Condition (Using Hardcoded Percentage)
        current_timespan = threat_data.get('subnet_time_span', 0)
        if analysis_duration_seconds > 0:
            # Use the hardcoded percentage
            min_timespan_threshold_seconds = analysis_duration_seconds * (DEFAULT_MIN_TIMESPAN_PERCENT / 100.0)
            if current_timespan >= min_timespan_threshold_seconds:
                timespan_condition_met = True
                block_decision_reasons.append(f"TimeSpan >= {DEFAULT_MIN_TIMESPAN_PERCENT:.1f}% ({current_timespan:.0f}s)")
            else:
                 block_decision_reasons.append(f"TimeSpan < {DEFAULT_MIN_TIMESPAN_PERCENT:.1f}% ({current_timespan:.0f}s)")
        else:
             # If duration is 0, cannot calculate percentage. Consider this condition unmet or handle differently.
             timespan_condition_met = False # Defaulting to unmet if duration is 0
             block_decision_reasons.append("TimeSpan % condition skipped (duration=0)")


        # b) Check Alternative Conditions - Only if TimeSpan condition is met
        if timespan_condition_met:
            # Check Req/Min(Win) using block_total_max_rpm_threshold
            req_min_win_ok = False
            # Use the value from config.block_total_max_rpm_threshold directly as the threshold for Req/Min(Win)
            min_req_win_threshold = config.block_total_max_rpm_threshold
            current_req_min_win = threat_data.get('subnet_req_per_min_window', 0.0)
            if current_req_min_win > min_req_win_threshold:
                 req_min_win_ok = True
                 alternative_condition_met = True
                 block_decision_reasons.append(f"Req/Min(Win) > {min_req_win_threshold:.1f}")
            # else: # Optional reason for logging/debugging
            #    block_decision_reasons.append(f"Req/Min(Win) <= {min_req_win_threshold:.1f}")


            # Check Total Requests using block_relative_threshold_percent (only if Req/Min(Win) wasn't met)
            total_req_ok = False
            if not alternative_condition_met and max_total_requests > 0:
                 # Calculate threshold based on the percentage of the max observed requests
                 min_total_req_threshold = max_total_requests * (config.block_relative_threshold_percent / 100.0)
                 current_total_req = threat_data.get('total_requests', 0)
                 # Ensure threshold is at least 1 if percentage is very low or max_total_requests is low
                 min_total_req_threshold = max(1, min_total_req_threshold)
                 if current_total_req > min_total_req_threshold:
                     total_req_ok = True
                     alternative_condition_met = True
                     block_decision_reasons.append(f"TotalReq > {config.block_relative_threshold_percent:.1f}% max ({current_total_req} > {min_total_req_threshold:.0f})")
                 # else: # Optional reason for logging/debugging
                 #    block_decision_reasons.append(f"TotalReq <= {config.block_relative_threshold_percent:.1f}% max ({current_total_req} <= {min_total_req_threshold:.0f})")
            elif not alternative_condition_met: # Reason if max_total_requests is 0 or condition skipped
                 block_decision_reasons.append("TotalReq condition skipped (max=0 or Req/Min(Win) already met)")

        # c) Final Block Decision
        if timespan_condition_met and alternative_condition_met:
            should_block = True
            # Format reason string more clearly
            reason_parts = []
            # Find the specific alternative condition that was met
            if req_min_win_ok:
                reason_parts.append(f"Req/Min(Win) > {min_req_win_threshold:.1f}")
            if total_req_ok:
                 reason_parts.append(f"TotalReq > {config.block_relative_threshold_percent:.1f}% max")

            reason = f"Block: {block_decision_reasons[0]} AND ({' OR '.join(reason_parts)})"

        else:
            should_block = False
            # Provide reason why block conditions failed, focusing on the first failure point
            if not timespan_condition_met:
                 reason = f"No Block: {block_decision_reasons[0]}" # Primary reason is failed TimeSpan
            elif timespan_condition_met and not alternative_condition_met:
                 # Construct reason showing TimeSpan met, but alternatives failed
                 failed_alternatives = []
                 if not req_min_win_ok:
                     failed_alternatives.append(f"Req/Min(Win) <= {min_req_win_threshold:.1f}")
                 if not total_req_ok:
                     # Add reason only if it was actually checked
                     if max_total_requests > 0:
                         min_total_req_threshold = max(1, max_total_requests * (config.block_relative_threshold_percent / 100.0))
                         failed_alternatives.append(f"TotalReq <= {config.block_relative_threshold_percent:.1f}% max ({threat_data.get('total_requests', 0)} <= {min_total_req_threshold:.0f})")
                     else:
                         failed_alternatives.append("TotalReq check skipped (max=0)")

                 reason = f"No Block: {block_decision_reasons[0]} but ({' AND '.join(failed_alternatives)})"
            else: # Should not happen with current logic, but as fallback
                 reason = "No Block: Conditions not met"


        # Return the score (based on original triggers) and the block decision/reason (based on new logic)
        return score, should_block, reason
