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
import pandas as pd # Import pandas for isna check

logger = logging.getLogger(__name__)

# --- Hardcoded value for TimeSpan threshold ---
DEFAULT_MIN_TIMESPAN_PERCENT = 75.0

class Strategy:
    """
    Combined strategy (Updated Logic):
    - Score reflects blocking conditions met (TimeSpan + Alternative).
    - Block decision is based on: Fixed TimeSpan % AND (Req/Min(Win) > block_total_max_rpm_threshold OR TotalReq > block_relative_threshold_percent of MaxTotalReq).
    - The initial effective_min_requests filter is NOT applied by this strategy.
    """

    def get_required_config_keys(self):
        """Returns a list of config keys required by this strategy."""
        # block_trigger_count and original thresholds are no longer directly used for blocking logic here
        return [
            'block_total_max_rpm_threshold', # Reused for Req/Min(Win) threshold
            'block_relative_threshold_percent' # Reused for Total Requests threshold %
            # block_ip_count_threshold, block_max_rpm_threshold, block_trigger_count are ignored by this strategy's block logic
        ]

    def calculate_threat_score_and_block(self,
                                         threat_data,
                                         config,
                                         effective_min_requests, # Received but ignored by this strategy's logic
                                         analysis_duration_seconds,
                                         max_total_requests,
                                         max_subnet_time_span, # Keep receiving for potential future use or context
                                         max_subnet_req_per_min_window):
        """
        Calculates score and decides blocking based on:
        Fixed TimeSpan % AND (Req/Min(Win) vs block_total_max_rpm_threshold OR TotalReq vs block_relative_threshold_percent of Max).
        Score reflects which blocking conditions were met.
        """
        score = 0.0 # Use float for score
        should_block = False
        reason = "Conditions not met"

        # --- REMOVED Initial Check for effective_min_requests ---
        # if threat_data.get('total_requests', 0) < effective_min_requests:
        #     reason = f"Below effective min requests ({effective_min_requests})"
        #     return 0, False, reason # Score 0, no block

        # --- Determine Block Decision and Score based on New Logic ---
        block_decision_reasons = []
        timespan_condition_met = False
        req_min_win_ok = False
        total_req_ok = False

        # a) Check Mandatory TimeSpan Condition (Using Hardcoded Percentage)
        current_timespan = threat_data.get('subnet_time_span', 0)
        if analysis_duration_seconds > 0:
            min_timespan_threshold_seconds = analysis_duration_seconds * (DEFAULT_MIN_TIMESPAN_PERCENT / 100.0)
            if current_timespan >= min_timespan_threshold_seconds:
                timespan_condition_met = True
                block_decision_reasons.append(f"TimeSpan >= {DEFAULT_MIN_TIMESPAN_PERCENT:.1f}% ({current_timespan:.0f}s)")
            else:
                 block_decision_reasons.append(f"TimeSpan < {DEFAULT_MIN_TIMESPAN_PERCENT:.1f}% ({current_timespan:.0f}s)")
        else:
             timespan_condition_met = False # Cannot meet % condition if duration is 0
             block_decision_reasons.append("TimeSpan % condition skipped (duration=0)")


        # b) Check Alternative Conditions - Only if TimeSpan condition is met
        if timespan_condition_met:
            # Check Req/Min(Win) using block_total_max_rpm_threshold
            min_req_win_threshold = config.block_total_max_rpm_threshold
            current_req_min_win = threat_data.get('subnet_req_per_min_window', 0.0)
            if current_req_min_win > min_req_win_threshold:
                 req_min_win_ok = True
                 block_decision_reasons.append(f"Req/Min(Win) > {min_req_win_threshold:.1f}")
            # else: # Optional reason
            #    block_decision_reasons.append(f"Req/Min(Win) <= {min_req_win_threshold:.1f}")


            # Check Total Requests using block_relative_threshold_percent (only if Req/Min(Win) wasn't met)
            if not req_min_win_ok and max_total_requests > 0:
                 min_total_req_threshold = max_total_requests * (config.block_relative_threshold_percent / 100.0)
                 # Ensure total_requests is numeric before comparison
                 current_total_req_raw = threat_data.get('total_requests', 0)
                 current_total_req = 0
                 if current_total_req_raw is not None and not pd.isna(current_total_req_raw):
                      current_total_req = int(current_total_req_raw)

                 min_total_req_threshold = max(1, min_total_req_threshold) # Ensure threshold is at least 1
                 if current_total_req > min_total_req_threshold:
                     total_req_ok = True
                     block_decision_reasons.append(f"TotalReq > {config.block_relative_threshold_percent:.1f}% max ({current_total_req} > {min_total_req_threshold:.0f})")
                 # else: # Optional reason
                 #    block_decision_reasons.append(f"TotalReq <= {config.block_relative_threshold_percent:.1f}% max ({current_total_req} <= {min_total_req_threshold:.0f})")
            # elif not req_min_win_ok: # Optional reason
            #    block_decision_reasons.append("TotalReq condition skipped (max=0 or Req/Min(Win) already met)")

        # c) Final Block Decision and Score Calculation
        alternative_condition_met = req_min_win_ok or total_req_ok

        if timespan_condition_met and alternative_condition_met:
            should_block = True
            # Score based on which alternative condition was met
            if req_min_win_ok:
                score = 2.0 # Higher score for meeting Req/Min(Win)
                reason_parts = [block_decision_reasons[0], f"Req/Min(Win) > {min_req_win_threshold:.1f}"]
            else: # total_req_ok must be true
                score = 1.5 # Slightly lower score for meeting TotalReq%
                reason_parts = [block_decision_reasons[0], f"TotalReq > {config.block_relative_threshold_percent:.1f}% max"]
            reason = "Block: " + " AND ".join(reason_parts)

        elif timespan_condition_met: # TimeSpan met, but no alternative
            should_block = False
            score = 1.0 # Score indicating only TimeSpan was met
            failed_alternatives = []
            if not req_min_win_ok:
                 failed_alternatives.append(f"Req/Min(Win) <= {min_req_win_threshold:.1f}")
            if not total_req_ok:
                 # Add reason only if it was actually checked
                 if max_total_requests > 0:
                     min_total_req_threshold = max(1, max_total_requests * (config.block_relative_threshold_percent / 100.0))
                     current_total_req = int(threat_data.get('total_requests', 0)) # Recalculate for reason string
                     failed_alternatives.append(f"TotalReq <= {config.block_relative_threshold_percent:.1f}% max ({current_total_req} <= {min_total_req_threshold:.0f})")
                 else:
                     failed_alternatives.append("TotalReq check skipped (max=0)")
            reason = f"No Block: {block_decision_reasons[0]} but ({' AND '.join(failed_alternatives)})"

        else: # TimeSpan condition not met
            should_block = False
            score = 0.0 # Score 0 if TimeSpan not met
            reason = f"No Block: {block_decision_reasons[0]}" # Primary reason is failed TimeSpan


        # Return the score (reflecting block conditions) and the block decision/reason
        return score, should_block, reason
