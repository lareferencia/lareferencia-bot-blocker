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
    Combined strategy (Updated Logic 2):
    - Score reflects how many blocking conditions are met (0-3).
    - Block decision requires ALL THREE conditions to be met:
        1. Fixed TimeSpan >= 75%
        2. TotalReq > block_relative_threshold_percent of MaxTotalReq
        3. Req/Min(Win) > block_total_max_rpm_threshold
    - The initial effective_min_requests filter is NOT applied by this strategy.
    """

    def get_required_config_keys(self):
        """Returns a list of config keys required by this strategy."""
        return [
            'block_total_max_rpm_threshold', # Used for Req/Min(Win) threshold (Condition 3)
            'block_relative_threshold_percent' # Used for Total Requests threshold % (Condition 2)
        ]

    def calculate_threat_score_and_block(self,
                                         threat_data,
                                         config,
                                         effective_min_requests, # Received but ignored
                                         analysis_duration_seconds,
                                         max_total_requests,
                                         max_subnet_time_span, # Keep receiving
                                         max_subnet_req_per_min_window):
        """
        Calculates score and decides blocking based on meeting ALL THREE conditions:
        1. TimeSpan >= 75%
        2. TotalReq > Relative% of Max
        3. Req/Min(Win) > Absolute Threshold
        Score reflects the number of conditions met (0-3).
        """
        score = 0.0 # Use float for score
        should_block = False
        reason = "Conditions not met"
        conditions_met_count = 0
        block_decision_reasons = [] # Store reasons for each condition check

        # --- Condition 1: Check Mandatory TimeSpan ---
        timespan_condition_met = False
        current_timespan = threat_data.get('subnet_time_span', 0)
        if analysis_duration_seconds > 0:
            min_timespan_threshold_seconds = analysis_duration_seconds * (DEFAULT_MIN_TIMESPAN_PERCENT / 100.0)
            if current_timespan >= min_timespan_threshold_seconds:
                timespan_condition_met = True
                conditions_met_count += 1
                block_decision_reasons.append(f"TimeSpan >= {DEFAULT_MIN_TIMESPAN_PERCENT:.1f}% ({current_timespan:.0f}s)")
            else:
                 block_decision_reasons.append(f"TimeSpan < {DEFAULT_MIN_TIMESPAN_PERCENT:.1f}% ({current_timespan:.0f}s)")
        else:
             block_decision_reasons.append("TimeSpan % condition skipped (duration=0)")

        # --- Condition 2: Check Mandatory Total Requests % ---
        total_req_ok = False
        if max_total_requests > 0:
             min_total_req_threshold = max_total_requests * (config.block_relative_threshold_percent / 100.0)
             current_total_req_raw = threat_data.get('total_requests', 0)
             current_total_req = 0
             if current_total_req_raw is not None and not pd.isna(current_total_req_raw):
                  current_total_req = int(current_total_req_raw)

             min_total_req_threshold = max(1, min_total_req_threshold) # Ensure threshold is at least 1
             if current_total_req > min_total_req_threshold:
                 total_req_ok = True
                 conditions_met_count += 1
                 block_decision_reasons.append(f"TotalReq > {config.block_relative_threshold_percent:.1f}% max ({current_total_req} > {min_total_req_threshold:.0f})")
             else:
                 block_decision_reasons.append(f"TotalReq <= {config.block_relative_threshold_percent:.1f}% max ({current_total_req} <= {min_total_req_threshold:.0f})")
        else:
             block_decision_reasons.append("TotalReq % condition skipped (max=0)")

        # --- Condition 3: Check Mandatory Req/Min(Win) ---
        req_min_win_ok = False
        min_req_win_threshold = config.block_total_max_rpm_threshold
        current_req_min_win = threat_data.get('subnet_req_per_min_window', 0.0)
        if current_req_min_win > min_req_win_threshold:
             req_min_win_ok = True
             conditions_met_count += 1
             block_decision_reasons.append(f"Req/Min(Win) > {min_req_win_threshold:.1f}")
        else:
             block_decision_reasons.append(f"Req/Min(Win) <= {min_req_win_threshold:.1f}")


        # --- Final Block Decision and Score Calculation ---
        # Block only if ALL THREE conditions are met
        if timespan_condition_met and total_req_ok and req_min_win_ok:
            should_block = True
            reason = "Block: " + " AND ".join(block_decision_reasons) # Join reasons for met conditions
        else:
            should_block = False
            # Construct reason showing which conditions failed
            failed_reasons = [r for r in block_decision_reasons if "<" in r or "<=" in r or "skipped" in r]
            met_reasons = [r for r in block_decision_reasons if ">" in r or ">=" in r]
            if failed_reasons:
                 reason = "No Block: Failed (" + ", ".join(failed_reasons) + ")"
                 if met_reasons:
                      reason += " Met (" + ", ".join(met_reasons) + ")"
            else: # Should not happen if should_block is False, but as fallback
                 reason = "No Block: Conditions not fully met"


        # Score is the count of conditions met
        score = float(conditions_met_count)

        # Return the score (0.0, 1.0, 2.0, or 3.0) and the block decision/reason
        return score, should_block, reason
