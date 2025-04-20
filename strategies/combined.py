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
from .base_strategy import BaseStrategy

logger = logging.getLogger("botstats.strategy.combined")

# Porcentaje mínimo de la ventana que debe cubrir la actividad del rango
TIME_SPAN_PERCENTAGE_THRESHOLD = 50.0  # 50 %

class Strategy(BaseStrategy):
    """Estrategia de bloqueo multidimensional."""

    # ----- Configuración requerida -------------------------------------------------
    def get_required_config_keys(self):
        # Retorna la lista de flags que esperamos encontrar en args
        return super().get_required_config_keys() + [
            "block_ip_count_threshold",         # IPs mínimas en la subred
            "block_max_rpm_threshold",          # Pico RPM por IP
            "block_total_max_rpm_threshold",    # Pico RPM combinado del rango
            "block_trigger_count"               # Disparadores que deben cumplirse
        ]

    # ----- Cálculo de score y decisión de bloqueo ----------------------------------
    def calculate_threat_score_and_block(
        self,
        threat_data,
        config,
        effective_min_requests,
        analysis_duration_seconds=None,
        max_total_requests=None,
        max_subnet_time_span=None,
    ):
        """Devuelve `(score, should_block, reason)` para la subred dada."""

        # --- Métricas extraídas ----------------------------------------------------
        total_requests      = threat_data.get("total_requests", 0)
        ip_count            = threat_data.get("ip_count", 0)
        max_ip_rpm          = threat_data.get("subnet_max_ip_rpm", 0)
        total_max_rpm       = threat_data.get("subnet_total_max_rpm", 0)
        subnet_time_span    = threat_data.get("subnet_time_span", 0)  # segundos

        # --- Normalización para el score -----------------------------------------
        # Evitar divisiones por cero
        def _safe_div(a, b):
            return a / b if b else 0.0

        norm_requests   = _safe_div(total_requests, max_total_requests)
        norm_ip_count   = _safe_div(ip_count, getattr(config, "block_ip_count_threshold", 1) * 2)
        norm_max_ip_rpm = _safe_div(max_ip_rpm, getattr(config, "block_max_rpm_threshold", 1) * 2)
        norm_total_rpm  = _safe_div(total_max_rpm, getattr(config, "block_total_max_rpm_threshold", 1) * 2)
        norm_timespan   = _safe_div(subnet_time_span, max_subnet_time_span)

        # Ponderación igualitaria (puedes ajustar)
        score = (
            0.2 * norm_requests +
            0.2 * norm_ip_count +
            0.2 * norm_max_ip_rpm +
            0.2 * norm_total_rpm +
            0.2 * norm_timespan
        )

        # --- Reglas de bloqueo -----------------------------------------------------
        triggers_met = []  # Mantiene textos para la razón

        # 1. Volumen base (obligatorio)
        if total_requests < effective_min_requests:
            logger.debug(
                f"Subnet {threat_data['id']} por debajo del umbral de volumen "
                f"({total_requests} < {effective_min_requests}).")
            return score, False, None  # Descarta sin bloquear

        # 2. Disparadores adicionales
        ip_threshold = getattr(config, "block_ip_count_threshold", 10)
        if ip_count >= ip_threshold:
            triggers_met.append(f"IP Count {ip_count}≥{ip_threshold}")

        max_rpm_threshold = getattr(config, "block_max_rpm_threshold", 60)
        if max_ip_rpm >= max_rpm_threshold:
            triggers_met.append(f"Max IP RPM {max_ip_rpm:.0f}≥{max_rpm_threshold}")

        total_rpm_threshold = getattr(config, "block_total_max_rpm_threshold", 120)
        if total_max_rpm >= total_rpm_threshold:
            triggers_met.append(
                f"Peak Subnet RPM {total_max_rpm:.0f}≥{total_rpm_threshold}")

        # Timespan solo si hay ventana definida
        timespan_percentage = 0.0
        if analysis_duration_seconds and analysis_duration_seconds > 0:
            timespan_percentage = _safe_div(subnet_time_span, analysis_duration_seconds) * 100
            if timespan_percentage >= TIME_SPAN_PERCENTAGE_THRESHOLD:
                triggers_met.append(
                    f"Timespan {timespan_percentage:.1f}%≥{TIME_SPAN_PERCENTAGE_THRESHOLD}%")

        # 3. Veredicto final
        trigger_req = getattr(config, "block_trigger_count", 2)
        should_block = len(triggers_met) >= trigger_req
        reason = None
        if should_block:
            reason = ", ".join(triggers_met[:3])  # limita longitud
        else:
            logger.debug(
                f"Subnet {threat_data['id']} no cumple el mínimo de "
                f"{trigger_req} disparadores ({len(triggers_met)} alcanzados).")

        return score, should_block, reason
