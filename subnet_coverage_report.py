#!/usr/bin/env python3
"""
Subnetwork coverage report for bot blocking analysis.

Reads raw web logs, computes subnet metrics with the existing analyzer/strategy,
and reports which high-usage subnets are NOT being blocked and why.
"""
import argparse
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

import psutil

from threat_analyzer import ThreatAnalyzer


LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(level_name):
    """Configure console logging."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(level=level, format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)


def calculate_start_date(time_window):
    """Return local start datetime for a named window."""
    now = datetime.now()
    if time_window == "hour":
        return now - timedelta(hours=1)
    if time_window == "6hour":
        return now - timedelta(hours=6)
    if time_window == "day":
        return now - timedelta(days=1)
    if time_window == "week":
        return now - timedelta(weeks=1)
    return None


def calculate_dynamic_thresholds(cpu_load_percent, base_rpm, base_sustained, max_cpu_load_threshold):
    """Replicate the dynamic threshold logic used by the unified strategy."""
    min_rpm_threshold = float(base_rpm)
    min_sustained_percent = float(base_sustained)

    if cpu_load_percent > max_cpu_load_threshold:
        if cpu_load_percent >= 90.0:
            rpm_factor = 0.25
        else:
            rpm_factor = 0.5 - ((cpu_load_percent - max_cpu_load_threshold) / 10.0) * 0.25

        if cpu_load_percent >= 90.0:
            sustained_factor = 0.25 - ((cpu_load_percent - 90.0) / 10.0) * 0.13
            sustained_factor = max(0.12, sustained_factor)
        else:
            sustained_factor = 0.5 - ((cpu_load_percent - max_cpu_load_threshold) / 10.0) * 0.25

        min_rpm_threshold = base_rpm * rpm_factor
        min_sustained_percent = base_sustained * sustained_factor

    return min_rpm_threshold, min_sustained_percent


def pct(part, whole):
    """Safe percentage helper."""
    if whole <= 0:
        return 0.0
    return (part / whole) * 100.0


def classify_gap(rpm_ok, sustained_ok):
    """Explain why a subnet stayed out of blocking."""
    if not rpm_ok and not sustained_ok:
        return "falla_rpm_y_sostenido"
    if not rpm_ok:
        return "falla_rpm"
    return "falla_sostenido"


def build_report(threats, analysis_duration_seconds, rpm_threshold, sustained_threshold, top_n):
    """Build structured coverage metrics from analyzed subnets."""
    rows = []
    total_requests_all = 0
    total_requests_blockable = 0

    for threat in threats:
        total_requests = int(threat.get("total_requests", 0) or 0)
        rpm = float(threat.get("subnet_req_per_min_window", 0.0) or 0.0)
        time_span = float(threat.get("subnet_time_span", 0.0) or 0.0)
        sustained_percent = pct(time_span, analysis_duration_seconds) if analysis_duration_seconds > 0 else 0.0

        rpm_ok = rpm >= rpm_threshold
        sustained_ok = sustained_percent >= sustained_threshold
        should_block = bool(threat.get("should_block", False))

        rpm_gap_percent = max(0.0, pct(rpm_threshold - rpm, rpm_threshold)) if rpm_threshold > 0 else 0.0
        sustained_gap_percent = (
            max(0.0, pct(sustained_threshold - sustained_percent, sustained_threshold))
            if sustained_threshold > 0 else 0.0
        )

        gate_ratio_rpm = rpm / rpm_threshold if rpm_threshold > 0 else 0.0
        gate_ratio_sustained = sustained_percent / sustained_threshold if sustained_threshold > 0 else 0.0
        gate_ratio = min(gate_ratio_rpm, gate_ratio_sustained)

        row = {
            "subnet": str(threat.get("id")),
            "should_block": should_block,
            "total_requests": total_requests,
            "ip_count": int(threat.get("ip_count", 0) or 0),
            "strategy_score": float(threat.get("strategy_score", 0.0) or 0.0),
            "rpm": rpm,
            "sustained_percent": sustained_percent,
            "rpm_ok": rpm_ok,
            "sustained_ok": sustained_ok,
            "gap_type": classify_gap(rpm_ok, sustained_ok) if not should_block else "bloqueable",
            "rpm_gap_percent": rpm_gap_percent,
            "sustained_gap_percent": sustained_gap_percent,
            "gate_ratio": gate_ratio
        }
        rows.append(row)

        total_requests_all += total_requests
        if should_block:
            total_requests_blockable += total_requests

    outside = [r for r in rows if not r["should_block"]]
    blockable = [r for r in rows if r["should_block"]]

    outside_sorted_by_requests = sorted(outside, key=lambda x: x["total_requests"], reverse=True)
    outside_sorted_by_near_miss = sorted(outside, key=lambda x: x["gate_ratio"], reverse=True)

    outside_total_requests = sum(r["total_requests"] for r in outside)
    outside_gap_counts = {
        "falla_rpm": len([r for r in outside if r["gap_type"] == "falla_rpm"]),
        "falla_sostenido": len([r for r in outside if r["gap_type"] == "falla_sostenido"]),
        "falla_rpm_y_sostenido": len([r for r in outside if r["gap_type"] == "falla_rpm_y_sostenido"])
    }
    outside_gap_requests = {
        k: sum(r["total_requests"] for r in outside if r["gap_type"] == k)
        for k in outside_gap_counts
    }

    report = {
        "summary": {
            "total_subnets": len(rows),
            "blockable_subnets": len(blockable),
            "outside_subnets": len(outside),
            "total_requests": total_requests_all,
            "blockable_requests": total_requests_blockable,
            "outside_requests": outside_total_requests,
            "blockable_requests_percent": pct(total_requests_blockable, total_requests_all),
            "outside_requests_percent": pct(outside_total_requests, total_requests_all),
            "outside_gap_counts": outside_gap_counts,
            "outside_gap_requests": outside_gap_requests
        },
        "top_outside_by_requests": outside_sorted_by_requests[:top_n],
        "top_outside_near_miss": outside_sorted_by_near_miss[:top_n]
    }
    return report


def print_report(report, rpm_threshold, sustained_threshold, cpu_load_percent):
    """Print a human-readable report."""
    summary = report["summary"]
    top_usage = report["top_outside_by_requests"]
    top_near = report["top_outside_near_miss"]

    print("\n=== INFORME DE COBERTURA DE SUBREDES ===")
    print(f"Umbral RPM efectivo: {rpm_threshold:.2f} req/min")
    print(f"Umbral sostenido efectivo: {sustained_threshold:.2f}%")
    print(f"Carga CPU normalizada usada: {cpu_load_percent:.1f}%")

    print("\n--- Resumen global ---")
    print(f"Subredes analizadas: {summary['total_subnets']}")
    print(f"Subredes bloqueables: {summary['blockable_subnets']}")
    print(f"Subredes fuera de bloqueo: {summary['outside_subnets']}")
    print(f"Requests totales: {summary['total_requests']}")
    print(
        f"Requests cubiertos por bloqueo: {summary['blockable_requests']} "
        f"({summary['blockable_requests_percent']:.1f}%)"
    )
    print(
        f"Requests fuera de bloqueo: {summary['outside_requests']} "
        f"({summary['outside_requests_percent']:.1f}%)"
    )

    print("\n--- Que queda fuera (conteo de subredes) ---")
    print(f"Falla solo RPM: {summary['outside_gap_counts']['falla_rpm']}")
    print(f"Falla solo sostenido: {summary['outside_gap_counts']['falla_sostenido']}")
    print(f"Falla ambas condiciones: {summary['outside_gap_counts']['falla_rpm_y_sostenido']}")

    print("\n--- Que queda fuera (volumen de requests) ---")
    print(f"Por falla solo RPM: {summary['outside_gap_requests']['falla_rpm']}")
    print(f"Por falla solo sostenido: {summary['outside_gap_requests']['falla_sostenido']}")
    print(f"Por falla ambas: {summary['outside_gap_requests']['falla_rpm_y_sostenido']}")

    print("\n--- Top subredes fuera por uso ---")
    if not top_usage:
        print("No hay subredes fuera de bloqueo en la ventana analizada.")
    else:
        for idx, row in enumerate(top_usage, 1):
            print(
                f"{idx}. {row['subnet']} | req={row['total_requests']} | "
                f"rpm={row['rpm']:.2f} | sust={row['sustained_percent']:.2f}% | "
                f"gap={row['gap_type']} | brecha_rpm={row['rpm_gap_percent']:.1f}% | "
                f"brecha_sost={row['sustained_gap_percent']:.1f}%"
            )

    print("\n--- Top subredes casi bloqueables (near miss) ---")
    if not top_near:
        print("No hay subredes fuera de bloqueo en la ventana analizada.")
    else:
        for idx, row in enumerate(top_near, 1):
            print(
                f"{idx}. {row['subnet']} | gate_ratio={row['gate_ratio']:.2f} | "
                f"req={row['total_requests']} | gap={row['gap_type']}"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Genera informe de cobertura: subredes con mas uso que quedan fuera de bloqueo.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--file", "-f", required=True, help="Ruta del log a analizar.")
    parser.add_argument(
        "--time-window", "-tw", default="hour", choices=["hour", "6hour", "day", "week"],
        help="Ventana temporal a analizar."
    )
    parser.add_argument(
        "--start-date", "-s", default=None,
        help="Fecha inicial manual (dd/Mmm/YYYY:HH:MM:SS). Ignorada si se usa --time-window."
    )
    parser.add_argument("--whitelist", "-w", help="Archivo de whitelist de IPs/subredes.")
    parser.add_argument("--top", "-n", type=int, default=15, help="Cantidad de subredes a mostrar por ranking.")
    parser.add_argument("--min-rpm-threshold", type=float, default=10.0, help="Umbral base RPM.")
    parser.add_argument("--min-sustained-percent", type=float, default=25.0, help="Umbral base sostenido (%%).")
    parser.add_argument(
        "--max-cpu-load-threshold", type=float, default=80.0,
        help="Carga CPU (%%) desde donde se bajan umbrales dinamicamente."
    )
    parser.add_argument("--output", "-o", help="Archivo para exportar el informe (JSON).")
    parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], default="INFO",
        help="Nivel de logs internos."
    )

    args = parser.parse_args()
    setup_logging(args.log_level)
    logger = logging.getLogger("coverage_report")

    if not os.path.exists(args.file):
        logger.error("No se encontro el log: %s", args.file)
        sys.exit(1)

    now_utc = datetime.now(timezone.utc)
    start_date_utc = None

    if args.time_window:
        start_date_local = calculate_start_date(args.time_window)
        start_date_utc = start_date_local.astimezone().astimezone(timezone.utc)
    elif args.start_date:
        try:
            start_naive = datetime.strptime(args.start_date, "%d/%b/%Y:%H:%M:%S")
            start_date_utc = start_naive.astimezone().astimezone(timezone.utc)
        except ValueError:
            logger.error("Formato invalido en --start-date. Usa dd/Mmm/YYYY:HH:MM:SS")
            sys.exit(1)

    analysis_duration_seconds = (
        max(0.0, (now_utc - start_date_utc).total_seconds()) if start_date_utc else 0.0
    )
    logger.info("Duracion de analisis: %.0fs", analysis_duration_seconds)

    analyzer = ThreatAnalyzer(whitelist=None)
    if args.whitelist:
        analyzer.load_whitelist_from_file(args.whitelist)

    total_requests = analyzer.analyze_log_file(args.file, start_date_utc=start_date_utc)
    if total_requests < 0:
        logger.error("Fallo el analisis del log.")
        sys.exit(1)
    if total_requests == 0:
        print("No hay entradas validas para analizar en la ventana seleccionada.")
        sys.exit(0)

    cpu_load_percent = 0.0
    try:
        load_avg_1min = psutil.getloadavg()[0]
        cpu_count = psutil.cpu_count() or 1
        cpu_load_percent = (load_avg_1min / cpu_count) * 100.0
    except Exception as exc:
        logger.warning("No se pudo calcular carga CPU. Se usara 0%%. Detalle: %s", exc)

    shared_context = {
        "analysis_duration_seconds": analysis_duration_seconds,
        "total_overall_requests": total_requests,
        "system_load_avg": -1.0,
        "cpu_load_percent": cpu_load_percent
    }

    threats = analyzer.identify_threats(
        strategy_name="unified",
        shared_context_params=shared_context,
        config=args
    )
    if threats is None:
        logger.error("No se pudo calcular amenazas/subredes.")
        sys.exit(1)

    eff_rpm, eff_sustained = calculate_dynamic_thresholds(
        cpu_load_percent=cpu_load_percent,
        base_rpm=args.min_rpm_threshold,
        base_sustained=args.min_sustained_percent,
        max_cpu_load_threshold=args.max_cpu_load_threshold
    )

    report = build_report(
        threats=threats,
        analysis_duration_seconds=analysis_duration_seconds,
        rpm_threshold=eff_rpm,
        sustained_threshold=eff_sustained,
        top_n=max(1, args.top)
    )

    print_report(report, eff_rpm, eff_sustained, cpu_load_percent)

    if args.output:
        payload = {
            "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "input": {
                "file": args.file,
                "time_window": args.time_window,
                "analysis_duration_seconds": analysis_duration_seconds
            },
            "effective_thresholds": {
                "rpm": eff_rpm,
                "sustained_percent": eff_sustained,
                "cpu_load_percent": cpu_load_percent
            },
            "report": report
        }
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
            print(f"\nInforme exportado a: {args.output}")
        except Exception as exc:
            logger.error("No se pudo escribir el archivo de salida: %s", exc)
            sys.exit(1)


if __name__ == "__main__":
    main()
