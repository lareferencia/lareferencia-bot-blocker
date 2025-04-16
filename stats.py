#!/usr/bin/env python3
"""
Script principal para análisis de logs y detección de amenazas de bots.
Detecta patrones sospechosos y puede bloquear IPs mediante UFW.

Uso:
    python stats.py -f /ruta/a/archivo.log [opciones]
"""
import argparse
import re
from datetime import datetime, timedelta, timezone
import sys
import os
import logging
import ipaddress

# Importar módulos propios
from log_parser import parse_log_line, get_subnet, is_ip_in_whitelist
from ufw_handler import UFWManager
from threat_analyzer import ThreatAnalyzer

# Configuración de logging
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

def setup_logging(log_file=None, log_level=logging.INFO):
    """
    Configura el sistema de logging.
    
    Args:
        log_file (str, optional): Ruta al archivo de log
        log_level (int): Nivel de logging
    """
    handlers = []
    
    # Siempre añadir handler de consola
    console = logging.StreamHandler()
    console.setLevel(log_level)
    console.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
    handlers.append(console)
    
    # Añadir handler de archivo si se especifica
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
        handlers.append(file_handler)
    
    # Configurar logger raíz
    logging.basicConfig(
        level=log_level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        handlers=handlers
    )

def calculate_start_date(time_window):
    """
    Calcula la fecha de inicio según la ventana de tiempo especificada.
    
    Args:
        time_window (str): 'hour', 'day', o 'week'
    
    Returns:
        datetime: Objeto datetime correspondiente a la fecha de inicio
    """
    now = datetime.now()
    if time_window == 'hour':
        return now - timedelta(hours=1)
    elif time_window == 'day':
        return now - timedelta(days=1)
    elif time_window == 'week':
        return now - timedelta(weeks=1)
    return None

def main():
    parser = argparse.ArgumentParser(
        description='Analiza un archivo de log, genera estadísticas y opcionalmente bloquea amenazas con UFW.'
    )
    parser.add_argument(
        '--file', '-f', required=True,
        help='Ruta del archivo de log a analizar.'
    )
    parser.add_argument(
        '--start-date', '-s', required=False, default=None,
        help='Fecha a partir de la cual se analiza el log. Formato: dd/mmm/yyyy:HH:MM:SS (ej. 16/Apr/2025:13:16:50). Si no se proporciona, analiza todos los registros.'
    )
    parser.add_argument(
        '--time-window', '-tw', required=False,
        choices=['hour', 'day', 'week'],
        help='Analizar solo entradas de la última hora, día o semana.'
    )
    parser.add_argument(
        '--threshold', '-t', type=float, default=100,
        help='Umbral de peticiones por minuto (RPM) para considerar una IP sospechosa (default: 100).'
    )
    parser.add_argument(
        '--top', '-n', type=int, default=10,
        help='Número de amenazas más peligrosas a mostrar (default: 10).'
    )
    parser.add_argument(
        '--block', action='store_true',
        help='Activar el bloqueo de amenazas detectadas usando UFW.'
    )
    parser.add_argument(
        '--block-threshold', type=int, default=10,
        help='Umbral de *peticiones totales* en el periodo analizado para activar el bloqueo UFW (default: 10).'
    )
    parser.add_argument(
        '--block-duration', type=int, default=60,
        help='Duración del bloqueo UFW en minutos (default: 60).'
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Mostrar los comandos UFW que se ejecutarían, pero no ejecutarlos.'
    )
    parser.add_argument(
        '--whitelist', '-w',
        help='Archivo con lista de IPs o subredes que nunca deben ser bloqueadas (una por línea).'
    )
    parser.add_argument(
        '--output', '-o',
        help='Archivo para guardar los resultados del análisis.'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'csv', 'text'],
        default='text',
        help='Formato de salida cuando se usa --output (default: text).'
    )
    parser.add_argument(
        '--log-file',
        help='Archivo donde guardar los logs de ejecución.'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Nivel de detalle de los logs (default: INFO).'
    )
    parser.add_argument(
        '--chunk-size', type=int, default=10000,
        help='Tamaño del fragmento para procesar logs grandes (default: 10000, 0 para no fragmentar).'
    )
    parser.add_argument(
        '--clean-rules', action='store_true',
        help='Ejecutar limpieza de reglas UFW expiradas y salir.'
    )
    args = parser.parse_args()

    # Configurar logging
    log_level = getattr(logging, args.log_level)
    setup_logging(args.log_file, log_level)
    logger = logging.getLogger('botstats.main')
    
    # Si solo queremos limpiar reglas, hacerlo y salir
    if args.clean_rules:
        logger.info("Iniciando limpieza de reglas UFW expiradas...")
        ufw = UFWManager(args.dry_run)
        count = ufw.clean_expired_rules()
        logger.info(f"Limpieza finalizada. {count} reglas eliminadas.")
        return
    
    # Validar archivo de log
    if not os.path.exists(args.file):
        logger.error(f"Error: No se encontró el archivo {args.file}")
        sys.exit(1)
        
    # Definir start_date
    start_date = None
    
    # Priorizar --time-window sobre --start-date si ambos están presentes
    if args.time_window:
        start_date = calculate_start_date(args.time_window)
        logger.info(f"Usando ventana de tiempo: {args.time_window} (desde {start_date})")
    elif args.start_date:
        try:
            start_date = datetime.strptime(args.start_date, '%d/%b/%Y:%H:%M:%S')
            logger.info(f"Usando fecha de inicio: {start_date}")
        except ValueError:
            logger.error("Error: Fecha inválida. Use el formato dd/mmm/yyyy:HH:MM:SS (ej. 16/Apr/2025:13:16:50)")
            sys.exit(1)
    
    # Inicializar analizador
    analyzer = ThreatAnalyzer(rpm_threshold=args.threshold)
    
    # Cargar lista blanca si se especificó
    whitelist_count = 0
    if args.whitelist:
        whitelist_count = analyzer.load_whitelist_from_file(args.whitelist)
        if whitelist_count == 0:
            logger.warning(f"No se pudieron cargar entradas de la lista blanca desde {args.whitelist}")
    
    # Analizar archivo de log
    logger.info(f"Iniciando análisis de {args.file}...")
    try:
        analyzer.analyze_log_file(args.file, start_date, args.chunk_size)
    except Exception as e:
        logger.error(f"Error analizando archivo de log: {e}")
        sys.exit(1)
    
    # Identificar amenazas
    threats = analyzer.identify_threats()
    
    # Verificar si hay amenazas
    if not threats:
        logger.info("No se encontraron amenazas sospechosas según los criterios especificados.")
        if args.block:
            logger.info("No se ejecutaron acciones de bloqueo.")
        sys.exit(0)
    
    # Inicializar UFW manager si se requiere bloqueo
    ufw = None
    if args.block:
        ufw = UFWManager(args.dry_run)
    
    # Bloquear amenazas si se activó la opción
    blocked_targets = set()
    if args.block:
        for threat in threats:
            target = threat['id']
            total_requests = threat['total_requests']
            # Verificar umbral para bloqueo
            should_block = total_requests >= args.block_threshold
            if should_block and target not in blocked_targets:
                if ufw.block_target(target, args.block_duration):
                    blocked_targets.add(target)
    
    # Mostrar resultados en consola
    top_count = min(args.top, len(threats))
    print(f"\n=== TOP {top_count} AMENAZAS MÁS PELIGROSAS DETECTADAS ===")
    if args.block:
        action = "Bloqueadas" if not args.dry_run else "[DRY RUN] Marcadas para bloquear"
        print(f"--- {action} según --block-threshold={args.block_threshold} peticiones totales y --block-duration={args.block_duration} min ---")

    # Tomar solo las primeras 'top' amenazas para el reporte detallado
    top_threats_report = threats[:top_count]

    for i, threat in enumerate(top_threats_report, 1):
        target_id_str = str(threat['id'])
        if threat['type'] == 'subnet':
            print(f"\n#{i} Subred: {target_id_str} - Peligrosidad total: {threat['danger_score']:.2f} ({threat['ip_count']} IPs, {threat['total_requests']} reqs)")
            # Mostrar detalles de las IPs más peligrosas dentro de la subred
            for ip_detail in threat['details'][:3]:  # Mostrar hasta 3 IPs
                rpm_str = f"~{ip_detail['rpm']:.2f} rpm" if ip_detail['is_suspicious_by_rpm'] else "RPM bajo umbral"
                ua_str = f" | UA: {ip_detail['suspicious_ua']}" if ip_detail['has_suspicious_ua'] else ""
                print(f"  -> IP: {ip_detail['ip']} ({ip_detail['total_requests']} reqs, Peligro: {ip_detail['danger_score']:.2f}, {rpm_str}{ua_str})")
            if threat['ip_count'] > 3:
                print(f"  ... y {threat['ip_count'] - 3} IPs más en esta subred.")
        else:  # threat['type'] == 'ip'
            rpm_str = f"~{threat['rpm']:.2f} rpm" if threat['is_suspicious_by_rpm'] else "RPM bajo umbral"
            ua_str = f" | UA: {threat['suspicious_ua']}" if threat['has_suspicious_ua'] else ""
            print(f"\n#{i} IP: {target_id_str} - Peligrosidad: {threat['danger_score']:.2f} ({threat['total_requests']} reqs, {rpm_str}{ua_str})")

        # Indicar si esta amenaza específica fue bloqueada
        if args.block and threat['id'] in blocked_targets:
            block_status = "[BLOQUEADA]" if not args.dry_run else "[DRY RUN - BLOQUEAR]"
            print(f"  {block_status}")
    
    # Exportar resultados si se especificó
    if args.output:
        if analyzer.export_results(args.format, args.output):
            logger.info(f"Resultados exportados a {args.output} en formato {args.format}")
        else:
            logger.error(f"Error exportando resultados a {args.output}")
    
    # Ejecutar limpieza de reglas expiradas
    if args.block:
        logger.info("Ejecutando limpieza de reglas UFW expiradas...")
        if ufw:
            count = ufw.clean_expired_rules()
            if count > 0:
                logger.info(f"Limpieza finalizada. {count} reglas eliminadas.")

    # Mostrar resumen final
    print(f"\nAnálisis completado. {len(blocked_targets)} objetivos únicos {'bloqueados' if not args.dry_run else 'marcados para bloquear'} en esta ejecución.")
    print(f"De un total de {len(threats)} amenazas detectadas.")
    if args.block:
        print(f"Use --clean-rules para eliminar reglas expiradas en el futuro.")

if __name__ == '__main__':
    main()

