#!/usr/bin/env python3
import argparse
import re
from datetime import datetime
from collections import defaultdict

def parse_log_line(line):
    """
    Extrae los campos clave de una línea del log usando expresión regular.
    Se asume que el log sigue el formato extendido (CLF extendido).
    """
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<request>[^"]+)" '
        r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]+)" "(?P<useragent>[^"]+)"'
    )
    match = log_pattern.search(line)
    if match:
        return match.groupdict()
    return None

def main():
    parser = argparse.ArgumentParser(
        description='Analiza un archivo de log y genera estadísticas a partir de una fecha dada.'
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
        '--threshold', '-t', type=float, default=100,
        help='Umbral de peticiones por minuto para generar alerta (default: 100).'
    )
    args = parser.parse_args()

    # Definir start_date como None por defecto (analizar todo)
    start_date = None
    
    # Intentar parsear la fecha de inicio solo si fue proporcionada
    if args.start_date:
        try:
            start_date = datetime.strptime(args.start_date, '%d/%b/%Y:%H:%M:%S')
        except ValueError:
            print("Error: Fecha inválida. Use el formato dd/mmm/yyyy:HH:MM:SS (ej. 16/Apr/2025:13:16:50)")
            return

    # Diccionario para acumular datos por IP
    ip_data = defaultdict(lambda: {'times': [], 'urls': [], 'useragents': []})

    try:
        with open(args.file, 'r') as f:
            for line in f:
                data = parse_log_line(line)
                if data is None:
                    continue  # Línea que no coincide con el patrón esperado
                # Obtener la fecha y hora del log. Se asume que el timezone viene después y se omite.
                dt_str = data['datetime'].split()[0]
                try:
                    dt = datetime.strptime(dt_str, '%d/%b/%Y:%H:%M:%S')
                except ValueError:
                    continue  # Saltar entradas con fecha mal formateada
                # Filtrar las entradas anteriores a la fecha indicada solo si se proporcionó una fecha
                if start_date and dt < start_date:
                    continue
                ip = data['ip']
                ip_data[ip]['times'].append(dt)
                ip_data[ip]['urls'].append(data['request'])
                ip_data[ip]['useragents'].append(data['useragent'])
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo {args.file}")
        return

    # Análisis y generación de alertas basadas en la frecuencia y en user-agent
    for ip, info in ip_data.items():
        times = sorted(info['times'])
        total_requests = len(times)
        if total_requests < 2:
            continue  # No es posible calcular intervalos de tiempo si hay menos de dos solicitudes.
        # Calcular el intervalo total (en segundos) entre la primera y la última petición de la IP
        time_span = (times[-1] - times[0]).total_seconds()
        # Calcular peticiones por minuto
        rpm = (total_requests / (time_span / 60)) if time_span > 0 else total_requests

        if rpm > args.threshold:
            print(f"[ALERTA] IP: {ip} - {total_requests} solicitudes en {time_span:.2f} segundos (~{rpm:.2f} rpm)")

        # Revisión del user-agent en busca de patrones que sugieran bot (por ejemplo, 'bot' o 'crawl')
        for ua in info['useragents']:
            if "bot" in ua.lower() or "crawl" in ua.lower():
                print(f"[ALERTA] IP: {ip} usa un user-agent sospechoso: {ua}")
                break

if __name__ == '__main__':
    main()

