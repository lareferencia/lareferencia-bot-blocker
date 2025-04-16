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

def get_subnet(ip):
    """
    Extrae los dos primeros octetos de la dirección IP para determinar la subred.
    """
    octets = ip.split('.')
    if len(octets) >= 2:
        return '.'.join(octets[:2])
    return ip  # En caso de formato IP no estándar, devuelve la IP completa

def calculate_danger_score(rpm, total_requests, has_suspicious_ua):
    """
    Calcula una puntuación de peligrosidad basada en el RPM, total de solicitudes
    y si tiene un user-agent sospechoso.
    """
    # Factor base es el RPM normalizado por el umbral
    score = rpm / 100
    
    # Factores adicionales
    if has_suspicious_ua:
        score *= 1.5  # Incremento por user-agent sospechoso
    
    # Número total de solicitudes también aumenta la peligrosidad
    score += total_requests / 1000
    
    return score

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

    # Estructura para agrupar por subred
    subnet_data = defaultdict(list)
    
    # Análisis y generación de alertas basadas en la frecuencia y en user-agent
    suspicious_ips = []
    for ip, info in ip_data.items():
        times = sorted(info['times'])
        total_requests = len(times)
        if total_requests < 2:
            continue  # No es posible calcular intervalos de tiempo si hay menos de dos solicitudes.
        
        # Calcular el intervalo total (en segundos) entre la primera y la última petición de la IP
        time_span = (times[-1] - times[0]).total_seconds()
        # Calcular peticiones por minuto
        rpm = (total_requests / (time_span / 60)) if time_span > 0 else total_requests

        # Verificar si hay user-agent sospechoso
        has_suspicious_ua = False
        suspicious_ua = ""
        for ua in info['useragents']:
            if "bot" in ua.lower() or "crawl" in ua.lower():
                has_suspicious_ua = True
                suspicious_ua = ua
                break
        
        # Determinar si esta IP es sospechosa
        is_suspicious = rpm > args.threshold or has_suspicious_ua
        
        if is_suspicious:
            # Calcular peligrosidad
            danger_score = calculate_danger_score(rpm, total_requests, has_suspicious_ua)
            
            # Obtener la subred
            subnet = get_subnet(ip)
            
            # Guardar datos para análisis agrupado
            subnet_data[subnet].append({
                'ip': ip,
                'rpm': rpm,
                'total_requests': total_requests,
                'time_span': time_span,
                'has_suspicious_ua': has_suspicious_ua,
                'suspicious_ua': suspicious_ua,
                'danger_score': danger_score
            })
    
    # Mostrar resultados agrupados por subred y ordenados por peligrosidad
    print("\n=== RESULTADOS AGRUPADOS POR SUBRED ===\n")
    
    # Ordenar subredes por la suma de peligrosidad de sus IPs
    sorted_subnets = sorted(
        subnet_data.items(),
        key=lambda x: sum(ip_info['danger_score'] for ip_info in x[1]),
        reverse=True
    )
    
    for subnet, ip_infos in sorted_subnets:
        # Ordenar IPs dentro de esta subred por peligrosidad
        sorted_ips = sorted(ip_infos, key=lambda x: x['danger_score'], reverse=True)
        
        print(f"\n== Subred: {subnet}.* ({len(sorted_ips)} IPs sospechosas) ==")
        
        for ip_info in sorted_ips:
            ip = ip_info['ip']
            rpm = ip_info['rpm']
            total_requests = ip_info['total_requests']
            time_span = ip_info['time_span']
            danger_score = ip_info['danger_score']
            
            print(f"[ALERTA] IP: {ip} - Peligrosidad: {danger_score:.2f}")
            print(f"  • {total_requests} solicitudes en {time_span:.2f} segundos (~{rpm:.2f} rpm)")
            
            if ip_info['has_suspicious_ua']:
                print(f"  • User-Agent sospechoso: {ip_info['suspicious_ua']}")

if __name__ == '__main__':
    main()

