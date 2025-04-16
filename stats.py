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
    parser.add_argument(
        '--top', '-n', type=int, default=10,
        help='Número de subredes más peligrosas a mostrar (default: 10).'
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
    
    # Calcular la puntuación total de peligrosidad para cada subred
    subnet_total_scores = {}
    subnet_ip_count = {}
    for subnet, ip_infos in subnet_data.items():
        subnet_total_scores[subnet] = sum(ip_info['danger_score'] for ip_info in ip_infos)
        subnet_ip_count[subnet] = len(ip_infos)
    
    # Crear una lista unificada de amenazas (tanto IPs individuales como subredes)
    unified_threats = []
    
    # Agregar amenazas de subredes con múltiples IPs
    for subnet, ip_infos in subnet_data.items():
        if len(ip_infos) > 1:  # Es una subred con múltiples IPs
            unified_threats.append({
                'type': 'subnet',
                'id': subnet,
                'danger_score': subnet_total_scores[subnet],
                'ip_count': len(ip_infos),
                'details': ip_infos
            })
    
    # Agregar IPs individuales como amenazas separadas
    for subnet, ip_infos in subnet_data.items():
        if len(ip_infos) == 1:  # Es una IP individual
            ip_info = ip_infos[0]
            unified_threats.append({
                'type': 'ip',
                'id': ip_info['ip'],
                'danger_score': ip_info['danger_score'],
                'rpm': ip_info['rpm'],
                'total_requests': ip_info['total_requests'],
                'time_span': ip_info['time_span'],
                'has_suspicious_ua': ip_info['has_suspicious_ua'],
                'suspicious_ua': ip_info['suspicious_ua'] if ip_info['has_suspicious_ua'] else ""
            })
    
    # Ordenar la lista unificada por peligrosidad
    sorted_threats = sorted(unified_threats, key=lambda x: x['danger_score'], reverse=True)
    
    # Comprobar si hay amenazas para mostrar
    if not sorted_threats:
        print("\nNo se encontraron amenazas sospechosas según los criterios especificados.")
        return
    
    # Mostrar resultados ordenados por peligrosidad
    top_count = min(args.top, len(sorted_threats))
    print(f"\n=== TOP {top_count} AMENAZAS MÁS PELIGROSAS ===\n")
    
    # Tomar solo las primeras 'top' amenazas
    top_threats = sorted_threats[:args.top]
    
    for i, threat in enumerate(top_threats, 1):
        if threat['type'] == 'subnet':
            subnet = threat['id']
            danger_score = threat['danger_score']
            ip_count = threat['ip_count']
            
            print(f"\n#{i} Subred: {subnet}.* - Peligrosidad total: {danger_score:.2f} ({ip_count} IPs sospechosas)")
            
            # Mostrar las IPs más peligrosas de esta subred
            sorted_ips = sorted(threat['details'], key=lambda x: x['danger_score'], reverse=True)
            for ip_info in sorted_ips[:5]:  # Mostrar hasta 5 IPs por subred para no sobrecargar la salida
                ip = ip_info['ip']
                rpm = ip_info['rpm']
                total_requests = ip_info['total_requests']
                time_span = ip_info['time_span']
                danger_score = ip_info['danger_score']
                
                print(f"[ALERTA] IP: {ip} - Peligrosidad: {danger_score:.2f}")
                print(f"  • {total_requests} solicitudes en {time_span:.2f} segundos (~{rpm:.2f} rpm)")
                
                if ip_info['has_suspicious_ua']:
                    print(f"  • User-Agent sospechoso: {ip_info['suspicious_ua']}")
            
            if len(sorted_ips) > 5:
                print(f"  ... y {len(sorted_ips) - 5} IPs más en esta subred")
                
        else:  # threat['type'] == 'ip'
            ip = threat['id']
            danger_score = threat['danger_score']
            rpm = threat['rpm']
            total_requests = threat['total_requests']
            time_span = threat['time_span']
            
            print(f"\n#{i} IP individual: {ip} - Peligrosidad: {danger_score:.2f}")
            print(f"  • {total_requests} solicitudes en {time_span:.2f} segundos (~{rpm:.2f} rpm)")
            
            if threat['has_suspicious_ua']:
                print(f"  • User-Agent sospechoso: {threat['suspicious_ua']}")

if __name__ == '__main__':
    main()

