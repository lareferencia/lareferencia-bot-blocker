#!/usr/bin/env python3
"""
Módulo para parsear y analizar logs de servidores web.
Tiene funciones para extraer información relevante de logs en formato CLF o CLF extendido.
"""
import re
from datetime import datetime
import ipaddress

def parse_log_line(line):
    """
    Extrae los campos clave de una línea del log usando expresión regular.
    Se asume que el log sigue el formato extendido (CLF extendido).
    
    Args:
        line (str): Línea del archivo de log a parsear
        
    Returns:
        dict: Diccionario con los campos extraídos o None si la línea no coincide con el patrón
    """
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<request>[^"]+)" '
        r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]+)" "(?P<useragent>[^"]+)"'
    )
    match = log_pattern.search(line)
    if match:
        return match.groupdict()
    return None

def get_subnet(ip_str, version=None):
    """
    Devuelve la subred como un objeto ipaddress.ip_network.
    Para IPv4 devuelve una red /24, para IPv6 devuelve una red /64.
    
    Args:
        ip_str (str): Dirección IP en formato string
        version (int, optional): Versión IP a forzar (4 o 6). Default: None (auto-detectar)
        
    Returns:
        ipaddress.ip_network: Objeto representando la subred, o None si la IP no es válida
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # Si se especifica una versión, verificar que la IP coincida
        if version and ip.version != version:
            return None
            
        if ip.version == 4:
            # Crea la red /24 sin verificar si la IP es la dirección de red
            return ipaddress.ip_network(f"{ip_str}/24", strict=False)
        elif ip.version == 6:
            # Para IPv6 usamos /64 que es común para subredes
            return ipaddress.ip_network(f"{ip_str}/64", strict=False)
    except ValueError:
        return None
    
    return None  # Caso no manejado (no debería llegar aquí)

def calculate_danger_score(rpm, total_requests, has_suspicious_ua):
    """
    Calcula una puntuación de peligrosidad basada en el RPM, total de solicitudes
    y si tiene un user-agent sospechoso.
    
    Args:
        rpm (float): Peticiones por minuto
        total_requests (int): Total de peticiones
        has_suspicious_ua (bool): Si tiene un user-agent sospechoso
        
    Returns:
        float: Puntuación de peligrosidad
    """
    # Factor base es el RPM normalizado por el umbral
    score = rpm / 100
    
    # Factores adicionales
    if has_suspicious_ua:
        score *= 1.5  # Incremento por user-agent sospechoso
    
    # Número total de solicitudes también aumenta la peligrosidad
    score += total_requests / 1000
    
    return score

def process_log_in_chunks(filename, handler_func, chunk_size=10000, **kwargs):
    """
    Procesa el archivo de log en segmentos para reducir uso de memoria.
    
    Args:
        filename (str): Ruta del archivo de log
        handler_func (callable): Función que procesa cada chunk de líneas
        chunk_size (int): Tamaño del chunk en número de líneas
        **kwargs: Argumentos adicionales a pasar a handler_func
        
    Returns:
        Any: El resultado de la última llamada a handler_func
    """
    result = None
    with open(filename, 'r') as f:
        chunk = []
        for i, line in enumerate(f):
            chunk.append(line)
            if i % chunk_size == chunk_size - 1:
                result = handler_func(chunk, **kwargs)
                chunk = []
        # Procesar el último segmento si existe
        if chunk:
            result = handler_func(chunk, **kwargs)
    return result

def is_ip_in_whitelist(ip, whitelist):
    """
    Verifica si una IP está en la lista blanca.
    
    Args:
        ip (str): La dirección IP a verificar
        whitelist (list): Lista de IPs o subredes en formato string
        
    Returns:
        bool: True si la IP está en la lista blanca, False en caso contrario
    """
    if not whitelist:
        return False
        
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        for item in whitelist:
            try:
                # Si el item es una red, verificar si la IP está contenida
                if '/' in item:
                    network = ipaddress.ip_network(item, strict=False)
                    if ip_obj in network:
                        return True
                # Si es una IP exacta
                else:
                    whitelist_ip = ipaddress.ip_address(item)
                    if ip_obj == whitelist_ip:
                        return True
            except ValueError:
                continue
    except ValueError:
        return False
        
    return False