#!/usr/bin/env python3
"""
Módulo para análisis y detección de amenazas basado en logs de servidores.
"""
import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta
import logging
import json
import csv
import os

from log_parser import parse_log_line, get_subnet, calculate_danger_score, is_ip_in_whitelist, process_log_in_chunks

# Logger para este módulo
logger = logging.getLogger('botstats.analyzer')

class ThreatAnalyzer:
    """
    Clase para analizar logs y detectar amenazas potenciales.
    """
    
    def __init__(self, rpm_threshold=100, whitelist=None):
        """
        Inicializa el analizador de amenazas.
        
        Args:
            rpm_threshold (float): Umbral de peticiones por minuto para considerar sospechosa una IP
            whitelist (list): Lista de IPs o subredes que nunca deben ser bloqueadas
        """
        self.rpm_threshold = rpm_threshold
        self.whitelist = whitelist or []
        self.ip_data = defaultdict(lambda: {'times': [], 'urls': [], 'useragents': []})
        self.subnet_data = defaultdict(list)
        self.unified_threats = []
        self.blocked_targets = set()
        
    def load_whitelist_from_file(self, whitelist_file):
        """
        Carga una lista blanca desde un archivo.
        
        Args:
            whitelist_file (str): Ruta al archivo con la lista blanca
            
        Returns:
            int: Número de entradas cargadas
        """
        if not os.path.exists(whitelist_file):
            logger.error(f"Archivo de whitelist no encontrado: {whitelist_file}")
            return 0
            
        try:
            with open(whitelist_file, 'r') as f:
                # Filtrar líneas vacías y comentarios
                self.whitelist = [
                    line.strip() for line in f 
                    if line.strip() and not line.strip().startswith('#')
                ]
            logger.info(f"Lista blanca cargada con {len(self.whitelist)} entradas desde {whitelist_file}")
            return len(self.whitelist)
        except Exception as e:
            logger.error(f"Error cargando lista blanca desde {whitelist_file}: {e}")
            return 0
    
    def _process_chunk(self, lines, start_date=None):
        """
        Procesa un fragmento de líneas de log.
        
        Args:
            lines (list): Lista de líneas de log
            start_date (datetime, optional): Fecha a partir de la cual analizar
            
        Returns:
            int: Número de líneas procesadas
        """
        processed = 0
        for line in lines:
            data = parse_log_line(line)
            if data is None:
                continue
                
            # Obtener la fecha y hora del log
            dt_str = data['datetime'].split()[0]
            try:
                dt = datetime.strptime(dt_str, '%d/%b/%Y:%H:%M:%S')
            except ValueError:
                continue  # Saltar entradas con fecha mal formateada
                
            # Filtrar por fecha
            if start_date and dt < start_date:
                continue
                
            ip = data['ip']
            
            # Verificar lista blanca
            if is_ip_in_whitelist(ip, self.whitelist):
                continue
                
            # Acumular datos
            self.ip_data[ip]['times'].append(dt)
            self.ip_data[ip]['urls'].append(data['request'])
            self.ip_data[ip]['useragents'].append(data['useragent'])
            processed += 1
            
        return processed
            
    def analyze_log_file(self, log_file, start_date=None, chunk_size=10000):
        """
        Analiza un archivo de log completo.
        
        Args:
            log_file (str): Ruta al archivo de log
            start_date (datetime, optional): Fecha a partir de la cual analizar
            chunk_size (int): Tamaño del fragmento para procesamiento por lotes
            
        Returns:
            int: Número de entradas procesadas
        """
        total_processed = 0
        try:
            if chunk_size > 0:
                logger.info(f"Procesando log en fragmentos de {chunk_size} líneas")
                result = process_log_in_chunks(
                    log_file, 
                    self._process_chunk, 
                    chunk_size, 
                    start_date=start_date
                )
                if isinstance(result, int):
                    total_processed = result
            else:
                # Procesamiento de una vez (para archivos pequeños)
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    total_processed = self._process_chunk(lines, start_date)
                    
            logger.info(f"Procesadas {total_processed} entradas de log")
            return total_processed
        except FileNotFoundError:
            logger.error(f"No se encontró el archivo {log_file}")
            raise
        except Exception as e:
            logger.error(f"Error procesando archivo de log {log_file}: {e}")
            raise
    
    def identify_threats(self):
        """
        Identifica amenazas basadas en los datos acumulados.
        
        Returns:
            list: Lista de amenazas detectadas
        """
        self.subnet_data = defaultdict(list)
        
        # Primer paso: analizar cada IP y agrupar por subred
        logger.info("Analizando IPs y agrupando por subredes...")
        for ip, info in self.ip_data.items():
            times = sorted(info['times'])
            total_requests = len(times)
            if total_requests == 0:
                continue

            # Calcular RPM
            rpm = 0
            time_span = 0
            if total_requests >= 2:
                time_span = (times[-1] - times[0]).total_seconds()
                if time_span > 0:
                    rpm = (total_requests / (time_span / 60))

            # Evaluar suspiciocidad por RPM
            has_suspicious_ua = False
            suspicious_ua = ""
            is_suspicious_by_rpm = rpm > self.rpm_threshold
            is_suspicious = is_suspicious_by_rpm

            if is_suspicious:
                danger_score = calculate_danger_score(rpm, total_requests, has_suspicious_ua)
                # Intentar obtener la subred (IPv4 o IPv6)
                subnet = get_subnet(ip)
                if subnet:
                    ip_info = {
                        'ip': ip,
                        'rpm': rpm,
                        'total_requests': total_requests,
                        'time_span': time_span,
                        'has_suspicious_ua': has_suspicious_ua,
                        'suspicious_ua': suspicious_ua,
                        'danger_score': danger_score,
                        'is_suspicious_by_rpm': is_suspicious_by_rpm
                    }
                    self.subnet_data[subnet].append(ip_info)

        # Segundo paso: unificar amenazas por subred
        self.unified_threats = []
        logger.info(f"Evaluando {len(self.subnet_data)} subredes con IPs sospechosas...")

        for subnet, ip_infos in self.subnet_data.items():
            subnet_total_requests = sum(info['total_requests'] for info in ip_infos)
            subnet_total_danger = sum(info['danger_score'] for info in ip_infos)
            subnet_ip_count = len(ip_infos)
            
            if subnet_ip_count > 1:  # Amenaza de tipo subred
                threat = {
                    'type': 'subnet',
                    'id': subnet,
                    'danger_score': subnet_total_danger,
                    'total_requests': subnet_total_requests,
                    'ip_count': subnet_ip_count,
                    'details': sorted(ip_infos, key=lambda x: x['danger_score'], reverse=True)
                }
                self.unified_threats.append(threat)
            else:  # Amenaza de IP individual
                ip_info = ip_infos[0]
                ip_addr_obj = ipaddress.ip_address(ip_info['ip'])
                threat = {
                    'type': 'ip',
                    'id': ip_addr_obj,
                    'danger_score': ip_info['danger_score'],
                    'rpm': ip_info['rpm'],
                    'total_requests': ip_info['total_requests'],
                    'time_span': ip_info['time_span'],
                    'has_suspicious_ua': ip_info['has_suspicious_ua'],
                    'suspicious_ua': ip_info['suspicious_ua'],
                    'is_suspicious_by_rpm': ip_info['is_suspicious_by_rpm']
                }
                self.unified_threats.append(threat)

        # Ordenar por peligrosidad
        self.unified_threats = sorted(
            self.unified_threats, 
            key=lambda x: x['danger_score'], 
            reverse=True
        )
        
        logger.info(f"Se identificaron {len(self.unified_threats)} amenazas en total")
        return self.unified_threats

    def get_top_threats(self, top=10):
        """
        Obtiene las amenazas más peligrosas.
        
        Args:
            top (int): Número de amenazas a devolver
            
        Returns:
            list: Las top N amenazas más peligrosas
        """
        if not self.unified_threats:
            self.identify_threats()
            
        return self.unified_threats[:top]
        
    def export_results(self, format_type, output_file):
        """
        Exporta los resultados a un archivo en formato específico.
        
        Args:
            format_type (str): Formato de exportación ('json', 'csv')
            output_file (str): Ruta del archivo de salida
            
        Returns:
            bool: True si la exportación fue exitosa, False en caso contrario
        """
        if not self.unified_threats:
            logger.warning("No hay amenazas para exportar")
            return False
            
        try:
            if format_type.lower() == 'json':
                # Convertir objetos ipaddress a strings para serialización JSON
                json_threats = []
                for threat in self.unified_threats:
                    json_threat = threat.copy()
                    json_threat['id'] = str(json_threat['id'])
                    if 'details' in json_threat:
                        json_threat['details'] = json_threat['details']
                    json_threats.append(json_threat)
                    
                with open(output_file, 'w') as f:
                    json.dump(json_threats, f, indent=2)
                    
            elif format_type.lower() == 'csv':
                with open(output_file, 'w', newline='') as f:
                    # Definir campos según el tipo de amenaza
                    fieldnames = ['type', 'id', 'danger_score', 'total_requests']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for threat in self.unified_threats:
                        # Crear una versión simplificada para CSV
                        csv_threat = {
                            'type': threat['type'],
                            'id': str(threat['id']),
                            'danger_score': threat['danger_score'],
                            'total_requests': threat['total_requests']
                        }
                        writer.writerow(csv_threat)
            else:
                logger.error(f"Formato de exportación no soportado: {format_type}")
                return False
                
            logger.info(f"Resultados exportados a {output_file} en formato {format_type}")
            return True
            
        except Exception as e:
            logger.error(f"Error exportando resultados: {e}")
            return False