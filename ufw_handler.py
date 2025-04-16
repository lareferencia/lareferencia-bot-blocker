#!/usr/bin/env python3
"""
Módulo para manejar interacciones con el firewall UFW.
Permite bloquear IPs/subredes y limpiar reglas expiradas.
"""
import re
import subprocess
import sys
from datetime import datetime, timezone, timedelta
import ipaddress
import logging

# Logger para este módulo
logger = logging.getLogger('botstats.ufw')

# Expresión regular para detectar reglas UFW con timestamp de expiración
RULE_STATUS_REGEX = re.compile(
    r"\[\s*(\d+)\].*(?:ALLOW|DENY)\s+IN\s+FROM\s+(\S+).*\s#\s*blocked_by_stats_py_until_(\d{8}T\d{6}Z)"
)

class UFWManager:
    """
    Clase para manejar operaciones con UFW de manera más encapsulada.
    """
    
    def __init__(self, dry_run=False):
        """
        Inicializa el manejador de UFW.
        
        Args:
            dry_run (bool): Si es True, muestra pero no ejecuta los comandos
        """
        self.dry_run = dry_run
        self._check_ufw_available()
        
    def _check_ufw_available(self):
        """
        Verifica que UFW esté disponible y el usuario tenga permisos.
        
        Returns:
            bool: True si UFW está disponible, False en caso contrario
        """
        try:
            result = subprocess.run(
                ["which", "ufw"], 
                check=False, 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            logger.warning("No se pudo verificar la disponibilidad de UFW. Algunas operaciones podrían fallar.")
            return False
            
    def block_target(self, subnet_or_ip, block_duration_minutes):
        """
        Bloquea una IP o subred usando UFW.
        
        Args:
            subnet_or_ip (ipaddress.IPv4Network|ipaddress.IPv6Network|ipaddress.IPv4Address|ipaddress.IPv6Address): 
                IP o subred a bloquear
            block_duration_minutes (int): Duración del bloqueo en minutos
            
        Returns:
            bool: True si el comando se ejecutó con éxito, False en caso contrario
        """
        # Validar el tipo de dirección o red
        valid_types = (
            ipaddress.IPv4Network, ipaddress.IPv6Network, 
            ipaddress.IPv4Address, ipaddress.IPv6Address
        )
        if not isinstance(subnet_or_ip, valid_types):
            logger.error(f"Tipo de dato inválido para bloqueo: {type(subnet_or_ip)}")
            return False

        target = str(subnet_or_ip)
        # Asegurar formato de red para IPs individuales
        if isinstance(subnet_or_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            # /32 para IPv4 y /128 para IPv6
            prefix_len = 32 if subnet_or_ip.version == 4 else 128
            target = f"{target}/{prefix_len}"

        # Calcular timestamp de expiración en UTC
        expiry_time = datetime.now(timezone.utc) + timedelta(minutes=block_duration_minutes)
        # Formato ISO 8601 compacto para nombres de archivo/comentarios
        expiry_str = expiry_time.strftime('%Y%m%dT%H%M%SZ')
        comment = f"blocked_by_stats_py_until_{expiry_str}"

        # Usar 'insert 1' para dar prioridad a la regla de bloqueo
        command = ["sudo", "ufw", "insert", "1", "deny", "from", target, "to", "any", "comment", comment]

        logger.info(f"Intentando bloquear: {target} hasta {expiry_str} UTC")
        if self.dry_run:
            logger.info(f"[DRY RUN] Comando UFW: {' '.join(command)}")
            return True

        try:
            result = subprocess.run(
                command, 
                check=True, 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            logger.info(f"Comando UFW ejecutado exitosamente para {target}.")
            if result.stdout:
                logger.debug(f"Salida UFW: {result.stdout.strip()}")
            # UFW a veces imprime mensajes informativos en stderr
            if result.stderr:
                logger.debug(f"Salida UFW (stderr): {result.stderr.strip()}")
            return True
        except FileNotFoundError:
            logger.error("El comando 'sudo' o 'ufw' no se encontró. Asegúrate de que ufw esté instalado.")
            return False
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout ejecutando comando UFW para {target}.")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"Error al ejecutar el comando UFW para {target}:")
            logger.error(f"Comando: {' '.join(command)}")
            logger.error(f"Código de retorno: {e.returncode}")
            logger.error(f"Salida de error: {e.stderr.strip()}")
            logger.error(f"Salida estándar: {e.stdout.strip()}")
            # Comprobar si el error es porque la regla ya existe
            if "Skipping adding existing rule" in e.stdout or "Skipping adding existing rule" in e.stderr:
                 logger.info(f"Nota: La regla para {target} probablemente ya existía.")
                 return True
            return False
        except Exception as e:
            logger.error(f"Error inesperado al ejecutar UFW para {target}: {e}")
            return False

    def get_expired_rules(self):
        """
        Obtiene una lista de números de reglas UFW expiradas.
        
        Returns:
            list: Lista de números de reglas expiradas ordenadas de mayor a menor
        """
        rules_to_delete = []
        try:
            cmd = ["sudo", "ufw", "status", "numbered"]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=15)
            output_lines = result.stdout.splitlines()
            now_utc = datetime.now(timezone.utc)
            for line in output_lines:
                match = RULE_STATUS_REGEX.search(line)
                if match:
                    rule_number_str, target, expiry_str = match.groups()
                    rule_number = int(rule_number_str)
                    try:
                        expiry_time = datetime.strptime(expiry_str, '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
                        if now_utc >= expiry_time:
                            rules_to_delete.append(rule_number)
                    except ValueError:
                        pass
            return sorted(rules_to_delete, reverse=True)
        except Exception as e:
            logger.error(f"Error obteniendo reglas UFW: {e}")
            return []

    def delete_rule(self, rule_number):
        """
        Elimina una regla UFW por su número.
        
        Args:
            rule_number (int): Número de la regla a eliminar
            
        Returns:
            bool: True si la regla se eliminó con éxito, False en caso contrario
        """
        command = ["sudo", "ufw", "--force", "delete", str(rule_number)]
        if self.dry_run:
            logger.info(f"[DRY RUN] Eliminaría regla #{rule_number}: {' '.join(command)}")
            return True
            
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)
            logger.info(f"Regla UFW #{rule_number} eliminada.")
            return True
        except Exception as e:
            logger.error(f"Error eliminando regla UFW #{rule_number}: {e}")
            return False

    def clean_expired_rules(self):
        """
        Limpia todas las reglas UFW expiradas.
        
        Returns:
            int: Número de reglas eliminadas
        """
        expiradas = self.get_expired_rules()
        if not expiradas:
            logger.info("No hay reglas expiradas para eliminar.")
            return 0
            
        count = 0
        for rule_num in expiradas:
            if self.delete_rule(rule_num):
                count += 1
                
        if count > 0:
            logger.info(f"Limpieza completada. {count} reglas eliminadas.")
        return count