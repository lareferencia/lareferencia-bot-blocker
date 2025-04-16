# LaReferencia Bot Stats

Herramienta para analizar logs de servidores web, detectar posibles amenazas de bots o ataques, y opcionalmente bloquear IPs sospechosas usando UFW (Uncomplicated Firewall).

## Características

- ✅ Análisis de logs para detección de comportamientos sospechosos
- ✅ Detección de ataques basada en patrones de solicitudes por minuto (RPM)
- ✅ Soporte para IPv4 e IPv6
- ✅ Agrupación de amenazas por subredes (/24 para IPv4, /64 para IPv6)
- ✅ Bloqueo automatizado de IPs/subredes mediante reglas UFW con caducidad
- ✅ Lista blanca de IPs/subredes que nunca deben bloquearse
- ✅ Procesamiento optimizado de logs grandes en fragmentos
- ✅ Múltiples formatos de exportación (JSON, CSV, texto)
- ✅ Sistema de logging completo
- ✅ Estructura modular y orientada a objetos

## Instalación

El script no requiere instalación especial, solo necesita Python 3.6 o superior.

Requisitos:
- Python 3.6+
- UFW (para funcionalidades de bloqueo) - Normalmente preinstalado en distribuciones Ubuntu

```bash
# Clonar el repositorio
git clone https://github.com/username/lareferencia-botstats.git
cd lareferencia-botstats

# Opcional: Crear entorno virtual
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

## Uso

### Ejemplo básico

```bash
python stats.py -f /var/log/apache2/access.log
```

Este comando analizará el log y mostrará las 10 amenazas más peligrosas detectadas, sin realizar ninguna acción de bloqueo.

### Análisis y bloqueo automático

```bash
sudo python stats.py -f /var/log/apache2/access.log --block --block-threshold 20 --block-duration 120
```

Este comando analizará el log, bloqueará IPs/subredes con más de 20 peticiones en el período analizado durante 120 minutos.

### Opciones avanzadas

```bash
python stats.py -f /var/log/nginx/access.log \
  --time-window day \
  --threshold 200 \
  --whitelist /etc/botstats/whitelist.txt \
  --output amenazas.json \
  --format json \
  --log-file /var/log/botstats.log \
  --log-level DEBUG \
  --chunk-size 50000
```

Este comando:
- Analiza solo las entradas del último día
- Usa un umbral de 200 RPM para considerar sospechosas las IPs
- Usa una lista blanca de IPs/subredes que no deben ser bloqueadas
- Exporta los resultados en formato JSON
- Guarda logs detallados en un archivo
- Procesa el archivo de log en fragmentos de 50,000 líneas para optimizar memoria

### Solo limpieza de reglas expiradas

```bash
sudo python stats.py --clean-rules
```

Este comando solo elimina las reglas UFW que han expirado y sale.

## Opciones

| Opción | Descripción |
|--------|-------------|
| `--file, -f` | Ruta del archivo de log a analizar |
| `--start-date, -s` | Fecha a partir de la cual se analiza el log (formato: dd/mmm/yyyy:HH:MM:SS) |
| `--time-window, -tw` | Analizar solo entradas de la última hora, día o semana |
| `--threshold, -t` | Umbral de RPM para considerar una IP sospechosa (default: 100) |
| `--top, -n` | Número de amenazas más peligrosas a mostrar (default: 10) |
| `--block` | Activar bloqueo de amenazas usando UFW |
| `--block-threshold` | Umbral de peticiones totales para activar bloqueo UFW (default: 10) |
| `--block-duration` | Duración del bloqueo en minutos (default: 60) |
| `--dry-run` | Mostrar comandos UFW sin ejecutarlos |
| `--whitelist, -w` | Archivo con lista de IPs o subredes que nunca deben bloquearse |
| `--output, -o` | Archivo para guardar los resultados del análisis |
| `--format` | Formato de salida: json, csv o text (default: text) |
| `--log-file` | Archivo donde guardar los logs de ejecución |
| `--log-level` | Nivel de detalle de los logs: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO) |
| `--chunk-size` | Tamaño del fragmento para procesar logs grandes (default: 10000, 0 para no fragmentar) |
| `--clean-rules` | Ejecutar limpieza de reglas UFW expiradas y salir |

## Formato de la lista blanca

El archivo de lista blanca debe contener una IP o subnet por línea. Ejemplos:

```
# Comentarios empiezan con #
192.168.1.1
10.0.0.0/8
2001:db8::/64
# También se pueden incluir IPs individuales IPv6
2001:db8::1
```

## Estructura del proyecto

El código está organizado en módulos:

- `stats.py`: Script principal que coordina todo el proceso
- `log_parser.py`: Módulo para parsear y analizar logs de servidores web
- `threat_analyzer.py`: Módulo para el análisis y detección de amenazas
- `ufw_handler.py`: Módulo para manejar interacciones con UFW

## Desarrollo

Para contribuir al proyecto:

1. Fork del repositorio
2. Crear una rama para tu función (`git checkout -b feature/nueva-funcion`)
3. Commit de tus cambios (`git commit -am 'Añadir nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcion`)
5. Crear un Pull Request

## Licencia

[MIT](LICENSE)