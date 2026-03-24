# PingMapper

Herramienta de descubrimiento de red para auditorias. Detecta todas las tramas y hosts activos de una red privada, lanza nmap sobre los hosts descubiertos y genera:

- `ips_trama_X.X.X.0.txt` — lista de IPs activas por subred
- `trama_X.X.X.0.xml` — resultado nmap en XML para importar en **pentest.ws**
- `network_report.html` — informe visual con hosts, puertos abiertos y servicios detectados

## Instalacion

```bash
git clone https://github.com/M4nuTCP/PingMapper.git
cd PingMapper
pip3 install -r requirements.txt
```

Requiere nmap instalado:
```bash
sudo apt install nmap
```

## Uso basico

```bash
sudo python3 pingmapper.py
```

Esto ejecuta un descubrimiento completo con configuracion conservadora (min-rate 1000) apta para redes empresariales.

## Opciones

| Flag | Default | Descripcion |
|---|---|---|
| `--nmap-rate` | 1000 | `--min-rate` de nmap. 500=sensible, 1000=normal, 5000=agresivo |
| `--skip-nmap` | — | Solo ping sweep, sin lanzar nmap |
| `--output-dir` | `.` | Directorio donde guardar XMLs, TXTs e HTML |
| `--subnet-threads` | 30 | Hilos para deteccion de tramas |
| `--host-threads` | 20 | Hilos para ping sweep de hosts |
| `--ping-timeout` | 1.0 | Timeout por ping (segundos) |
| `--delay` | 0.0 | Retardo entre pings (segundos) |
| `--mode` | full | `subnets` = solo tramas, `full` = tramas + hosts |

## Ejemplos segun sensibilidad de la red

### Red empresarial critica (no saturar bajo ninguna circunstancia)
```bash
sudo python3 pingmapper.py --nmap-rate 500 --subnet-threads 5 --host-threads 5 --delay 0.2 --ping-timeout 2.0
```

### Red empresarial normal
```bash
sudo python3 pingmapper.py --nmap-rate 1000 --subnet-threads 10 --host-threads 10 --delay 0.1
```

### Red robusta / pentest sin restricciones
```bash
sudo python3 pingmapper.py --nmap-rate 5000 --subnet-threads 30 --host-threads 20
```

### Solo descubrimiento, sin nmap
```bash
sudo python3 pingmapper.py --skip-nmap --output-dir /tmp/auditoria
```

### Guardar todo en un directorio especifico
```bash
sudo python3 pingmapper.py --nmap-rate 1000 --output-dir /tmp/cliente_2025
```

## Flujo de trabajo en auditoria

1. Ejecutar PingMapper en la red objetivo
2. Revisar `network_report.html` para el informe inicial
3. Importar los archivos `trama_*.xml` en [pentest.ws](https://pentest.ws) para el reporte formal

## Notas sobre seguridad de la red

- `--nmap-rate 1000` (default) envia ~1000 paquetes/segundo por subred. En la gran mayoria de redes empresariales esto no genera impacto perceptible.
- `--nmap-rate 500` + `--delay 0.1` para entornos con IDS/IPS sensibles o redes legacy.
- `-p-` escanea los 65535 puertos. Si el tiempo es un factor, puedes limitar con `--nmap-extra-args` modificando el script.
- El escaneo nmap se lanza **secuencialmente por subred**, nunca en paralelo, para no multiplicar la carga.
