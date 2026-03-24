# PingMapper

Herramienta de descubrimiento de red para auditorias. Detecta todas las tramas y hosts activos, lanza nmap y genera:

- `ips_trama_X.X.X.0.txt` — IPs activas por subred
- `trama_X.X.X.0.xml` — resultado nmap en XML para importar en **pentest.ws**
- `network_report.html` — informe visual con hosts, puertos abiertos y servicios

## Instalacion

```bash
git clone https://github.com/M4nuTCP/PingMapper.git
cd PingMapper
pip3 install -r requirements.txt
sudo apt install nmap
```

## Uso

```bash
sudo python3 pingmapper.py --profile <perfil>
```

## Perfiles

| Perfil | Uso recomendado | ping/s | nmap max-rate | retries |
|---|---|---|---|---|
| `stealth`    | OT/SCADA, IDS/IPS, redes criticas | 5 | 100 pps | 1 |
| `safe`       | Redes empresariales sensibles | 20 | 400 pps | 1 |
| `normal`     | Redes empresariales estandar (default) | 80 | 1000 pps | 2 |
| `aggressive` | Redes internas robustas / lab | 500 | 5000 pps | 3 |

## Ejemplos

```bash
# Red empresarial normal (recomendado para la mayoria de auditorias)
sudo python3 pingmapper.py --profile normal

# Red sensible o con IDS
sudo python3 pingmapper.py --profile safe

# Override puntual sobre un perfil
sudo python3 pingmapper.py --profile safe --nmap-max-rate 300

# Guardar resultados en un directorio especifico
sudo python3 pingmapper.py --profile normal --output-dir /tmp/auditoria_cliente

# Solo descubrimiento por ping, sin nmap
sudo python3 pingmapper.py --profile normal --skip-nmap
```

## Protecciones contra saturacion de red

### Ping sweep
- **Token Bucket global**: todos los hilos comparten un limite comun de pings/segundo. Con `stealth` nunca se superan 5 pings/s en total aunque haya 2 hilos activos.
- **`--ping-rate`**: techo configurable de pings/segundo.
- **`--delay`**: pausa adicional entre resultados.

### Nmap
- **`--max-rate`**: techo absoluto de paquetes/segundo. Nmap nunca lo supera independientemente de la red.
- **`--max-parallelism`**: limita las sondas TCP simultaneas pendientes de respuesta.
- **`--max-retries 1`**: el parametro de mayor impacto. El nmap por defecto reintenta cada puerto hasta 10 veces. Con retries=1 se reduce el trafico hasta un **80%** sin perder cobertura significativa.
- **`--max-rtt-timeout`**: tiempo maximo de espera por respuesta antes de pasar al siguiente puerto. Evita que hosts lentos bloqueen el escaneo.
- **`--host-timeout`**: abandona un host si tarda mas del limite. Evita colgarse en hosts con firewalls que dropean silenciosamente.
- **`-n`**: sin resolucion DNS. Elimina trafico UDP/53 innecesario.
- **`-Pn`**: no envia pings de descubrimiento nmap (ya se hizo con el ping sweep).
- Los nmap de cada subred se lanzan **secuencialmente**, nunca en paralelo.

## Flujo de trabajo en auditoria

1. Ejecutar PingMapper en la red objetivo
2. Los XML generados se importan directamente en [pentest.ws](https://pentest.ws)
3. El HTML sirve como informe inicial para el cliente
