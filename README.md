# PingMapper

Herramienta de descubrimiento de red para auditorias. Detecta todas las tramas y hosts activos, lanza nmap y genera:

- `ips_trama_X.X.X.0.txt` — IPs activas por subred
- `trama_X.X.X.0.xml` — resultado nmap en XML para importar en **pentest.ws**
- `network_report.html` — informe visual con hosts, puertos abiertos y servicios

## Instalacion

### Opcion A — Instalar como binario del sistema (recomendado en Kali Linux)

Instala PingMapper como el comando `pingmapper`, para poder ejecutarlo desde
cualquier ruta sin depender de la carpeta del `git clone`:

```bash
git clone https://github.com/M4nuTCP/PingMapper.git
cd PingMapper
sudo ./install.sh
```

El instalador:
- instala las dependencias (`nmap`, `python3-pip`, `jinja2`),
- copia PingMapper a `/usr/local/lib/pingmapper/`,
- crea el lanzador `/usr/local/bin/pingmapper`.

Despues puedes ejecutarlo desde cualquier directorio:

```bash
sudo pingmapper --profile normal --name auditoria_cliente
```

Para desinstalarlo:

```bash
sudo ./install.sh --uninstall
```

### Opcion B — Ejecucion directa (sin instalar)

```bash
git clone https://github.com/M4nuTCP/PingMapper.git
cd PingMapper
pip3 install -r requirements.txt
sudo apt install nmap
sudo python3 pingmapper.py --profile normal
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

## Informe HTML

El `network_report.html` es un informe interactivo y autocontenido:

- **Copiar / descargar IPs por trama**: cada subred tiene un boton **Copiar IPs**
  (al portapapeles) y otro **.txt** que descarga un fichero
  `trama_ips_<rama>.0.txt` con las IPs una debajo de otra.
- **Copiar / descargar todas las IPs**: botones globales en la barra de
  herramientas (`trama_ips_todas.txt`).
- **Filtro** por IP, puerto o servicio, y controles para expandir/colapsar todo.
- Diseno oscuro profesional con estadisticas, badges de puertos y graficas.

## Escaneo por fases de una sola trama (`scan_trama.sh`)

Script nmap independiente que, dada una trama en formato CIDR, encadena las tres
fases y usa `--top-ports 1000` en el descubrimiento de puertos:

1. **Equipos activos** — `nmap -sn` (host discovery) → `ips_trama_<red>.txt`
2. **Puertos de los equipos** — `-sS --top-ports 1000 --open` sobre los equipos activos
3. **Servicios / versiones** — lanza el comando preferido sobre los puertos encontrados:

```bash
sudo nmap -p<puertos> -sS -sV --min-rate 3000 --open -vvv -n \
          -oX trama_<red>.xml -Pn -iL ips_trama_<red>.txt
```

Uso:

```bash
sudo ./scan_trama.sh 172.16.12.0/24
sudo ./scan_trama.sh 172.16.12.0/24 -r 5000 -o auditoria   # min-rate y carpeta
sudo ./scan_trama.sh 10.0.0.0/24 --full-ports              # fase 2 con -p- (todos)
sudo ./scan_trama.sh 10.0.0.0/24 --no-discovery            # sin fase 1 (toda la trama)
```

Genera `ips_trama_<red>.txt`, `ports_trama_<red>.gnmap` y `trama_<red>.xml`
(importable en pentest.ws).

## Flujo de trabajo en auditoria

1. Ejecutar PingMapper en la red objetivo
2. Los XML generados se importan directamente en [pentest.ws](https://pentest.ws)
3. El HTML sirve como informe inicial para el cliente; desde el se pueden
   copiar o exportar las IPs de cada trama con un clic
