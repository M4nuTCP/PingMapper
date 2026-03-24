#!/usr/bin/env python3
"""
PingMapper - Descubrimiento de red y escaneo nmap para auditorias.
Disenado para no saturar redes empresariales.
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from jinja2 import Template


# --------------------------------------------------------------------------- #
# Perfiles de velocidad                                                         #
# --------------------------------------------------------------------------- #

PROFILES = {
    "stealth": {
        "description": "Minimo ruido. IDS/IPS, OT/SCADA, redes criticas.",
        "subnet_threads":     2,
        "host_threads":       2,
        "ping_timeout":       2.0,
        "ping_rate":          5,
        "delay":              0.5,
        "nmap_min_rate":      50,
        "nmap_max_rate":      100,
        "nmap_parallelism":   2,
        "nmap_retries":       1,
        "nmap_max_rtt":       "3000ms",
        "nmap_init_rtt":      "500ms",
        "nmap_host_timeout":  "90m",
    },
    "safe": {
        "description": "Conservador. Redes empresariales sensibles (recomendado).",
        "subnet_threads":     5,
        "host_threads":       5,
        "ping_timeout":       1.5,
        "ping_rate":          20,
        "delay":              0.1,
        "nmap_min_rate":      200,
        "nmap_max_rate":      400,
        "nmap_parallelism":   5,
        "nmap_retries":       1,
        "nmap_max_rtt":       "2000ms",
        "nmap_init_rtt":      "300ms",
        "nmap_host_timeout":  "45m",
    },
    "normal": {
        "description": "Estandar. Redes empresariales normales (default).",
        "subnet_threads":     15,
        "host_threads":       15,
        "ping_timeout":       1.0,
        "ping_rate":          80,
        "delay":              0.0,
        "nmap_min_rate":      500,
        "nmap_max_rate":      1000,
        "nmap_parallelism":   20,
        "nmap_retries":       2,
        "nmap_max_rtt":       "1000ms",
        "nmap_init_rtt":      "200ms",
        "nmap_host_timeout":  "20m",
    },
    "aggressive": {
        "description": "Rapido. Redes internas robustas o laboratorios.",
        "subnet_threads":     30,
        "host_threads":       20,
        "ping_timeout":       0.7,
        "ping_rate":          500,
        "delay":              0.0,
        "nmap_min_rate":      3000,
        "nmap_max_rate":      5000,
        "nmap_parallelism":   100,
        "nmap_retries":       3,
        "nmap_max_rtt":       "500ms",
        "nmap_init_rtt":      "100ms",
        "nmap_host_timeout":  "10m",
    },
}


# --------------------------------------------------------------------------- #
# Display en vivo                                                               #
# --------------------------------------------------------------------------- #

class Live:
    """
    Separa el output en dos capas:
      - log()    : lineas permanentes que suben (hallazgos, eventos)
      - status() : una sola linea al final que se sobreescribe en cada tick
    """

    def __init__(self):
        self._has_status = False
        self._lock = threading.Lock()

    def log(self, msg: str):
        """Imprime una linea permanente, limpiando el status anterior."""
        with self._lock:
            if self._has_status:
                sys.stdout.write("\r\033[K")
            print(msg)
            self._has_status = False

    def status(self, msg: str):
        """Sobreescribe la linea de estado actual."""
        with self._lock:
            # Trunca si es mas ancho que el terminal para no romper el formato
            try:
                cols = os.get_terminal_size().columns - 1
            except OSError:
                cols = 100
            if len(msg) > cols:
                msg = msg[:cols - 3] + "..."
            sys.stdout.write(f"\r\033[K{msg}")
            sys.stdout.flush()
            self._has_status = True

    def clear(self):
        """Borra la linea de estado."""
        with self._lock:
            if self._has_status:
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()
                self._has_status = False

    def section(self, title: str):
        """Cabecera de seccion."""
        self.clear()
        self.log(f"\n{'─' * 50}")
        self.log(f"  {title}")
        self.log(f"{'─' * 50}")


class Counter:
    """Contador thread-safe."""

    def __init__(self):
        self._v = 0
        self._lock = threading.Lock()

    def inc(self) -> int:
        with self._lock:
            self._v += 1
            return self._v

    @property
    def value(self) -> int:
        return self._v


def pbar(done: int, total: int, width: int = 22) -> str:
    """Barra de progreso ASCII simple."""
    pct = done / total if total else 0
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {done}/{total}"


# --------------------------------------------------------------------------- #
# Token Bucket                                                                  #
# --------------------------------------------------------------------------- #

class TokenBucket:
    """Limita la tasa global de pings entre todos los hilos."""

    def __init__(self, rate: float):
        self.rate      = float(rate)
        self.tokens    = float(rate)
        self.max_tokens= float(rate)
        self.last      = time.monotonic()
        self._lock     = threading.Lock()

    def acquire(self):
        while True:
            with self._lock:
                now = time.monotonic()
                self.tokens = min(self.max_tokens, self.tokens + (now - self.last) * self.rate)
                self.last = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.rate
            time.sleep(wait)


# --------------------------------------------------------------------------- #
# Comprobacion de dependencias                                                  #
# --------------------------------------------------------------------------- #

def check_nmap() -> bool:
    """Comprueba si nmap esta disponible en el PATH."""
    return shutil.which("nmap") is not None


# --------------------------------------------------------------------------- #
# Ping                                                                          #
# --------------------------------------------------------------------------- #

def ping(ip: str, timeout: float = 1.0, bucket: TokenBucket = None) -> tuple:
    if bucket:
        bucket.acquire()
    is_win = platform.system().lower() == "windows"
    cmd = ["ping", "-n" if is_win else "-c", "1",
           "-w" if is_win else "-W",
           str(int(timeout * 1000) if not is_win else int(timeout)),
           ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=timeout + 0.5)
        return ip, r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return ip, False


def ping_subnet_start(subnet: str, timeout: float, bucket: TokenBucket) -> tuple:
    for host in [1, 254, 100, 50, 10, 200]:
        _, ok = ping(f"{subnet}.{host}", timeout=timeout, bucket=bucket)
        if ok:
            return subnet, True
    return subnet, False


def active_subnets(base_subnets: list, threads: int, timeout: float,
                   bucket: TokenBucket, live: Live) -> list:
    total   = len(base_subnets)
    checked = Counter()
    found   = Counter()

    def probe(subnet):
        result = ping_subnet_start(subnet, timeout=timeout, bucket=bucket)
        n = checked.inc()
        if result[1]:
            found.inc()
            live.log(f"  [+] Trama activa: {subnet}.0/24")
        live.status(f"  Tramas  {pbar(n, total)}  {found.value} activas encontradas")
        return result

    with ThreadPoolExecutor(max_workers=threads) as ex:
        results = list(ex.map(probe, base_subnets))

    live.clear()
    return [s for s, ok in results if ok]


def ping_subnet(subnet: str, timeout: float, max_workers: int,
                delay: float, bucket: TokenBucket, live: Live) -> list:
    ip_range   = [f"{subnet}.{i}" for i in range(1, 255)]
    total      = len(ip_range)
    scanned    = Counter()
    found_cnt  = Counter()
    found_ips  = []
    _lock      = threading.Lock()

    def scan(ip):
        _, ok = ping(ip, timeout=timeout, bucket=bucket)
        n = scanned.inc()
        if ok:
            found_cnt.inc()
            live.log(f"    [+] {ip}")
            with _lock:
                found_ips.append(ip)
            if delay:
                time.sleep(delay)
        live.status(f"  Hosts   {pbar(n, total, 22)}  {found_cnt.value} activos  [{subnet}.0/24]")

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        list(ex.map(scan, ip_range))

    live.clear()
    return sorted(found_ips, key=lambda ip: int(ip.split(".")[-1]))


# --------------------------------------------------------------------------- #
# Nmap                                                                          #
# --------------------------------------------------------------------------- #

def save_ips_to_file(subnet: str, hosts: list, output_dir: str, live: Live) -> str:
    path = os.path.join(output_dir, f"ips_trama_{subnet}.0.txt")
    with open(path, "w") as f:
        f.write("\n".join(hosts) + "\n")
    live.log(f"  [+] IPs guardadas: {path}")
    return path


def build_nmap_cmd(ips_file: str, xml_output: str, cfg: dict) -> list:
    return [
        "nmap",
        "-p-", "-sS", "-sV", "--open", "-n", "-Pn",
        "--min-rate",            str(cfg["nmap_min_rate"]),
        "--max-rate",            str(cfg["nmap_max_rate"]),
        "--max-parallelism",     str(cfg["nmap_parallelism"]),
        "--max-retries",         str(cfg["nmap_retries"]),
        "--max-rtt-timeout",     cfg["nmap_max_rtt"],
        "--initial-rtt-timeout", cfg["nmap_init_rtt"],
        "--host-timeout",        cfg["nmap_host_timeout"],
        "-oX", xml_output,
        "-iL", ips_file,
    ]


def run_nmap(subnet: str, ips_file: str, output_dir: str,
             cfg: dict, live: Live) -> str | None:
    xml_output = os.path.join(output_dir, f"trama_{subnet}.0.xml")
    cmd = build_nmap_cmd(ips_file, xml_output, cfg)
    live.log(f"  [*] nmap {subnet}.0/24  max-rate={cfg['nmap_max_rate']} | retries={cfg['nmap_retries']}")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
    except FileNotFoundError:
        live.log("[!] nmap no encontrado. Instala con: sudo apt install nmap")
        return None

    # Consume stdout en hilo separado para no bloquear la pipe
    output_lines = []
    def _drain():
        for line in proc.stdout:
            output_lines.append(line)
    drain = threading.Thread(target=_drain, daemon=True)
    drain.start()

    spinner = ["|", "/", "-", "\\"]
    start   = time.time()
    i       = 0
    while proc.poll() is None:
        elapsed = int(time.time() - start)
        live.status(f"  {spinner[i % 4]}  Nmap corriendo en {subnet}.0/24 ... {elapsed}s")
        i += 1
        time.sleep(0.15)

    drain.join()
    live.clear()
    elapsed = int(time.time() - start)

    if proc.returncode == 0:
        live.log(f"  [+] Nmap completado en {elapsed}s  ->  {xml_output}")
    else:
        live.log(f"  [!] Nmap error (codigo {proc.returncode})")
        tail = "".join(output_lines[-10:])
        if tail.strip():
            live.log(tail.strip())

    return xml_output if os.path.exists(xml_output) else None


# --------------------------------------------------------------------------- #
# Parseo XML nmap                                                               #
# --------------------------------------------------------------------------- #

def parse_nmap_xml(xml_file: str) -> dict:
    hosts_data = {}
    if not xml_file or not os.path.exists(xml_file):
        return hosts_data
    try:
        root = ET.parse(xml_file).getroot()
        for host in root.findall("host"):
            st = host.find("status")
            if st is None or st.get("state") != "up":
                continue
            addr = host.find("address[@addrtype='ipv4']")
            if addr is None:
                continue
            ip    = addr.get("addr")
            ports = []
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    se = port.find("state")
                    if se is None or se.get("state") != "open":
                        continue
                    svc = port.find("service")
                    ports.append({
                        "port":     port.get("portid"),
                        "protocol": port.get("protocol"),
                        "service":  svc.get("name", "")      if svc is not None else "",
                        "product":  svc.get("product", "")   if svc is not None else "",
                        "version":  svc.get("version", "")   if svc is not None else "",
                        "extra":    svc.get("extrainfo", "") if svc is not None else "",
                    })
            hosts_data[ip] = {"ports": ports, "port_count": len(ports)}
    except ET.ParseError as e:
        print(f"[!] Error parseando {xml_file}: {e}")
    return hosts_data


# --------------------------------------------------------------------------- #
# HTML Report                                                                   #
# --------------------------------------------------------------------------- #

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>PingMapper - Informe de Red</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d0d1a; color: #e0e0e0; }
header {
    background: linear-gradient(135deg, #1a1a2e, #16213e);
    border-bottom: 2px solid #4caf50;
    padding: 18px 30px;
    display: flex; align-items: center; justify-content: space-between;
}
header h1 { color: #4caf50; font-size: 1.7em; letter-spacing: 2px; }
header .meta { font-size: 0.82em; color: #888; text-align: right; }
.profile-badge {
    display: inline-block; margin-top: 4px;
    background: #1e3a1e; border: 1px solid #4caf50;
    color: #4caf50; font-size: 0.75em; border-radius: 4px; padding: 2px 8px;
}
.stats-bar {
    display: flex; gap: 12px; padding: 14px 30px;
    background: #111120; border-bottom: 1px solid #1e1e2e; flex-wrap: wrap;
}
.stat-card {
    background: #1a1a2e; border: 1px solid #4caf50;
    border-radius: 6px; padding: 10px 22px; text-align: center; min-width: 120px;
}
.stat-card .num { font-size: 1.9em; color: #4caf50; font-weight: bold; }
.stat-card .lbl { font-size: 0.72em; color: #888; text-transform: uppercase; letter-spacing: 1px; }
.container { padding: 20px 30px; }
.subnet-block { margin-bottom: 22px; border: 1px solid #252535; border-radius: 8px; overflow: hidden; }
.subnet-header {
    background: #1a1a2e; border-left: 4px solid #4caf50;
    padding: 11px 18px; cursor: pointer;
    display: flex; justify-content: space-between; align-items: center; user-select: none;
}
.subnet-header:hover { background: #1e2040; }
.subnet-header h3 { color: #4caf50; font-size: 0.95em; font-family: monospace; }
.badge { border-radius: 12px; padding: 2px 10px; font-size: 0.72em; font-weight: bold; }
.badge-green  { background: #4caf50; color: #000; }
.badge-orange { background: #ff9800; color: #000; }
.badge-grey   { background: #333; color: #888; }
.subnet-body { display: none; padding: 14px; background: #10101c; }
.host-block { margin-bottom: 10px; border: 1px solid #202030; border-radius: 6px; overflow: hidden; }
.host-header {
    background: #18182a; padding: 7px 14px; cursor: pointer;
    display: flex; justify-content: space-between; align-items: center;
}
.host-header:hover { background: #1e1e38; }
.host-ip { color: #81d4fa; font-family: monospace; font-size: 0.92em; }
.host-ports-body { display: none; padding: 10px; background: #0c0c18; }
table.ports { width: 100%; border-collapse: collapse; font-size: 0.83em; }
table.ports th {
    background: #1e1e30; color: #4caf50;
    padding: 6px 10px; text-align: left; border-bottom: 1px solid #2a2a40;
}
table.ports td { padding: 5px 10px; border-bottom: 1px solid #18182a; font-family: monospace; }
table.ports tr:hover td { background: #16162a; }
.p-num { color: #ff9800; }
.p-svc { color: #81d4fa; }
.p-ver { color: #aaa; }
.no-data { color: #444; font-size: 0.82em; padding: 8px 4px; }
.charts { display: flex; gap: 20px; flex-wrap: wrap; padding: 10px 30px 30px; }
.chart-box {
    background: #1a1a2e; border: 1px solid #252535;
    border-radius: 8px; padding: 20px; flex: 1; min-width: 300px;
}
.chart-box h4 { color: #4caf50; margin-bottom: 14px; font-size: 0.88em; letter-spacing: 1px; }
footer {
    text-align: center; padding: 14px;
    background: #090912; border-top: 1px solid #1a1a2a; color: #444; font-size: 0.78em;
}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<header>
  <div>
    <h1>PingMapper</h1>
    <div style="color:#555;font-size:0.8em;margin-top:3px">Network Discovery &amp; Audit Report</div>
  </div>
  <div class="meta">
    <div>{{ scan_time }}</div>
    <div><span class="profile-badge">perfil: {{ profile }}</span></div>
    <div style="color:#4caf50;margin-top:4px">M4nuTCP</div>
  </div>
</header>

<div class="stats-bar">
  <div class="stat-card"><div class="num">{{ subnets|length }}</div><div class="lbl">Subredes</div></div>
  <div class="stat-card"><div class="num">{{ total_hosts }}</div><div class="lbl">Hosts vivos</div></div>
  <div class="stat-card"><div class="num">{{ total_open_ports }}</div><div class="lbl">Puertos abiertos</div></div>
</div>

<div class="container">
{% for subnet in subnets %}
  <div class="subnet-block">
    <div class="subnet-header" onclick="tog('sn{{ loop.index }}')">
      <h3>&#9658; {{ subnet }}.0/24</h3>
      <span class="badge badge-green">{{ hosts[subnet]|length }} hosts</span>
    </div>
    <div class="subnet-body" id="sn{{ loop.index }}">
      {% for ip in hosts[subnet] %}
      {% set hd = nmap_data.get(subnet, {}).get(ip, {}) %}
      {% set pts = hd.get('ports', []) %}
      <div class="host-block">
        <div class="host-header" onclick="tog('h_{{ ip|replace('.','_') }}')">
          <span class="host-ip">{{ ip }}</span>
          {% if pts %}
          <span class="badge badge-orange">{{ pts|length }} puertos</span>
          {% else %}
          <span class="badge badge-grey">sin nmap</span>
          {% endif %}
        </div>
        <div class="host-ports-body" id="h_{{ ip|replace('.','_') }}">
          {% if pts %}
          <table class="ports">
            <thead><tr><th>Puerto</th><th>Proto</th><th>Servicio</th><th>Version / Info</th></tr></thead>
            <tbody>
            {% for p in pts %}
              <tr>
                <td class="p-num">{{ p.port }}</td>
                <td>{{ p.protocol }}</td>
                <td class="p-svc">{{ p.service }}</td>
                <td class="p-ver">{{ p.product }} {{ p.version }} {{ p.extra }}</td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
          {% else %}
          <div class="no-data">Sin datos de nmap para este host.</div>
          {% endif %}
        </div>
      </div>
      {% endfor %}
    </div>
  </div>
{% endfor %}
</div>

<div class="charts">
  <div class="chart-box"><h4>HOSTS POR SUBRED</h4><canvas id="c1"></canvas></div>
  <div class="chart-box"><h4>DISTRIBUCION (%)</h4><canvas id="c2"></canvas></div>
</div>
<footer>PingMapper &mdash; M4nuTCP &mdash; {{ scan_time }}</footer>

<script>
function tog(id) {
  var e = document.getElementById(id);
  if (e) e.style.display = (e.style.display === 'block') ? 'none' : 'block';
}
document.addEventListener('DOMContentLoaded', function () {
  var labels = [{% for s in subnets %}"{{ s }}.0/24",{% endfor %}];
  var counts = [{% for s in subnets %}{{ hosts[s]|length }},{% endfor %}];
  var total  = counts.reduce(function(a,b){return a+b;}, 1);
  var pcts   = counts.map(function(c){return ((c/total)*100).toFixed(1);});
  var pal    = ['#4caf50','#ff9800','#2196f3','#f44336','#9c27b0','#00bcd4','#ffeb3b','#e91e63'];
  var grid   = {color:'#1e1e2e'}; var tc = {color:'#888'};
  new Chart(document.getElementById('c1'),{type:'bar',
    data:{labels:labels,datasets:[{label:'Hosts',data:counts,backgroundColor:pal}]},
    options:{responsive:true,plugins:{legend:{labels:{color:'#ccc'}}},
      scales:{x:{ticks:tc,grid:grid},y:{ticks:tc,grid:grid}}}});
  new Chart(document.getElementById('c2'),{type:'doughnut',
    data:{labels:labels,datasets:[{data:pcts,backgroundColor:pal}]},
    options:{responsive:true,plugins:{legend:{labels:{color:'#ccc'}}}}});
});
</script>
</body>
</html>"""


def generate_html_report(subnets, hosts, nmap_data, profile, output_dir, live):
    total_hosts = sum(len(hosts[s]) for s in subnets)
    total_open_ports = sum(
        nmap_data.get(s, {}).get(ip, {}).get("port_count", 0)
        for s in subnets for ip in hosts[s]
    )
    html = Template(HTML_TEMPLATE).render(
        subnets=subnets, hosts=hosts, nmap_data=nmap_data,
        total_hosts=total_hosts, total_open_ports=total_open_ports,
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        profile=profile,
    )
    path = os.path.join(output_dir, "network_report.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    live.log(f"  [+] HTML: {path}")


# --------------------------------------------------------------------------- #
# Subnets                                                                       #
# --------------------------------------------------------------------------- #

def build_subnet_list():
    return (
        [f"10.{i}.0" for i in range(256)]
        + [f"172.{i}.0" for i in range(16, 32)]
        + [f"192.168.{i}" for i in range(256)]
    )


# --------------------------------------------------------------------------- #
# CLI                                                                            #
# --------------------------------------------------------------------------- #

def parse_arguments():
    profile_help = "\n".join(
        f"  {k:12} {v['description']}" for k, v in PROFILES.items()
    )
    parser = argparse.ArgumentParser(
        description="PingMapper - Descubrimiento de red + nmap para auditorias",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Perfiles:
{profile_help}

Ejemplos:
  sudo python3 pingmapper.py --profile safe --name auditoria_cliente
  sudo python3 pingmapper.py --profile normal --name red_interna
  sudo python3 pingmapper.py --profile aggressive --name lab_test
  sudo python3 pingmapper.py --profile safe --nmap-max-rate 300 --name empresa_xyz
  sudo python3 pingmapper.py --skip-nmap --name solo_discovery
  sudo python3 pingmapper.py --output-dir /tmp --name cliente_2024
        """,
    )
    parser.add_argument("--profile", choices=PROFILES.keys(), default="normal",
                        help="Perfil de velocidad (default: normal)")
    parser.add_argument("--mode", choices=["subnets", "full"], default="full",
                        help="subnets=solo tramas, full=tramas+hosts (default: full)")
    parser.add_argument("--skip-nmap", action="store_true",
                        help="Omitir escaneo nmap")
    parser.add_argument("--output-dir", default=".",
                        help="Directorio base de salida (default: .)")
    parser.add_argument("--name", default=None,
                        help="Nombre de la carpeta donde se guardan los resultados")

    g = parser.add_argument_group("overrides del perfil (opcionales)")
    g.add_argument("--subnet-threads",    type=int)
    g.add_argument("--host-threads",      type=int)
    g.add_argument("--ping-timeout",      type=float)
    g.add_argument("--ping-rate",         type=int)
    g.add_argument("--delay",             type=float)
    g.add_argument("--nmap-min-rate",     type=int)
    g.add_argument("--nmap-max-rate",     type=int)
    g.add_argument("--nmap-parallelism",  type=int)
    g.add_argument("--nmap-retries",      type=int)
    g.add_argument("--nmap-max-rtt",      type=str)
    g.add_argument("--nmap-init-rtt",     type=str)
    g.add_argument("--nmap-host-timeout", type=str)
    return parser.parse_args()


def build_config(args) -> dict:
    cfg = dict(PROFILES[args.profile])
    for key, attr in [
        ("subnet_threads",    "subnet_threads"),
        ("host_threads",      "host_threads"),
        ("ping_timeout",      "ping_timeout"),
        ("ping_rate",         "ping_rate"),
        ("delay",             "delay"),
        ("nmap_min_rate",     "nmap_min_rate"),
        ("nmap_max_rate",     "nmap_max_rate"),
        ("nmap_parallelism",  "nmap_parallelism"),
        ("nmap_retries",      "nmap_retries"),
        ("nmap_max_rtt",      "nmap_max_rtt"),
        ("nmap_init_rtt",     "nmap_init_rtt"),
        ("nmap_host_timeout", "nmap_host_timeout"),
    ]:
        val = getattr(args, attr, None)
        if val is not None:
            cfg[key] = val
    return cfg


# --------------------------------------------------------------------------- #
# Main                                                                          #
# --------------------------------------------------------------------------- #

def main():
    args = parse_arguments()
    cfg  = build_config(args)
    live = Live()

    # ── Nombre de la carpeta de salida ───────────────────────────────────────
    folder_name = args.name
    if not folder_name:
        try:
            folder_name = input("\nNombre de la carpeta de resultados: ").strip()
        except (EOFError, KeyboardInterrupt):
            folder_name = ""
    if not folder_name:
        folder_name = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    output_dir = os.path.join(args.output_dir, folder_name)
    os.makedirs(output_dir, exist_ok=True)

    # ── Comprobacion de nmap ─────────────────────────────────────────────────
    if not args.skip_nmap:
        if not check_nmap():
            print("\n[!] nmap no esta instalado o no se encuentra en el PATH.")
            print("[!] Instalalo con:  sudo apt install nmap")
            print("[!] O usa --skip-nmap para omitir el escaneo nmap.\n")
            sys.exit(1)

    live.log(f"\nPingMapper  |  perfil: {args.profile}  |  {PROFILES[args.profile]['description']}")
    live.log(f"  Carpeta de salida: {output_dir}")
    if not args.skip_nmap:
        live.log(f"nmap: max-rate={cfg['nmap_max_rate']} pps | parallelism={cfg['nmap_parallelism']} | retries={cfg['nmap_retries']}")

    # ── Fase 1: detectar tramas activas ─────────────────────────────────────
    live.section("FASE 1 / 3  Detectando tramas de red")
    bucket = TokenBucket(rate=cfg["ping_rate"])
    detected = active_subnets(
        build_subnet_list(),
        threads=cfg["subnet_threads"],
        timeout=cfg["ping_timeout"],
        bucket=bucket,
        live=live,
    )
    all_subnets  = sorted(set(detected))
    subnet_hosts = {s: [] for s in all_subnets}

    if not all_subnets:
        live.log("\n[-] No se detectaron tramas activas.")
        return
    live.log(f"\n  {len(all_subnets)} trama(s) activa(s) encontrada(s).")

    # ── Fase 2: hosts por trama ──────────────────────────────────────────────
    if args.mode == "full":
        live.section("FASE 2 / 3  Escaneando hosts por trama")
        for subnet in all_subnets:
            live.log(f"\n  [{subnet}.0/24]")
            subnet_hosts[subnet] = ping_subnet(
                subnet,
                timeout=cfg["ping_timeout"],
                max_workers=cfg["host_threads"],
                delay=cfg["delay"],
                bucket=bucket,
                live=live,
            )
            live.log(f"  -> {len(subnet_hosts[subnet])} host(s) activo(s)")

    # ── Guardar TXTs y generar HTML (antes de nmap) ──────────────────────────
    live.section("Guardando IPs y generando informe HTML inicial")
    ips_files = {}
    for subnet in all_subnets:
        hosts_list = subnet_hosts[subnet]
        if hosts_list:
            ips_files[subnet] = save_ips_to_file(subnet, hosts_list, output_dir, live)

    generate_html_report(all_subnets, subnet_hosts, {},
                         args.profile, output_dir, live)
    live.log(f"  [i] Puedes abrir el HTML ahora; se actualizara al terminar nmap.")

    # ── Fase 3: nmap ─────────────────────────────────────────────────────────
    nmap_results = {}
    xml_files    = {}

    if not args.skip_nmap:
        live.section("FASE 3 / 3  Escaneo nmap")
        for subnet in all_subnets:
            hosts_list = subnet_hosts[subnet]
            if not hosts_list:
                live.log(f"  [-] {subnet}.0/24 sin hosts, omitiendo.")
                nmap_results[subnet] = {}
                continue
            ips_file = ips_files.get(subnet)
            if not ips_file:
                ips_file = save_ips_to_file(subnet, hosts_list, output_dir, live)
            xml_file = run_nmap(subnet, ips_file, output_dir, cfg, live)
            xml_files[subnet]    = xml_file
            nmap_results[subnet] = parse_nmap_xml(xml_file)
    else:
        for subnet in all_subnets:
            nmap_results[subnet] = {}

    # ── Informe final (con datos nmap) ────────────────────────────────────────
    live.section("Generando informe HTML final")
    generate_html_report(all_subnets, subnet_hosts, nmap_results,
                         args.profile, output_dir, live)

    live.log("\n  ── Archivos generados ──────────────────────────────────")
    live.log(f"  Carpeta: {output_dir}")
    for subnet in all_subnets:
        live.log(f"  {subnet}.0/24  ({len(subnet_hosts[subnet])} hosts)")
        if ips_files.get(subnet):
            live.log(f"    IPs  ->  {ips_files[subnet]}")
        if not args.skip_nmap and xml_files.get(subnet):
            live.log(f"    XML  ->  {xml_files[subnet]}")
    live.log(f"    HTML ->  {os.path.join(output_dir, 'network_report.html')}\n")


if __name__ == "__main__":
    main()
