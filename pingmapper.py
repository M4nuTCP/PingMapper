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
# Merge XML nmap                                                                #
# --------------------------------------------------------------------------- #

def generate_all_ips_xml(xml_files: dict, output_dir: str, live: Live) -> str | None:
    """Fusiona todos los XML de nmap por subred en un unico all_ips.xml."""
    valid_files = [f for f in xml_files.values() if f and os.path.exists(f)]
    if not valid_files:
        live.log("  [-] No hay XMLs validos para generar all_ips.xml.")
        return None

    try:
        first_root = ET.parse(valid_files[0]).getroot()
    except ET.ParseError as e:
        live.log(f"  [!] Error parseando XML base: {e}")
        return None

    merged = ET.Element("nmaprun", first_root.attrib)

    for tag in ("scaninfo", "verbose", "debugging"):
        elem = first_root.find(tag)
        if elem is not None:
            merged.append(elem)

    total_hosts = 0
    for xml_file in valid_files:
        try:
            root = ET.parse(xml_file).getroot()
            for host in root.findall("host"):
                merged.append(host)
                total_hosts += 1
        except ET.ParseError as e:
            live.log(f"  [!] Error parseando {xml_file}: {e}")

    runstats = ET.SubElement(merged, "runstats")
    ET.SubElement(runstats, "finished",
        time=str(int(time.time())),
        timestr=datetime.now().strftime("%a %b %d %H:%M:%S %Y"),
        elapsed="0",
        summary=f"PingMapper merged scan; {total_hosts} hosts",
        exit="success",
    )
    ET.SubElement(runstats, "hosts", up=str(total_hosts), down="0", total=str(total_hosts))

    out_path = os.path.join(output_dir, "all_ips.xml")
    tree = ET.ElementTree(merged)
    ET.indent(tree, space="  ")
    with open(out_path, "wb") as f:
        f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write(b'<!DOCTYPE nmaprun>\n')
        tree.write(f, encoding="utf-8", xml_declaration=False)

    live.log(f"  [+] all_ips.xml ({total_hosts} hosts): {out_path}")
    return out_path


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
:root {
  --bg:       #0a0e17;
  --bg-soft:  #0f1420;
  --panel:    #141a28;
  --panel-2:  #1a2233;
  --border:   #232c40;
  --text:     #dce3ef;
  --muted:    #7a879e;
  --accent:   #3ddc84;
  --cyan:     #56c8ff;
  --orange:   #ffb454;
  --shadow:   0 8px 24px rgba(0,0,0,.35);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, Arial, sans-serif;
  background: radial-gradient(1200px 600px at 20% -10%, #12203a 0%, transparent 60%),
              radial-gradient(1000px 500px at 100% 0%, #0f2a24 0%, transparent 55%),
              var(--bg);
  color: var(--text); min-height: 100vh; -webkit-font-smoothing: antialiased;
}
.mono { font-family: 'JetBrains Mono','Fira Code','SFMono-Regular',Consolas,'Liberation Mono',monospace; }

header {
  position: sticky; top: 0; z-index: 50;
  background: rgba(12,17,28,.82); backdrop-filter: blur(10px);
  border-bottom: 1px solid var(--border); padding: 16px 32px;
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
}
.brand { display: flex; align-items: center; gap: 14px; }
.logo {
  width: 42px; height: 42px; border-radius: 11px;
  background: linear-gradient(135deg, var(--accent), var(--cyan));
  display: grid; place-items: center; font-size: 1.35em;
  box-shadow: 0 0 22px rgba(61,220,132,.35);
}
header h1 { font-size: 1.35em; font-weight: 700; letter-spacing: .5px; }
header h1 span { color: var(--accent); }
.subtitle { color: var(--muted); font-size: .78em; margin-top: 2px; letter-spacing: .3px; }
.meta { text-align: right; font-size: .8em; color: var(--muted); line-height: 1.5; }
.profile-badge {
  display: inline-block; margin-top: 3px;
  background: rgba(61,220,132,.12); border: 1px solid rgba(61,220,132,.4);
  color: var(--accent); font-size: .92em; border-radius: 20px; padding: 2px 12px;
}
.author { color: var(--accent); font-weight: 600; margin-top: 4px; }

.stats-bar {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 14px; padding: 22px 32px 8px;
}
.stat-card {
  background: linear-gradient(160deg, var(--panel), var(--bg-soft));
  border: 1px solid var(--border); border-radius: 14px;
  padding: 16px 20px; box-shadow: var(--shadow); position: relative; overflow: hidden;
}
.stat-card::before {
  content:''; position:absolute; left:0; top:0; bottom:0; width:3px;
  background: linear-gradient(var(--accent), var(--cyan));
}
.stat-card .num { font-size: 2.1em; font-weight: 800; color: var(--text); line-height: 1; }
.stat-card .lbl { font-size: .72em; color: var(--muted); text-transform: uppercase; letter-spacing: 1.4px; margin-top: 6px; }

.toolbar {
  display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
  padding: 16px 32px; justify-content: space-between;
}
.filter {
  flex: 1; min-width: 220px; max-width: 420px;
  background: var(--panel); border: 1px solid var(--border); color: var(--text);
  border-radius: 10px; padding: 10px 14px; font-size: .9em;
  transition: border-color .15s, box-shadow .15s;
}
.filter:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(61,220,132,.15); }
.filter::placeholder { color: var(--muted); }
.toolbar-actions { display: flex; flex-wrap: wrap; gap: 8px; }

.btn {
  display: inline-flex; align-items: center; gap: 6px;
  background: rgba(61,220,132,.12); color: var(--accent);
  border: 1px solid rgba(61,220,132,.38); border-radius: 8px;
  padding: 7px 13px; font-size: .78em; font-weight: 600;
  cursor: pointer; transition: all .15s ease; font-family: inherit; white-space: nowrap;
}
.btn:hover { background: rgba(61,220,132,.22); box-shadow: 0 0 14px rgba(61,220,132,.28); }
.btn:active { transform: translateY(1px); }
.btn-ghost { color: var(--cyan); background: rgba(86,200,255,.1); border-color: rgba(86,200,255,.35); }
.btn-ghost:hover { background: rgba(86,200,255,.2); box-shadow: 0 0 14px rgba(86,200,255,.25); }

.container { padding: 8px 32px 30px; }
.subnet-block {
  margin-bottom: 16px; border: 1px solid var(--border); border-radius: 14px;
  overflow: hidden; background: var(--bg-soft); box-shadow: var(--shadow);
}
.subnet-header {
  background: linear-gradient(120deg, var(--panel), var(--bg-soft));
  padding: 14px 18px; cursor: pointer; user-select: none;
  display: flex; justify-content: space-between; align-items: center; gap: 12px;
  transition: background .15s;
}
.subnet-header:hover { background: var(--panel-2); }
.sn-title { display: flex; align-items: center; gap: 12px; min-width: 0; }
.chevron { color: var(--accent); font-size: .8em; transition: transform .2s ease; display: inline-block; }
.subnet-block.open > .subnet-header .chevron { transform: rotate(90deg); }
.subnet-header h3 { color: var(--text); font-size: 1em; font-weight: 700; }
.sn-actions { display: flex; gap: 8px; flex-shrink: 0; }
.badge { border-radius: 20px; padding: 3px 11px; font-size: .72em; font-weight: 700; letter-spacing: .3px; }
.badge-green  { background: rgba(61,220,132,.18); color: var(--accent); border: 1px solid rgba(61,220,132,.4); }
.badge-orange { background: rgba(255,180,84,.16); color: var(--orange); border: 1px solid rgba(255,180,84,.4); }
.badge-grey   { background: rgba(122,135,158,.14); color: var(--muted); border: 1px solid rgba(122,135,158,.3); }
.subnet-body { display: none; padding: 14px 16px; background: var(--bg); border-top: 1px solid var(--border); }

.host-block { margin-bottom: 10px; border: 1px solid var(--border); border-radius: 10px; overflow: hidden; background: var(--panel); }
.host-block:last-child { margin-bottom: 0; }
.host-header {
  padding: 9px 14px; cursor: pointer;
  display: flex; justify-content: space-between; align-items: center; gap: 10px;
  transition: background .15s;
}
.host-header:hover { background: var(--panel-2); }
.host-left { display: flex; align-items: center; gap: 10px; }
.host-ip { color: var(--cyan); font-size: .92em; font-weight: 600; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 8px var(--accent); }
.host-ports-body { display: none; padding: 12px 14px; background: var(--bg); border-top: 1px solid var(--border); }

table.ports { width: 100%; border-collapse: collapse; font-size: .84em; }
table.ports th {
  background: var(--panel-2); color: var(--accent);
  padding: 8px 12px; text-align: left; font-weight: 600;
  text-transform: uppercase; font-size: .82em; letter-spacing: .6px;
}
table.ports td { padding: 7px 12px; border-bottom: 1px solid var(--border); }
table.ports tr:last-child td { border-bottom: none; }
table.ports tbody tr:hover td { background: rgba(86,200,255,.05); }
.p-num { color: var(--orange); font-weight: 600; }
.p-svc { color: var(--cyan); }
.p-ver { color: var(--muted); }
.no-data { color: var(--muted); font-size: .84em; padding: 6px 2px; font-style: italic; }

.charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 18px; padding: 8px 32px 32px; }
.chart-box { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 22px; box-shadow: var(--shadow); }
.chart-box h4 { color: var(--muted); margin-bottom: 16px; font-size: .78em; letter-spacing: 1.4px; text-transform: uppercase; }
.empty { text-align: center; color: var(--muted); padding: 60px 20px; }

footer { text-align: center; padding: 20px; color: var(--muted); font-size: .78em; border-top: 1px solid var(--border); }
footer span { color: var(--accent); }

.toast {
  position: fixed; bottom: 26px; left: 50%; transform: translateX(-50%) translateY(20px);
  background: var(--panel-2); color: var(--text); border: 1px solid var(--accent);
  padding: 11px 22px; border-radius: 10px; font-size: .88em; font-weight: 600;
  box-shadow: 0 8px 30px rgba(0,0,0,.5); opacity: 0; pointer-events: none;
  transition: opacity .2s, transform .2s; z-index: 100;
}
.toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }

@media (max-width: 640px) {
  header { flex-direction: column; align-items: flex-start; }
  .meta { text-align: left; }
  .subnet-header { flex-direction: column; align-items: flex-start; }
}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<header>
  <div class="brand">
    <div class="logo">&#128225;</div>
    <div>
      <h1>Ping<span>Mapper</span></h1>
      <div class="subtitle">Network Discovery &amp; Audit Report</div>
    </div>
  </div>
  <div class="meta">
    <div>{{ scan_time }}</div>
    <div><span class="profile-badge">perfil: {{ profile }}</span></div>
    <div class="author">M4nuTCP</div>
  </div>
</header>

<div class="stats-bar">
  <div class="stat-card"><div class="num">{{ subnets|length }}</div><div class="lbl">Subredes</div></div>
  <div class="stat-card"><div class="num">{{ total_hosts }}</div><div class="lbl">Hosts vivos</div></div>
  <div class="stat-card"><div class="num">{{ total_open_ports }}</div><div class="lbl">Puertos abiertos</div></div>
</div>

<div class="toolbar">
  <input id="filter" class="filter" placeholder="&#128269; Filtrar por IP, puerto o servicio..." oninput="applyFilter(this.value)">
  <div class="toolbar-actions">
    <button class="btn" onclick="expandAll(true)">Expandir todo</button>
    <button class="btn" onclick="expandAll(false)">Colapsar todo</button>
    <button class="btn" onclick="copyAllIps()">&#128203; Copiar todas las IPs</button>
    <button class="btn btn-ghost" onclick="downloadAllIps()">&#11015; Descargar todas .txt</button>
  </div>
</div>

<div class="container">
{% for subnet in subnets %}
  <div class="subnet-block" data-subnet="{{ subnet }}">
    <div class="subnet-header" onclick="tog('sn{{ loop.index }}', this)">
      <div class="sn-title">
        <span class="chevron">&#9656;</span>
        <h3 class="mono">{{ subnet }}.0/24</h3>
        <span class="badge {% if hosts[subnet]|length %}badge-green{% else %}badge-grey{% endif %}">{{ hosts[subnet]|length }} hosts</span>
      </div>
      <div class="sn-actions">
        <button class="btn" onclick="copyIps(event, this)" title="Copiar las IPs de esta trama">&#128203; Copiar IPs</button>
        <button class="btn btn-ghost" onclick="downloadIps(event, this, '{{ subnet }}')" title="Descargar trama_ips_{{ subnet }}.0.txt">&#11015; .txt</button>
      </div>
    </div>
    <div class="subnet-body" id="sn{{ loop.index }}">
      {% for ip in hosts[subnet] %}
      {% set hd = nmap_data.get(subnet, {}).get(ip, {}) %}
      {% set pts = hd.get('ports', []) %}
      <div class="host-block">
        <div class="host-header" onclick="tog('h_{{ ip|replace('.','_') }}', this)">
          <div class="host-left">
            <span class="dot"></span>
            <span class="host-ip mono">{{ ip }}</span>
          </div>
          {% if pts %}
          <span class="badge badge-orange">{{ pts|length }} puertos</span>
          {% else %}
          <span class="badge badge-grey">sin nmap</span>
          {% endif %}
        </div>
        <div class="host-ports-body" id="h_{{ ip|replace('.','_') }}">
          {% if pts %}
          <table class="ports mono">
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
      {% if not hosts[subnet] %}
      <div class="no-data">Sin hosts activos en esta subred.</div>
      {% endif %}
    </div>
  </div>
{% endfor %}
{% if not subnets %}
  <div class="empty">No se detectaron subredes activas.</div>
{% endif %}
</div>

<div class="charts">
  <div class="chart-box"><h4>Hosts por subred</h4><canvas id="c1"></canvas></div>
  <div class="chart-box"><h4>Distribuci&oacute;n (%)</h4><canvas id="c2"></canvas></div>
</div>
<footer>PingMapper &mdash; <span>M4nuTCP</span> &mdash; {{ scan_time }}</footer>
<div id="toast" class="toast"></div>

<script>
function tog(id, headerEl) {
  var e = document.getElementById(id);
  if (!e) return;
  var open = e.style.display === 'block';
  e.style.display = open ? 'none' : 'block';
  var block = headerEl ? headerEl.parentElement : e.parentElement;
  if (block) block.classList.toggle('open', !open);
}
function expandAll(open) {
  document.querySelectorAll('.subnet-body, .host-ports-body').forEach(function(b){
    b.style.display = open ? 'block' : 'none';
  });
  document.querySelectorAll('.subnet-block, .host-block').forEach(function(b){
    b.classList.toggle('open', open);
  });
}
function ipsIn(scope) {
  var ips = [];
  scope.querySelectorAll('.host-ip').forEach(function(el){
    var t = el.textContent.trim();
    if (t) ips.push(t);
  });
  return ips;
}
function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text).catch(function(){ return legacyCopy(text); });
  }
  return legacyCopy(text);
}
function legacyCopy(text) {
  return new Promise(function(resolve){
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta); resolve();
  });
}
function saveFile(filename, text) {
  var blob = new Blob([text], {type: 'text/plain;charset=utf-8'});
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  setTimeout(function(){ URL.revokeObjectURL(url); }, 1000);
}
function toast(msg) {
  var t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg; t.classList.add('show');
  clearTimeout(t._t);
  t._t = setTimeout(function(){ t.classList.remove('show'); }, 1800);
}
function copyIps(ev, btn) {
  ev.stopPropagation();
  var ips = ipsIn(btn.closest('.subnet-block'));
  if (!ips.length) { toast('No hay IPs en esta trama'); return; }
  copyText(ips.join('\\n')).then(function(){ toast(ips.length + ' IP(s) copiadas'); });
}
function downloadIps(ev, btn, subnet) {
  ev.stopPropagation();
  var ips = ipsIn(btn.closest('.subnet-block'));
  if (!ips.length) { toast('No hay IPs en esta trama'); return; }
  var name = 'trama_ips_' + subnet + '.0.txt';
  saveFile(name, ips.join('\\n') + '\\n');
  toast('Descargado ' + name);
}
function copyAllIps() {
  var ips = ipsIn(document);
  if (!ips.length) { toast('No hay IPs'); return; }
  copyText(ips.join('\\n')).then(function(){ toast(ips.length + ' IP(s) copiadas'); });
}
function downloadAllIps() {
  var ips = ipsIn(document);
  if (!ips.length) { toast('No hay IPs'); return; }
  saveFile('trama_ips_todas.txt', ips.join('\\n') + '\\n');
  toast('Descargado trama_ips_todas.txt (' + ips.length + ' IPs)');
}
function applyFilter(q) {
  q = (q || '').trim().toLowerCase();
  document.querySelectorAll('.subnet-block').forEach(function(sb){
    var any = false;
    sb.querySelectorAll('.host-block').forEach(function(hb){
      var match = !q || hb.textContent.toLowerCase().indexOf(q) !== -1;
      hb.style.display = match ? '' : 'none';
      if (match) any = true;
    });
    sb.style.display = any ? '' : 'none';
    var body = sb.querySelector('.subnet-body');
    if (q && body) { body.style.display = any ? 'block' : 'none'; sb.classList.toggle('open', any); }
  });
}
document.addEventListener('DOMContentLoaded', function () {
  var labels = [{% for s in subnets %}"{{ s }}.0/24",{% endfor %}];
  var counts = [{% for s in subnets %}{{ hosts[s]|length }},{% endfor %}];
  if (!labels.length || typeof Chart === 'undefined') return;
  var total  = counts.reduce(function(a,b){return a+b;}, 0) || 1;
  var pcts   = counts.map(function(c){return ((c/total)*100).toFixed(1);});
  var pal    = ['#3ddc84','#56c8ff','#ffb454','#ff6b6b','#b57bff','#00d4c8','#ffd93d','#ff8fb3'];
  var grid   = {color:'rgba(255,255,255,.06)'}; var tc = {color:'#7a879e'};
  new Chart(document.getElementById('c1'),{type:'bar',
    data:{labels:labels,datasets:[{label:'Hosts',data:counts,backgroundColor:pal,borderRadius:6}]},
    options:{responsive:true,plugins:{legend:{display:false}},
      scales:{x:{ticks:tc,grid:grid},y:{ticks:tc,grid:grid,beginAtZero:true}}}});
  new Chart(document.getElementById('c2'),{type:'doughnut',
    data:{labels:labels,datasets:[{data:pcts,backgroundColor:pal,borderColor:'#0a0e17',borderWidth:2}]},
    options:{responsive:true,cutout:'62%',plugins:{legend:{position:'right',labels:{color:'#dce3ef',font:{size:11},padding:12}}}}});
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

    # ── Generar all_ips.xml ───────────────────────────────────────────────────
    all_xml_path = None
    if not args.skip_nmap and xml_files:
        live.section("Generando all_ips.xml")
        all_xml_path = generate_all_ips_xml(xml_files, output_dir, live)

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
    live.log(f"    HTML ->  {os.path.join(output_dir, 'network_report.html')}")
    if all_xml_path:
        live.log(f"    ALL  ->  {all_xml_path}")
    live.log("")


if __name__ == "__main__":
    main()
