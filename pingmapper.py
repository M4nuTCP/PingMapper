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
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PingMapper - Informe de Red</title>
<script>
(function () {
  try {
    var t = localStorage.getItem('pm-theme');
    if (t !== 'dark' && t !== 'light') {
      t = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
    }
    document.documentElement.setAttribute('data-theme', t);
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'light');
  }
})();
</script>
<style>
:root {
  color-scheme: light;
  --bg:            #f4f5f7;
  --surface:       #ffffff;
  --surface-2:     #f6f7f9;
  --border:        #e5e8ed;
  --border-2:      #d3d8e0;
  --border-hover:  #c2c8d2;
  --text:          #101828;
  --text-2:        #3a4256;
  --muted:         #667085;
  --primary:       #2456e6;
  --primary-strong:#1d47c4;
  --primary-soft:  #eef2fe;
  --primary-border:#d6e0fb;
  --ok:            #17a34a;
  --row-hover:     #f8f9fb;
  --focus-ring:    rgba(36,86,230,.14);
  --badge-green-bg:#ecfdf3; --badge-green-fg:#067647; --badge-green-bd:#abefc6;
  --badge-grey-bg: #f2f4f7; --badge-grey-fg: #667085; --badge-grey-bd: #e4e7ec;
  --toast-bg:      #101828; --toast-fg:#ffffff;
  --maxw:          1200px;
  --shadow:        0 1px 2px rgba(16,24,40,.06);
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --bg:            #0b0f17;
  --surface:       #121826;
  --surface-2:     #0e131e;
  --border:        #222b3b;
  --border-2:      #2c3648;
  --border-hover:  #3a465c;
  --text:          #eef1f6;
  --text-2:        #c3cad6;
  --muted:         #8a93a6;
  --primary:       #5b82f6;
  --primary-strong:#8aa6ff;
  --primary-soft:  rgba(91,130,246,.14);
  --primary-border:rgba(91,130,246,.36);
  --ok:            #35c46a;
  --row-hover:     rgba(255,255,255,.03);
  --focus-ring:    rgba(91,130,246,.28);
  --badge-green-bg:rgba(53,196,106,.14); --badge-green-fg:#4ade80; --badge-green-bd:rgba(53,196,106,.34);
  --badge-grey-bg: rgba(138,147,166,.14); --badge-grey-fg:#9aa4b6; --badge-grey-bd:rgba(138,147,166,.28);
  --toast-bg:      #eef1f6; --toast-fg:#0b0f17;
  --shadow:        0 1px 2px rgba(0,0,0,.4);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, Arial, sans-serif;
  background: var(--bg); color: var(--text-2);
  min-height: 100vh; -webkit-font-smoothing: antialiased;
}
.mono { font-family: 'JetBrains Mono','Fira Code','SFMono-Regular',Consolas,'Liberation Mono',monospace; }

header {
  position: sticky; top: 0; z-index: 50;
  background: var(--surface); border-bottom: 1px solid var(--border);
  padding: 15px 32px;
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
}
.brand { display: flex; align-items: center; gap: 12px; }
.logo { color: var(--primary); display: grid; place-items: center; }
.logo svg { display: block; }
header h1 { font-size: 1.15em; font-weight: 700; letter-spacing: -.2px; color: var(--text); }
header h1 span { color: var(--primary); }
.subtitle { color: var(--muted); font-size: .75em; margin-top: 1px; }
.header-right { display: flex; align-items: center; gap: 16px; }
.theme-toggle {
  display: inline-grid; place-items: center; width: 34px; height: 34px;
  background: var(--surface); color: var(--text-2);
  border: 1px solid var(--border-2); cursor: pointer;
  transition: background .15s, border-color .15s, color .15s;
}
.theme-toggle:hover { background: var(--surface-2); border-color: var(--border-hover); color: var(--text); }
.theme-toggle svg { display: block; }
.theme-toggle .icon-sun { display: none; }
:root[data-theme="dark"] .theme-toggle .icon-sun { display: block; }
:root[data-theme="dark"] .theme-toggle .icon-moon { display: none; }
.meta { text-align: right; font-size: .77em; color: var(--muted); line-height: 1.5; }
.profile-badge {
  display: inline-block; margin-top: 3px;
  background: var(--primary-soft); border: 1px solid var(--primary-border);
  color: var(--primary-strong); font-size: .95em; padding: 2px 9px; font-weight: 600;
}
.author { color: var(--text-2); font-weight: 600; margin-top: 3px; }

.stats-bar {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 14px; padding: 24px 32px 8px; max-width: var(--maxw); margin: 0 auto;
}
.stat-card {
  background: var(--surface); border: 1px solid var(--border);
  padding: 18px 20px; box-shadow: var(--shadow);
}
.stat-card .num { font-size: 1.9em; font-weight: 700; color: var(--text); line-height: 1; letter-spacing: -.5px; }
.stat-card .lbl { font-size: .72em; color: var(--muted); text-transform: uppercase; letter-spacing: .8px; margin-top: 6px; font-weight: 600; }

.toolbar {
  display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
  padding: 18px 32px; justify-content: space-between; max-width: var(--maxw); margin: 0 auto;
}
.filter-wrap { position: relative; display: flex; align-items: center; flex: 1; min-width: 220px; max-width: 420px; }
.filter-ic { position: absolute; left: 11px; color: var(--muted); pointer-events: none; }
.filter {
  width: 100%;
  background: var(--surface); border: 1px solid var(--border-2); color: var(--text);
  padding: 9px 13px 9px 34px; font-size: .9em; font-family: inherit;
  transition: border-color .15s, box-shadow .15s;
}
.filter:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px var(--focus-ring); }
.filter::placeholder { color: var(--muted); }
.toolbar-actions { display: flex; flex-wrap: wrap; gap: 8px; }

.btn {
  display: inline-flex; align-items: center; gap: 6px;
  background: var(--surface); color: var(--text-2);
  border: 1px solid var(--border-2);
  padding: 8px 13px; font-size: .8em; font-weight: 600;
  cursor: pointer; transition: background .15s, border-color .15s, color .15s; font-family: inherit; white-space: nowrap;
}
.btn svg { flex-shrink: 0; }
.btn:hover { background: var(--surface-2); border-color: var(--border-hover); }
.btn:active { transform: translateY(.5px); }
.btn-ghost { color: var(--primary); }
.btn-ghost:hover { background: var(--primary-soft); border-color: var(--primary-border); color: var(--primary-strong); }

.container { padding: 8px 32px 30px; max-width: var(--maxw); margin: 0 auto; }
.subnet-block {
  margin-bottom: 12px; border: 1px solid var(--border);
  overflow: hidden; background: var(--surface); box-shadow: var(--shadow);
}
.subnet-header {
  background: var(--surface); padding: 14px 18px; cursor: pointer; user-select: none;
  display: flex; justify-content: space-between; align-items: center; gap: 12px;
  transition: background .15s;
}
.subnet-header:hover { background: var(--surface-2); }
.sn-title { display: flex; align-items: center; gap: 11px; min-width: 0; }
.chevron { color: var(--muted); font-size: .72em; transition: transform .2s ease; display: inline-block; }
.subnet-block.open > .subnet-header .chevron { transform: rotate(90deg); }
.subnet-header h3 { color: var(--text); font-size: .95em; font-weight: 600; }
.sn-actions { display: flex; gap: 8px; flex-shrink: 0; }
.badge { padding: 3px 9px; font-size: .72em; font-weight: 600; letter-spacing: .2px; }
.badge-green  { background: var(--badge-green-bg); color: var(--badge-green-fg); border: 1px solid var(--badge-green-bd); }
.badge-orange { background: var(--primary-soft); color: var(--primary-strong); border: 1px solid var(--primary-border); }
.badge-grey   { background: var(--badge-grey-bg); color: var(--badge-grey-fg); border: 1px solid var(--badge-grey-bd); }
.subnet-body { display: none; padding: 12px 14px; background: var(--surface-2); border-top: 1px solid var(--border); }

.host-block { margin-bottom: 8px; border: 1px solid var(--border); overflow: hidden; background: var(--surface); }
.host-block:last-child { margin-bottom: 0; }
.host-header {
  padding: 9px 14px; cursor: pointer;
  display: flex; justify-content: space-between; align-items: center; gap: 10px;
  transition: background .15s;
}
.host-header:hover { background: var(--surface-2); }
.host-left { display: flex; align-items: center; gap: 10px; }
.host-ip { color: var(--text); font-size: .9em; font-weight: 600; }
.dot { width: 7px; height: 7px; background: var(--ok); flex-shrink: 0; }
.host-ports-body { display: none; padding: 10px 12px; background: var(--surface-2); border-top: 1px solid var(--border); }

table.ports { width: 100%; border-collapse: collapse; font-size: .84em; }
table.ports th {
  color: var(--muted); padding: 7px 10px; text-align: left; font-weight: 600;
  text-transform: uppercase; font-size: .78em; letter-spacing: .5px; border-bottom: 1px solid var(--border);
}
table.ports td { padding: 7px 10px; border-bottom: 1px solid var(--border); color: var(--text-2); }
table.ports tr:last-child td { border-bottom: none; }
table.ports tbody tr:hover td { background: var(--row-hover); }
.p-num { color: var(--primary-strong); font-weight: 600; }
.p-svc { color: var(--text); }
.p-ver { color: var(--muted); }
.no-data { color: var(--muted); font-size: .84em; padding: 6px 2px; }

.charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; padding: 16px 32px 40px; max-width: var(--maxw); margin: 0 auto; }
.chart-card { background: var(--surface); border: 1px solid var(--border); padding: 20px 22px; box-shadow: var(--shadow); }
.chart-card h4 { color: var(--text); margin-bottom: 3px; font-size: .9em; font-weight: 600; }
.chart-sub { color: var(--muted); font-size: .76em; margin-bottom: 16px; }
.chart-wrap { position: relative; height: 280px; }
.empty { text-align: center; color: var(--muted); padding: 60px 20px; }

footer { text-align: center; padding: 24px; color: var(--muted); font-size: .78em; border-top: 1px solid var(--border); margin-top: 8px; }
footer span { color: var(--primary); font-weight: 600; }

.toast {
  position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%) translateY(16px);
  background: var(--toast-bg); color: var(--toast-fg);
  padding: 10px 18px; font-size: .85em; font-weight: 500;
  box-shadow: 0 6px 20px rgba(0,0,0,.25); opacity: 0; pointer-events: none;
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
    <div class="logo">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="1.7" fill="currentColor" stroke="none"/>
        <path d="M8.6 8.6a4.8 4.8 0 0 0 0 6.8"/><path d="M15.4 8.6a4.8 4.8 0 0 1 0 6.8"/>
        <path d="M5.8 5.8a9 9 0 0 0 0 12.4"/><path d="M18.2 5.8a9 9 0 0 1 0 12.4"/>
      </svg>
    </div>
    <div>
      <h1>Ping<span>Mapper</span></h1>
      <div class="subtitle">Network Discovery &amp; Audit Report</div>
    </div>
  </div>
  <div class="header-right">
    <button class="theme-toggle" onclick="toggleTheme()" aria-label="Cambiar tema" title="Cambiar tema claro / oscuro">
      <svg class="icon-moon" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>
      <svg class="icon-sun" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
    </button>
    <div class="meta">
      <div>{{ scan_time }}</div>
      <div><span class="profile-badge">perfil: {{ profile }}</span></div>
      <div class="author">M4nuTCP</div>
    </div>
  </div>
</header>

<div class="stats-bar">
  <div class="stat-card"><div class="num">{{ subnets|length }}</div><div class="lbl">Subredes</div></div>
  <div class="stat-card"><div class="num">{{ total_hosts }}</div><div class="lbl">Hosts vivos</div></div>
  <div class="stat-card"><div class="num">{{ total_open_ports }}</div><div class="lbl">Puertos abiertos</div></div>
</div>

<div class="toolbar">
  <div class="filter-wrap">
    <svg class="filter-ic" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
    <input id="filter" class="filter" placeholder="Filtrar por IP, puerto o servicio..." oninput="applyFilter(this.value)">
  </div>
  <div class="toolbar-actions">
    <button class="btn" onclick="expandAll(true)">Expandir todo</button>
    <button class="btn" onclick="expandAll(false)">Colapsar todo</button>
    <button class="btn" onclick="copyAllIps()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11"/><path d="M5 15V5a1 1 0 0 1 1-1h9"/></svg>Copiar todas las IPs</button>
    <button class="btn btn-ghost" onclick="downloadAllIps()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="M7 11l5 4 5-4"/><path d="M5 20h14"/></svg>Descargar todas .txt</button>
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
        <button class="btn" onclick="copyIps(event, this)" title="Copiar las IPs de esta trama"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11"/><path d="M5 15V5a1 1 0 0 1 1-1h9"/></svg>Copiar IPs</button>
        <button class="btn btn-ghost" onclick="downloadIps(event, this, '{{ subnet }}')" title="Descargar trama_ips_{{ subnet }}.0.txt"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="M7 11l5 4 5-4"/><path d="M5 20h14"/></svg>.txt</button>
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

<section class="charts">
  <div class="chart-card">
    <h4>Hosts por subred</h4>
    <div class="chart-sub">Hosts activos detectados en cada trama</div>
    <div class="chart-wrap"><canvas id="c1"></canvas></div>
  </div>
  <div class="chart-card">
    <h4>Distribuci&oacute;n de hosts</h4>
    <div class="chart-sub">Peso relativo de cada trama sobre el total</div>
    <div class="chart-wrap"><canvas id="c2"></canvas></div>
  </div>
</section>
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
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('pm-theme', t); } catch (e) {}
  renderCharts();
}
function toggleTheme() {
  var cur = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  applyTheme(cur === 'dark' ? 'light' : 'dark');
}

var CHART_LABELS = [{% for s in subnets %}"{{ s }}.0/24",{% endfor %}];
var CHART_COUNTS = [{% for s in subnets %}{{ hosts[s]|length }},{% endfor %}];
var _charts = [];
function renderCharts() {
  if (typeof Chart === 'undefined' || !CHART_LABELS.length) return;
  var dark    = document.documentElement.getAttribute('data-theme') === 'dark';
  var textC   = dark ? '#8a93a6' : '#667085';
  var gridC   = dark ? 'rgba(255,255,255,.07)' : '#eef0f3';
  var sliceBd = dark ? '#121826' : '#ffffff';
  var legendC = dark ? '#c3cad6' : '#3a4256';
  var barC    = dark ? '#5b82f6' : '#2456e6';
  var barH    = dark ? '#7c9dff' : '#1d47c4';
  var tipBg   = dark ? '#eef1f6' : '#101828';
  var tipFg   = dark ? '#101828' : '#ffffff';
  var pal     = dark
    ? ['#5b82f6','#9b8cff','#22c1d6','#7aa2ff','#b79bff','#4bcb93','#f0ad4e','#f27a9b']
    : ['#2456e6','#6b5bd6','#0ea5b7','#5b8def','#9b6dd6','#2f9e78','#e08a2b','#dc5b7a'];
  var colors = CHART_LABELS.map(function(_, i){ return pal[i % pal.length]; });

  Chart.defaults.font.family = "'Inter', -apple-system, 'Segoe UI', Roboto, Arial, sans-serif";
  Chart.defaults.color = textC;
  var tip = {backgroundColor:tipBg, titleColor:tipFg, bodyColor:tipFg, padding:10, cornerRadius:0,
    titleFont:{size:12, weight:'600'}, bodyFont:{size:12}};

  _charts.forEach(function(c){ try { c.destroy(); } catch (e) {} });
  _charts = [];

  _charts.push(new Chart(document.getElementById('c1'), {type:'bar',
    data:{labels:CHART_LABELS, datasets:[{label:'Hosts', data:CHART_COUNTS,
      backgroundColor:barC, hoverBackgroundColor:barH, borderRadius:0, maxBarThickness:52}]},
    options:{responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}, tooltip:Object.assign({displayColors:false}, tip)},
      scales:{
        x:{grid:{display:false}, border:{display:false}, ticks:{color:textC, font:{size:12}}},
        y:{beginAtZero:true, grid:{color:gridC}, border:{display:false}, ticks:{color:textC, precision:0, font:{size:12}}}
      }}}));

  _charts.push(new Chart(document.getElementById('c2'), {type:'doughnut',
    data:{labels:CHART_LABELS, datasets:[{data:CHART_COUNTS, backgroundColor:colors,
      borderColor:sliceBd, borderWidth:2, hoverOffset:6}]},
    options:{responsive:true, maintainAspectRatio:false, cutout:'66%',
      plugins:{
        legend:{position:'right', labels:{color:legendC, font:{size:12}, padding:14,
          usePointStyle:true, pointStyle:'circle', boxWidth:8}},
        tooltip:Object.assign({displayColors:true, callbacks:{label:function(ctx){
          var t = ctx.dataset.data.reduce(function(a,b){return a+b;}, 0) || 1;
          var v = ctx.parsed;
          return ' ' + v + ' hosts (' + ((v/t)*100).toFixed(1) + '%)';
        }}}, tip)
      }}}));
}
document.addEventListener('DOMContentLoaded', renderCharts);
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
