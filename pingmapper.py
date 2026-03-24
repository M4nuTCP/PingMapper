#!/usr/bin/env python3

import argparse
import os
import platform
import subprocess
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from jinja2 import Template


def ping(ip, timeout=1.0):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", ip]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return ip, result.returncode == 0
    except subprocess.TimeoutExpired:
        return ip, False


def ping_subnet(subnet, timeout=1.0, max_workers=20, delay=0.0):
    active_hosts = []
    ip_range = [f"{subnet}.{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(lambda target: ping(target, timeout=timeout), ip_range))
    for ip, status in results:
        if delay:
            time.sleep(delay)
        if status:
            print(f"  [+] {ip}")
            active_hosts.append(ip)
    return active_hosts


def active_subnets(base_subnets, threads=30, timeout=1.0):
    active_networks = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = list(executor.map(lambda subnet: ping_subnet_start(subnet, timeout=timeout), base_subnets))
    for subnet, status in results:
        if status:
            print(f"[+] Trama de red detectada: {subnet}.0/24")
            active_networks.append(subnet)
    return active_networks


def ping_subnet_start(subnet, timeout=1.0):
    probe_hosts = [1, 254, 100, 50, 10, 200]
    for host in probe_hosts:
        _, status = ping(f"{subnet}.{host}", timeout=timeout)
        if status:
            return subnet, True
    return subnet, False


def save_ips_to_file(subnet, hosts, output_dir="."):
    filename = os.path.join(output_dir, f"ips_trama_{subnet}.0.txt")
    with open(filename, "w") as f:
        for ip in hosts:
            f.write(ip + "\n")
    print(f"[+] IPs guardadas: {filename}")
    return filename


def run_nmap(subnet, ips_file, output_dir=".", min_rate=1000):
    xml_output = os.path.join(output_dir, f"trama_{subnet}.0.xml")
    cmd = [
        "nmap",
        "-p-",
        "-sS",
        "-sV",
        "--min-rate", str(min_rate),
        "--open",
        "-n",
        "-Pn",
        "-oX", xml_output,
        "-iL", ips_file,
    ]
    print(f"\n[*] Lanzando nmap en {subnet}.0/24  (min-rate={min_rate})")
    print(f"    {' '.join(cmd)}\n")

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if proc.returncode == 0:
            print(f"[+] Nmap completado -> {xml_output}")
        else:
            print(f"[!] Nmap terminó con código {proc.returncode}")
            tail = proc.stdout[-2000:] if len(proc.stdout) > 2000 else proc.stdout
            print(tail)
    except FileNotFoundError:
        print("[!] nmap no encontrado. Instálalo con: sudo apt install nmap")
        return None

    return xml_output if os.path.exists(xml_output) else None


def parse_nmap_xml(xml_file):
    """Parsea el XML de nmap y devuelve {ip: {ports: [...], port_count: N}}."""
    hosts_data = {}
    if not xml_file or not os.path.exists(xml_file):
        return hosts_data

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            addr = host.find("address[@addrtype='ipv4']")
            if addr is None:
                continue
            ip = addr.get("addr")

            ports = []
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    state_elem = port.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
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
.host-ports { display: none; padding: 10px; background: #0c0c18; }
table.ports { width: 100%; border-collapse: collapse; font-size: 0.83em; }
table.ports th {
    background: #1e1e30; color: #4caf50;
    padding: 6px 10px; text-align: left; border-bottom: 1px solid #2a2a40;
}
table.ports td { padding: 5px 10px; border-bottom: 1px solid #18182a; font-family: monospace; }
table.ports tr:hover td { background: #16162a; }
.p-num  { color: #ff9800; }
.p-svc  { color: #81d4fa; }
.p-ver  { color: #aaa; }
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
    <div style="color:#4caf50;margin-top:3px">M4nuTCP</div>
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
        <div class="host-ports" id="h_{{ ip|replace('.','_') }}">
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
  var grid   = { color: '#1e1e2e' };
  var tickCfg = { color: '#888' };

  new Chart(document.getElementById('c1'), {
    type: 'bar',
    data: { labels: labels, datasets: [{ label: 'Hosts', data: counts, backgroundColor: pal }] },
    options: { responsive: true,
      plugins: { legend: { labels: { color: '#ccc' } } },
      scales: { x: { ticks: tickCfg, grid: grid }, y: { ticks: tickCfg, grid: grid } }
    }
  });

  new Chart(document.getElementById('c2'), {
    type: 'doughnut',
    data: { labels: labels, datasets: [{ data: pcts, backgroundColor: pal }] },
    options: { responsive: true, plugins: { legend: { labels: { color: '#ccc' } } } }
  });
});
</script>
</body>
</html>"""


def generate_html_report(subnets, hosts, nmap_data, output_dir="."):
    total_hosts = sum(len(hosts[s]) for s in subnets)
    total_open_ports = sum(
        nmap_data.get(s, {}).get(ip, {}).get("port_count", 0)
        for s in subnets for ip in hosts[s]
    )
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = Template(HTML_TEMPLATE).render(
        subnets=subnets,
        hosts=hosts,
        nmap_data=nmap_data,
        total_hosts=total_hosts,
        total_open_ports=total_open_ports,
        scan_time=scan_time,
    )
    path = os.path.join(output_dir, "network_report.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Informe HTML: {path}")


def build_subnet_list():
    return (
        [f"10.{i}.0" for i in range(256)]
        + [f"172.{i}.0" for i in range(16, 32)]
        + [f"192.168.{i}" for i in range(256)]
    )


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="PingMapper - Descubrimiento de red + nmap para auditorias",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Red empresarial sensible (conservador, no satura)
  sudo python3 pingmapper.py --nmap-rate 500 --subnet-threads 5 --host-threads 5 --delay 0.1

  # Red normal
  sudo python3 pingmapper.py --nmap-rate 1000

  # Red robusta / pentest agresivo
  sudo python3 pingmapper.py --nmap-rate 5000 --subnet-threads 30 --host-threads 20

  # Solo descubrimiento ping, sin nmap
  sudo python3 pingmapper.py --skip-nmap

  # Guardar todo en un directorio especifico
  sudo python3 pingmapper.py --output-dir /tmp/auditoria_cliente
        """,
    )
    parser.add_argument("--mode", choices=["subnets", "full"], default="full",
                        help="subnets=solo tramas, full=tramas+hosts (default: full)")
    parser.add_argument("--subnet-threads", type=int, default=30,
                        help="Hilos para deteccion de tramas (default: 30)")
    parser.add_argument("--host-threads", type=int, default=20,
                        help="Hilos para escaneo de hosts por ping (default: 20)")
    parser.add_argument("--ping-timeout", type=float, default=1.0,
                        help="Timeout por ping en segundos (default: 1.0)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Retardo entre pings en segundos, para redes sensibles (default: 0.0)")
    parser.add_argument("--skip-nmap", action="store_true",
                        help="Omitir escaneo nmap (solo ping sweep)")
    parser.add_argument("--nmap-rate", type=int, default=1000,
                        help="--min-rate de nmap. 500 =sensible, 1000=normal, 5000=agresivo (default: 1000)")
    parser.add_argument("--output-dir", default=".",
                        help="Directorio de salida para XMLs, TXTs e HTML (default: .)")
    return parser.parse_args()


def main():
    args = parse_arguments()
    os.makedirs(args.output_dir, exist_ok=True)

    print("\n[+] Escaneando tramas de red privadas...\n")
    active_subnets_list = active_subnets(
        build_subnet_list(), threads=args.subnet_threads, timeout=args.ping_timeout
    )
    all_subnets = sorted(set(active_subnets_list))
    subnet_hosts = {s: [] for s in all_subnets}

    if not all_subnets:
        print("[-] No se detectaron tramas activas.")
        return

    if args.mode == "full":
        for subnet in all_subnets:
            print(f"\n[+] Escaneando hosts en {subnet}.0/24...")
            subnet_hosts[subnet] = ping_subnet(
                subnet,
                timeout=args.ping_timeout,
                max_workers=args.host_threads,
                delay=args.delay,
            )

    nmap_results = {}
    xml_files = {}

    for subnet in all_subnets:
        hosts = subnet_hosts[subnet]
        if not hosts:
            print(f"[-] Sin hosts activos en {subnet}.0/24, omitiendo nmap.")
            nmap_results[subnet] = {}
            continue

        ips_file = save_ips_to_file(subnet, hosts, args.output_dir)

        if not args.skip_nmap:
            xml_file = run_nmap(subnet, ips_file, args.output_dir, min_rate=args.nmap_rate)
            xml_files[subnet] = xml_file
            nmap_results[subnet] = parse_nmap_xml(xml_file)
        else:
            nmap_results[subnet] = {}

    print("\n[+] Generando informe HTML...")
    generate_html_report(all_subnets, subnet_hosts, nmap_results, args.output_dir)

    print("\n===== Archivos generados =====")
    for subnet in all_subnets:
        print(f"  {subnet}.0/24")
        print(f"    IPs  -> {args.output_dir}/ips_trama_{subnet}.0.txt")
        if not args.skip_nmap and xml_files.get(subnet):
            print(f"    XML  -> {xml_files[subnet]}  (importar en pentest.ws)")
    print(f"    HTML -> {args.output_dir}/network_report.html\n")


if __name__ == "__main__":
    main()
