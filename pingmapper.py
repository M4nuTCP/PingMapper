#!/usr/bin/env python3

import os
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sniff, IP, ARP
from jinja2 import Template

def ping(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", ip]
    try:
        subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1)
        return ip, True
    except subprocess.TimeoutExpired:
        return ip, False

def ping_subnet(subnet):
    active_hosts = []
    ip_range = [f"{subnet}.{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(ping, ip_range)
    for ip, status in results:
        if status:
            print(f"{ip}")
            active_hosts.append(ip)
    return active_hosts

def active_subnets(base_subnets, threads=50):
    active_networks = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(ping_subnet_start, base_subnets)
    for subnet, status in results:
        if status:
            print(f"Trama de red detectada: {subnet}.0/24")
            active_networks.append(subnet)
    return active_networks

def ping_subnet_start(subnet):
    _, status = ping(f"{subnet}.1")
    return subnet, status

def generate_html_report(subnets, hosts):
    total_hosts = sum(len(hosts[subnet]) for subnet in subnets)
    template = """
    <html>
    <head>
        <title>Informe de Red</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #1e1e2f;
                color: #ffffff;
                margin: 0;
                padding: 0;
            }
            h2 {
                margin: 20px;
                border-bottom: 2px solid #4caf50;
                padding-bottom: 10px;
            }
            .container {
                margin: 20px;
            }
            .subnet {
                margin-bottom: 20px;
                border: 1px solid #4caf50;
                border-radius: 5px;
                padding: 15px;
                background-color: #2e2e3d;
            }
            .subnet h3 {
                margin: 0;
                cursor: pointer;
            }
            .hosts {
                margin-top: 10px;
                display: none;
            }
            .hosts ul {
                list-style-type: none;
                padding: 0;
            }
            .hosts li {
                padding: 5px;
                margin: 5px 0;
                background-color: #4caf50;
                color: #ffffff;
                border-radius: 3px;
            }
            .chart-section {
                display: flex;
                justify-content: space-around;
                flex-wrap: wrap;
                margin: 20px;
            }
            .chart-container {
                background-color: #2e2e3d;
                border-radius: 5px;
                padding: 20px;
                margin: 10px;
                text-align: center;
                width: 45%;
            }
            footer {
                text-align: center;
                margin: 20px 0;
                padding: 10px;
                background-color: #222;
                color: #ffffff;
            }
        </style>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script>
            function toggleHosts(id) {
                const element = document.getElementById(id);
                element.style.display = element.style.display === "none" ? "block" : "none";
            }
            document.addEventListener("DOMContentLoaded", function () {
                const ctx1 = document.getElementById('subnetChart1').getContext('2d');
                const ctx2 = document.getElementById('subnetChart2').getContext('2d');
                
                const data1 = {
                    labels: [{% for subnet in subnets %}"{{ subnet }}",{% endfor %}],
                    datasets: [{
                        label: 'Hosts dentro de la trama',
                        data: [{% for subnet in subnets %}{{ hosts[subnet]|length }},{% endfor %}],
                        backgroundColor: ['#4caf50', '#ff9800', '#2196f3', '#f44336']
                    }]
                };

                const data2 = {
                    labels: [{% for subnet in subnets %}"{{ subnet }}",{% endfor %}],
                    datasets: [{
                        label: 'Porcentaje de Hosts',
                        data: [{% for subnet in subnets %}{{ (hosts[subnet]|length / total_hosts) * 100 }},{% endfor %}],
                        backgroundColor: ['#4caf50', '#ff9800', '#2196f3', '#f44336']
                    }]
                };

                const config1 = {
                    type: 'bar',
                    data: data1,
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { display: true, labels: { color: '#ffffff' } }
                        },
                        scales: {
                            x: { ticks: { color: '#ffffff' } },
                            y: { ticks: { color: '#ffffff' } }
                        }
                    }
                };

                const config2 = {
                    type: 'pie',
                    data: data2,
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { display: true, labels: { color: '#ffffff' } }
                        }
                    }
                };

                new Chart(ctx1, config1);
                new Chart(ctx2, config2);
            });
        </script>
    </head>
    <body>
        <div class="container">
            <h2>Tramas de red detectadas:</h2>
            {% for subnet in subnets %}
            <div class="subnet">
                <h3 onclick="toggleHosts('hosts{{ loop.index }}')">{{ subnet }}.0/24</h3>
                <div class="hosts" id="hosts{{ loop.index }}">
                    <ul>
                        {% for host in hosts[subnet] %}
                        <li>{{ host }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </div>
            {% endfor %}
        </div>
        <div class="chart-section">
            <div class="chart-container">
                <canvas id="subnetChart1" width="400" height="300"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="subnetChart2" width="400" height="300"></canvas>
            </div>
        </div>
        <footer>
            &copy; M4nu
        </footer>
    </body>
    </html>
    """
    html_template = Template(template)
    html_content = html_template.render(subnets=subnets, hosts=hosts, total_hosts=total_hosts)
    with open("network_report.html", "w") as f:
        f.write(html_content)
    print("\n[+] Informe generado: network_report.html")

if __name__ == "__main__":
    private_subnets = [
        f"10.{i}.0" for i in range(256)
    ] + [
        f"172.{i}.0" for i in range(16, 32)
    ] + [
        f"192.168.{i}" for i in range(256)
    ]

    print("\n[+] Escaneando tramas de red...\n")
    active_subnets_list = active_subnets(private_subnets)
    all_subnets = set(active_subnets_list)
    subnet_hosts = {}
    for subnet in all_subnets:
        print(f"\n[+] Escaneando hosts en {subnet}.0/24...\n")
        subnet_hosts[subnet] = ping_subnet(subnet)
    generate_html_report(all_subnets, subnet_hosts)
