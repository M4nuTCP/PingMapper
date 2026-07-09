#!/usr/bin/env bash
#
# scan_trama.sh - Escaneo nmap por fases de una trama (CIDR).
# ----------------------------------------------------------
#   Fase 1  Equipos activos       (host discovery, nmap -sn)
#   Fase 2  Puertos de los equipos (--top-ports 1000 por defecto)
#   Fase 3  Servicios / versiones  (-sS -sV sobre los puertos encontrados)
#
# Genera (mismos nombres que PingMapper, importables en pentest.ws):
#   ips_trama_<red>.txt    - IPs activas, una por linea
#   ports_trama_<red>.gnmap- salida greppable de la fase de puertos
#   trama_<red>.xml        - resultado -sV en XML
#
# La fase 3 lanza exactamente tu comando preferido:
#   sudo nmap -p<puertos> -sS -sV --min-rate 3000 --open -vvv -n \
#             -oX trama_<red>.xml -Pn -iL ips_trama_<red>.txt
#
# Uso:
#   sudo ./scan_trama.sh 172.16.12.0/24
#   sudo ./scan_trama.sh 172.16.12.0/24 -r 5000 -o auditoria
#   sudo ./scan_trama.sh 10.0.0.0/24 --full-ports
#
set -euo pipefail

# ── Valores por defecto ─────────────────────────────────────────────────────
MIN_RATE=3000
TOP_PORTS=1000
FULL_PORTS=0
SKIP_DISCOVERY=0
OUTDIR="."
SUBNET=""

c_g="\033[1;32m"; c_b="\033[1;34m"; c_y="\033[1;33m"; c_r="\033[1;31m"; c_0="\033[0m"
info(){ echo -e "${c_b}[*]${c_0} $*"; }
ok(){   echo -e "${c_g}[+]${c_0} $*"; }
warn(){ echo -e "${c_y}[!]${c_0} $*"; }
err(){  echo -e "${c_r}[!]${c_0} $*" >&2; }

usage(){
  cat <<EOF
Uso: sudo $0 <trama_CIDR> [opciones]

  <trama_CIDR>          Trama a escanear, p.ej. 172.16.12.0/24

Opciones:
  -o, --output DIR      Carpeta de salida (default: .)
  -r, --min-rate N      min-rate de nmap (default: 3000)
  -t, --top-ports N     Puertos en la fase de descubrimiento (default: 1000)
  -f, --full-ports      Fase 2 escanea TODOS los puertos (-p-) en vez de --top-ports
  -n, --no-discovery    Omitir fase 1 y tratar toda la trama como activa (-Pn)
  -h, --help            Muestra esta ayuda

Ejemplos:
  sudo $0 172.16.12.0/24
  sudo $0 172.16.12.0/24 -r 5000 -o auditoria
  sudo $0 10.0.0.0/24 --full-ports
EOF
}

# ── Parseo de argumentos ────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output)       OUTDIR="${2:?falta el directorio}"; shift 2;;
    -r|--min-rate)     MIN_RATE="${2:?falta el valor}"; shift 2;;
    -t|--top-ports)    TOP_PORTS="${2:?falta el valor}"; shift 2;;
    -f|--full-ports)   FULL_PORTS=1; shift;;
    -n|--no-discovery) SKIP_DISCOVERY=1; shift;;
    -h|--help)         usage; exit 0;;
    -*)                err "Opcion desconocida: $1"; usage; exit 1;;
    *)                 if [[ -z "$SUBNET" ]]; then SUBNET="$1"; else err "Argumento extra: $1"; exit 1; fi; shift;;
  esac
done

[[ -z "$SUBNET" ]] && { err "Falta la trama (CIDR)."; usage; exit 1; }

# ── Comprobaciones ──────────────────────────────────────────────────────────
command -v nmap >/dev/null 2>&1 || { err "nmap no esta instalado.  sudo apt install nmap"; exit 1; }

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  err "Se necesita root para -sS/-sn (raw sockets)."
  err "Ejecuta:  sudo $0 $SUBNET"
  exit 1
fi

if [[ ! "$SUBNET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
  err "Formato de trama invalido: '$SUBNET'  (esperado p.ej. 172.16.12.0/24)"
  exit 1
fi

# Etiqueta de la red = parte anterior a la mascara (172.16.12.0/24 -> 172.16.12.0)
NET="${SUBNET%%/*}"
mkdir -p "$OUTDIR"
IPS_FILE="$OUTDIR/ips_trama_${NET}.txt"
PORTS_GNMAP="$OUTDIR/ports_trama_${NET}.gnmap"
XML_OUT="$OUTDIR/trama_${NET}.xml"

if [[ $FULL_PORTS -eq 1 ]]; then
  PORT_DESC="TODOS (-p-)"
else
  PORT_DESC="top-${TOP_PORTS}"
fi

echo
echo -e "${c_g}══════════════════════════════════════════════════════════${c_0}"
echo -e "  scan_trama  ·  trama ${c_g}${SUBNET}${c_0}"
echo -e "  min-rate=${MIN_RATE}   puertos-descubrimiento=${PORT_DESC}   salida=${OUTDIR}/"
echo -e "${c_g}══════════════════════════════════════════════════════════${c_0}"

# ── Fase 1: equipos activos ─────────────────────────────────────────────────
if [[ $SKIP_DISCOVERY -eq 1 ]]; then
  info "Fase 1/3  Descubrimiento omitido (--no-discovery): se escanea toda la trama."
  echo "$SUBNET" > "$IPS_FILE"
else
  info "Fase 1/3  Descubriendo equipos activos en ${SUBNET} ..."
  nmap -sn -n --min-rate "$MIN_RATE" "$SUBNET" -oG - 2>/dev/null \
    | awk '/Status: Up/{print $2}' | sort -V -u > "$IPS_FILE" || true

  COUNT=$(wc -l < "$IPS_FILE" | tr -d ' ')
  if [[ "$COUNT" -eq 0 ]]; then
    warn "No se detectaron equipos activos en ${SUBNET}."
    warn "Puedes forzar el escaneo de toda la trama con:  --no-discovery"
    exit 0
  fi
  ok "${COUNT} equipo(s) activo(s)  ->  ${IPS_FILE}"
  sed 's/^/      /' "$IPS_FILE"
fi

# ── Fase 2: puertos de los equipos ──────────────────────────────────────────
if [[ $FULL_PORTS -eq 1 ]]; then
  PORTSEL=(-p-)
else
  PORTSEL=(--top-ports "$TOP_PORTS")
fi
echo
info "Fase 2/3  Buscando puertos abiertos (${PORT_DESC}) sobre los equipos activos ..."
nmap -sS -n -Pn --open --min-rate "$MIN_RATE" "${PORTSEL[@]}" \
     -iL "$IPS_FILE" -oG "$PORTS_GNMAP" || warn "nmap (fase 2) devolvio un codigo != 0; se intenta continuar."

# Union de puertos TCP abiertos encontrados en toda la trama
PORTS=$(grep -hoE '[0-9]+/open/tcp' "$PORTS_GNMAP" 2>/dev/null | cut -d/ -f1 | sort -un | paste -sd, - || true)
if [[ -z "$PORTS" ]]; then
  warn "No se encontraron puertos TCP abiertos en la trama. Nada que analizar con -sV."
  echo "  IPs activas  ->  $IPS_FILE"
  exit 0
fi
NPORTS=$(echo "$PORTS" | tr ',' '\n' | grep -c .)
ok "${NPORTS} puerto(s) abierto(s) en la trama:  ${PORTS}"

# ── Fase 3: servicios / versiones (-sS -sV) ─────────────────────────────────
echo
info "Fase 3/3  Detectando servicios y versiones (-sS -sV) sobre: ${PORTS}"
echo -e "      ${c_b}nmap -p${PORTS} -sS -sV --min-rate ${MIN_RATE} --open -vvv -n -oX ${XML_OUT} -Pn -iL ${IPS_FILE}${c_0}"
echo
nmap -p"$PORTS" -sS -sV --min-rate "$MIN_RATE" --open -vvv -n \
     -oX "$XML_OUT" -Pn -iL "$IPS_FILE" || warn "nmap (fase 3) devolvio un codigo != 0."

# ── Resumen ─────────────────────────────────────────────────────────────────
echo
echo -e "${c_g}── Escaneo completado ────────────────────────────────────${c_0}"
echo "  IPs activas       ->  $IPS_FILE"
echo "  Puertos (grep)    ->  $PORTS_GNMAP"
echo "  Servicios (XML)   ->  $XML_OUT   (importable en pentest.ws)"
echo
