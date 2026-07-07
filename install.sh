#!/usr/bin/env bash
#
# PingMapper - Instalador para Kali Linux / Debian / Ubuntu
# ---------------------------------------------------------
# Instala PingMapper como binario del sistema (comando "pingmapper")
# para poder ejecutarlo desde cualquier ruta, sin depender de la
# carpeta donde se hizo el "git clone".
#
# Uso:
#   sudo ./install.sh              # instalar / actualizar
#   sudo ./install.sh --uninstall  # desinstalar
#
set -euo pipefail

PREFIX="/usr/local"
LIBDIR="$PREFIX/lib/pingmapper"
BINPATH="$PREFIX/bin/pingmapper"
RAW_URL="https://raw.githubusercontent.com/M4nuTCP/PingMapper/main/pingmapper.py"

c_green="\033[1;32m"; c_red="\033[1;31m"; c_blue="\033[1;34m"; c_reset="\033[0m"
info() { echo -e "${c_blue}[*]${c_reset} $*"; }
ok()   { echo -e "${c_green}[+]${c_reset} $*"; }
err()  { echo -e "${c_red}[!]${c_reset} $*" >&2; }

require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    err "Este script necesita privilegios de root."
    err "Ejecuta:  sudo $0 $*"
    exit 1
  fi
}

uninstall() {
  require_root "$@"
  info "Desinstalando PingMapper..."
  rm -f  "$BINPATH"
  rm -rf "$LIBDIR"
  ok "PingMapper desinstalado. (Las dependencias de Python no se han tocado.)"
  exit 0
}

# ── Desinstalacion ──────────────────────────────────────────────────────────
if [[ "${1:-}" == "--uninstall" || "${1:-}" == "-u" ]]; then
  uninstall "$@"
fi

require_root "$@"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo
echo "  ┌────────────────────────────────────────────┐"
echo "  │   PingMapper · Instalador para Kali Linux    │"
echo "  └────────────────────────────────────────────┘"
echo

# ── Dependencias del sistema ────────────────────────────────────────────────
if command -v apt-get >/dev/null 2>&1; then
  info "Instalando dependencias del sistema (nmap, python3, pip)..."
  apt-get update -qq || true
  if ! apt-get install -y nmap python3 python3-pip >/dev/null 2>&1; then
    err "Algun paquete apt no se pudo instalar; continuo de todos modos."
  fi
else
  err "apt-get no encontrado. Instala manualmente: nmap python3 python3-pip"
fi

# ── Dependencias de Python (jinja2) ─────────────────────────────────────────
info "Instalando dependencias de Python (jinja2)..."
if pip3 install --break-system-packages jinja2 >/dev/null 2>&1; then
  ok "jinja2 instalado (--break-system-packages)."
elif pip3 install jinja2 >/dev/null 2>&1; then
  ok "jinja2 instalado."
else
  err "No se pudo instalar jinja2 con pip3. Instalalo a mano:  pip3 install jinja2"
fi

# ── Copiar el codigo fuente a una ubicacion fija ────────────────────────────
mkdir -p "$LIBDIR"
if [[ -f "$SCRIPT_DIR/pingmapper.py" ]]; then
  info "Copiando PingMapper a $LIBDIR ..."
  cp "$SCRIPT_DIR/pingmapper.py" "$LIBDIR/pingmapper.py"
  [[ -f "$SCRIPT_DIR/requirements.txt" ]] && cp "$SCRIPT_DIR/requirements.txt" "$LIBDIR/"
else
  info "pingmapper.py no esta junto al instalador; descargando desde GitHub..."
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$RAW_URL" -o "$LIBDIR/pingmapper.py"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$LIBDIR/pingmapper.py" "$RAW_URL"
  else
    err "Ni curl ni wget disponibles y no hay pingmapper.py local. Aborto."
    exit 1
  fi
fi
chmod 0644 "$LIBDIR/pingmapper.py"

# ── Crear el lanzador (binario) ─────────────────────────────────────────────
info "Creando el comando en $BINPATH ..."
cat > "$BINPATH" <<EOF
#!/usr/bin/env bash
# Lanzador de PingMapper (generado por install.sh)
exec python3 "$LIBDIR/pingmapper.py" "\$@"
EOF
chmod 0755 "$BINPATH"

echo
ok "PingMapper instalado correctamente."
echo
echo "  Ejecutalo desde cualquier carpeta:"
echo -e "    ${c_green}sudo pingmapper --profile normal --name auditoria${c_reset}"
echo
echo "  Ver la ayuda:"
echo "    pingmapper --help"
echo
echo "  Desinstalar:"
echo "    sudo ./install.sh --uninstall"
echo
