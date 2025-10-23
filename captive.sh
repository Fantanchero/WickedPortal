#!/usr/bin/env bash
# deploy_captive_portal.sh - Captive portal "auth-first" con sesión atada a la conexión (IP+MAC)
# Requisitos implementados:
# - Android: NO TOCAR (sigue devolviendo 204 y funciona bien).
# - iOS/macOS/Windows: respuesta inmediata post-login sin redirects, según probe esperado.
# - Persistencia de autorización por sesión de conexión: mientras el equipo siga conectado, navega.
#   Si se desconecta (DHCP del o desaparición ARP/lease), se revoca la autorización y debe reautenticarse.
# - Coherencia IP/MAC: si una IP se reasigna a otra MAC, NO hereda autorización.
# - ALLOWED_TTL desactivado (0): el vencimiento ocurre al desconectarse, no por tiempo.
# - Hook de dnsmasq (dhcp-script) para sincronizar reglas en alta/baja de lease.
# - Limpieza automática por watchdog en la app (revisa leases y ARP/neighbor y revoca si no está conectado).
# - clear_captive.sh se genera en el MISMO directorio de este script.
#
# IMPORTANTE: ejecuta con bash. Si lo lanzas con "sh", se reejecuta con bash para evitar "Bad substitution".
if [ -z "${BASH_VERSION:-}" ]; then
  exec /usr/bin/env bash "$0" "$@"
fi

set -euo pipefail

# --- Configuración ---
LAN_IF="eth1"
LAN_IP="192.168.3.1/24"
WAN_IF="eth0"

DNSMASQ_CONF="/etc/dnsmasq.d/lab-captive.conf"
APP_DIR="/opt/captive"
APP_PY="$APP_DIR/portal_allow.py"
DHCP_HOOK="$APP_DIR/dhcp_hook.sh"
SYSTEMD_UNIT="/etc/systemd/system/captive-portal.service"
CSV_FILE="/tmp/submissions.csv"
ALLOWED_FILE="/tmp/allowed_ips.txt"    # formato: ip,mac,timestamp_epoch
DNS_LOG="/var/log/dnsmasq-lab.log"
LEASES_FILE="/var/lib/misc/dnsmasq.leases"
LOCK_FILE="/tmp/captive.lock"

# TTL desactivado: 0 (la sesión termina por desconexión, no por tiempo)
ALLOWED_TTL="${ALLOWED_TTL:-0}"

# Directorio del script (para dejar aquí clear_captive.sh)
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root"; exit 1
fi

# Respaldo de iptables
iptables-save > "/root/iptables-backup-$(date +%F-%T).rules" || true

# Parar despliegue previo
systemctl stop captive-portal.service 2>/dev/null || true
pkill -f "$APP_PY" 2>/dev/null || true

apt-get update -qq
apt-get install -y dnsmasq python3 python3-flask conntrack iptables-persistent dnsutils >/dev/null

# Liberar :53 si systemd-resolved está activo (lab)
if systemctl is-active --quiet systemd-resolved; then
  systemctl stop systemd-resolved || true
  systemctl disable systemd-resolved || true
fi

# Limpiar reglas previas (lab_captive_allow & PORTAL)
while iptables -S | grep -q "lab_captive_allow"; do
  RULE=$(iptables -S | grep lab_captive_allow | head -n1 || true)
  IP=$(echo "$RULE" | awk '{for(i=1;i<=NF;i++) if($i=="-s") print $(i+1)}' || true)
  if [ -n "${IP:-}" ]; then
    iptables -D FORWARD -s "$IP" -j ACCEPT -m comment --comment lab_captive_allow 2>/dev/null || true
    iptables -t nat -D PREROUTING -s "$IP" -i "$LAN_IF" -p tcp --dport 80 -j ACCEPT -m comment --comment lab_captive_allow_nat 2>/dev/null || true
    iptables -t nat -D PREROUTING -s "$IP" -p tcp --dport 80 -j ACCEPT -m comment --comment lab_captive_allow_nat 2>/dev/null || true
    iptables -t nat -D PORTAL -s "$IP" -j RETURN 2>/dev/null || true
  else
    iptables -S FORWARD | nl -ba | grep lab_captive_allow | awk '{print $1}' | while read -r n; do iptables -D FORWARD "$n" 2>/dev/null || true; done || true
  fi
done

if iptables -t nat -L PORTAL >/dev/null 2>&1; then
  iptables -t nat -F PORTAL 2>/dev/null || true
  iptables -t nat -D PREROUTING -i "$LAN_IF" -p tcp --dport 80 -j PORTAL 2>/dev/null || true
  iptables -t nat -X PORTAL 2>/dev/null || true
fi

# Configurar IP LAN
ip addr flush dev "$LAN_IF" || true
ip addr add "$LAN_IP" dev "$LAN_IF" || true
ip link set "$LAN_IF" up

# Config dnsmasq (wildcard + hook DHCP)
cat > "$DNSMASQ_CONF" <<EOF
interface=$LAN_IF
bind-interfaces
dhcp-range=192.168.3.50,192.168.3.150,12h
dhcp-option=3,${LAN_IP%/*}
dhcp-option=6,${LAN_IP%/*}
log-queries
log-facility=${DNS_LOG}
address=/#/${LAN_IP%/*}
dhcp-script=${DHCP_HOOK}
EOF

systemctl restart dnsmasq
sleep 1

# Habilitar forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null
cat > /etc/sysctl.d/99-captive.conf <<EOF
net.ipv4.ip_forward = 1
EOF
sysctl --system >/dev/null || true

# NAT en WAN
if ip link show "$WAN_IF" >/dev/null 2>&1 && ip addr show "$WAN_IF" | grep -q "inet "; then
  iptables -t nat -C POSTROUTING -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE
fi

# Cadena PORTAL y redirección HTTP->80 local
iptables -t nat -N PORTAL 2>/dev/null || true
iptables -t nat -C PREROUTING -i "$LAN_IF" -p tcp --dport 80 -j PORTAL 2>/dev/null || \
  iptables -t nat -A PREROUTING -i "$LAN_IF" -p tcp --dport 80 -j PORTAL
iptables -t nat -C PORTAL -p tcp -j REDIRECT --to-ports 80 2>/dev/null || \
  iptables -t nat -A PORTAL -p tcp -j REDIRECT --to-ports 80

# Aceptar ESTABLISHED/RELATED antes del DROP global
iptables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Política por defecto
iptables -P FORWARD DROP

# Permitir servicios locales (DHCP/DNS/HTTP) desde LAN
iptables -C INPUT -i "$LAN_IF" -p udp --dport 67 -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$LAN_IF" -p udp --dport 67 -j ACCEPT
iptables -C INPUT -i "$LAN_IF" -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$LAN_IF" -p udp --dport 53 -j ACCEPT
iptables -C INPUT -i "$LAN_IF" -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$LAN_IF" -p tcp --dport 80 -j ACCEPT

# Forzar DNS hacia el gateway (dnsmasq) y bloquear DNS externos
iptables -C FORWARD -i "$LAN_IF" -p udp --dport 53 -d "${LAN_IP%/*}" -j ACCEPT 2>/dev/null || iptables -I FORWARD 2 -i "$LAN_IF" -p udp --dport 53 -d "${LAN_IP%/*}" -j ACCEPT
iptables -C FORWARD -i "$LAN_IF" -p tcp --dport 53 -d "${LAN_IP%/*}" -j ACCEPT 2>/dev/null || iptables -I FORWARD 3 -i "$LAN_IF" -p tcp --dport 53 -d "${LAN_IP%/*}" -j ACCEPT
iptables -C FORWARD -i "$LAN_IF" -p udp --dport 53 -j DROP 2>/dev/null || iptables -A FORWARD -i "$LAN_IF" -p udp --dport 53 -j DROP
iptables -C FORWARD -i "$LAN_IF" -p tcp --dport 53 -j DROP 2>/dev/null || iptables -A FORWARD -i "$LAN_IF" -p tcp --dport 53 -j DROP

# Bloquear HTTPS/DoT a no autenticados (por IP se habilita tras login)
iptables -C FORWARD -i "$LAN_IF" -p tcp --dport 443 -j DROP 2>/dev/null || iptables -A FORWARD -i "$LAN_IF" -p tcp --dport 443 -j DROP
iptables -C FORWARD -i "$LAN_IF" -p tcp --dport 853 -j DROP 2>/dev/null || iptables -A FORWARD -i "$LAN_IF" -p tcp --dport 853 -j DROP

# Limpiar conntrack para la subred LAN
if command -v conntrack >/dev/null 2>&1; then
  conntrack -D -s "${LAN_IP%/*}" || true
fi

# --- App Flask (IP+MAC+TS; autoriza async; responde probes; watchdog de desconexión) ---
mkdir -p "$APP_DIR"
cat > "$APP_PY" <<'PY'
#!/usr/bin/env python3
from flask import Flask, request, render_template_string, make_response, jsonify
import csv, datetime, os, subprocess, sys, time, threading, re, fcntl

CSVFILE = '/tmp/submissions.csv'
ALLOWED_FILE = '/tmp/allowed_ips.txt'    # ip,mac,ts_epoch
DNSMASQ_CONF = '/etc/dnsmasq.d/lab-captive.conf'
LEASES_FILE = '/var/lib/misc/dnsmasq.leases'
LOCK_FILE = '/tmp/captive.lock'
APP_PORT = 80

def _intenv(k, d):
    try: return int(os.environ.get(k, str(d)))
    except Exception: return d

ALLOWED_TTL = _intenv('ALLOWED_TTL', 0)   # 0 = sin TTL; se revoca por desconexión
LAN_IF = os.environ.get('LAN_IF', '')
LAN_IP = os.environ.get('LAN_IP', '')  # sin máscara

app = Flask(__name__)

SPLASH = """<!doctype html><html><head><meta charset="utf-8"><title>Captive</title></head>
<body>
<h3>Captive Portal</h3>
<form id="f" method="post" action="/login" autocomplete="off">
  <label>Nombre: <input name="nombre" required></label><br>
  <label>Email: <input name="email"></label><br>
  <button id="b" type="submit">Ingresar</button>
</form>
<script> (function(){var f=document.getElementById('f'), b=document.getElementById('b'); if(f&&b){f.addEventListener('submit',function(){b.disabled=true;b.innerText='Ingresando...';},{once:true});}})(); </script>
</body></html>"""

APPLE_SUCCESS_HTML = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
MSFT_CONNECT = "Microsoft Connect Test"
MSFT_NCSI = "Microsoft NCSI"
FIREFOX_SUCCESS = "success\n"

NO_CACHE = {'Cache-Control':'no-store, no-cache, must-revalidate, max-age=0','Pragma':'no-cache','Expires':'0'}

def ensure_csv():
    if not os.path.exists(CSVFILE):
        with open(CSVFILE, 'w', newline='') as f:
            csv.writer(f).writerow(['ts','client_ip','user_agent','path','host','nombre','email'])

def log_submission(ip, ua, path, host, form):
    ensure_csv()
    try:
        with open(CSVFILE, 'a', newline='') as f:
            csv.writer(f).writerow([datetime.datetime.utcnow().iso8601() if hasattr(datetime.datetime.utcnow(), 'iso8601') else datetime.datetime.utcnow().isoformat(), ip, ua, path, host, form.get('nombre',''), form.get('email','')])
    except Exception as e:
        print("log_submission error:", e, file=sys.stderr)

def now_ts(): return int(time.time())

def _lock_file():
    f = open(LOCK_FILE, 'a+')
    fcntl.flock(f, fcntl.LOCK_EX)
    return f

def read_allowed():
    # returns dict: ip -> {'mac': mac, 'ts': ts}
    d={}
    if not os.path.exists(ALLOWED_FILE): return d
    try:
        with open(ALLOWED_FILE,'r') as fh:
            for line in fh:
                line=line.strip()
                if not line: continue
                parts=line.split(',')
                if len(parts)>=3:
                    ip=parts[0].strip(); mac=parts[1].strip()
                    try: ts=int(parts[2].strip())
                    except: ts=0
                    d[ip]={'mac':mac,'ts':ts}
    except Exception as e:
        print("read_allowed error:", e, file=sys.stderr)
    return d

def write_allowed(d):
    try:
        with open(ALLOWED_FILE,'w') as fh:
            for ip,meta in d.items():
                mac=meta.get('mac',''); ts=meta.get('ts',0)
                fh.write(f"{ip},{mac},{ts}\n")
            fh.flush(); os.fsync(fh.fileno())
    except Exception as e:
        print("write_allowed error:", e, file=sys.stderr)

def get_mac_from_leases(ip):
    try:
        with open(LEASES_FILE,'r') as f:
            for line in f:
                parts=line.strip().split()
                if len(parts)>=3:
                    mac=parts[1].lower(); lip=parts[2]
                    if lip==ip: return mac
    except Exception: pass
    return ''

def get_mac_for_ip(ip):
    mac = get_mac_from_leases(ip)
    if mac: return mac
    try:
        cmd=['ip','neigh','show','to',ip]
        if LAN_IF: cmd+=['dev',LAN_IF]
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1.5)
        m = re.search(r'(?i)lladdr\s+([0-9a-f:]{17})', cp.stdout or '')
        if m: return m.group(1).lower()
    except Exception: pass
    try:
        cp = subprocess.run(['arp','-n',ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1.5)
        m = re.search(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})', cp.stdout or '', re.I)
        if m: return m.group(1).lower()
    except Exception: pass
    return ''

def add_allowed(ip):
    mac = get_mac_for_ip(ip)
    lock = _lock_file()
    try:
        d=read_allowed()
        d[ip]={'mac':mac,'ts':now_ts()}
        write_allowed(d)
    finally:
        try: fcntl.flock(lock, fcntl.LOCK_UN); lock.close()
        except Exception: pass
    return mac

def remove_allowed(ip):
    lock = _lock_file()
    try:
        d=read_allowed()
        if ip in d:
            del d[ip]
            write_allowed(d)
    finally:
        try: fcntl.flock(lock, fcntl.LOCK_UN); lock.close()
        except Exception: pass

def rule_exists(cmd):
    try:
        cp=subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return cp.returncode==0
    except Exception:
        return False

def iptables_allow(ip):
    # NAT PORTAL RETURN
    try:
        if not rule_exists(['iptables','-t','nat','-C','PORTAL','-s',ip,'-j','RETURN']):
            subprocess.run(['iptables','-t','nat','-I','PORTAL','1','-s',ip,'-j','RETURN'], check=False)
    except Exception as e:
        print("nat RETURN error:", e, file=sys.stderr)
    # NAT PREROUTING BYPASS
    try:
        chk=['iptables','-t','nat','-C','PREROUTING','-s',ip,'-p','tcp','--dport','80','-j','ACCEPT','-m','comment','--comment','lab_captive_allow_nat']
        ins=['iptables','-t','nat','-I','PREROUTING','1','-s',ip,'-p','tcp','--dport','80','-j','ACCEPT','-m','comment','--comment','lab_captive_allow_nat']
        if LAN_IF:
            chk=['iptables','-t','nat','-C','PREROUTING','-s',ip,'-i',LAN_IF,'-p','tcp','--dport','80','-j','ACCEPT','-m','comment','--comment','lab_captive_allow_nat']
            ins=['iptables','-t','nat','-I','PREROUTING','1','-s',ip,'-i',LAN_IF,'-p','tcp','--dport','80','-j','ACCEPT','-m','comment','--comment','lab_captive_allow_nat']
        if not rule_exists(chk):
            subprocess.run(ins, check=False)
    except Exception as e:
        print("nat PREROUTING bypass error:", e, file=sys.stderr)
    # FORWARD ACCEPT
    try:
        if not rule_exists(['iptables','-C','FORWARD','-s',ip,'-j','ACCEPT','-m','comment','--comment','lab_captive_allow']):
            subprocess.run(['iptables','-I','FORWARD','2','-s',ip,'-j','ACCEPT','-m','comment','--comment','lab_captive_allow'], check=False)
    except Exception as e:
        print("FORWARD allow error:", e, file=sys.stderr)
    # Limpiar conntrack
    try: subprocess.run(['conntrack','-D','-s',ip], check=False)
    except Exception: pass
    try: subprocess.run(['conntrack','-D','-d',ip], check=False)
    except Exception: pass

def iptables_revoke(ip):
    # Quitar NAT PREROUTING bypass
    try:
        if LAN_IF:
            subprocess.run(['iptables','-t','nat','-D','PREROUTING','-s',ip,'-i',LAN_IF,'-p','tcp','--dport','80','-j','ACCEPT','-m','comment','--comment','lab_captive_allow_nat'], check=False)
        subprocess.run(['iptables','-t','nat','-D','PREROUTING','-s',ip,'-p','tcp','--dport','80','-j','ACCEPT','-m','comment','--comment','lab_captive_allow_nat'], check=False)
    except Exception: pass
    # Quitar NAT PORTAL RETURN
    try: subprocess.run(['iptables','-t','nat','-D','PORTAL','-s',ip,'-j','RETURN'], check=False)
    except Exception: pass
    # Quitar FORWARD ACCEPT
    try: subprocess.run(['iptables','-D','FORWARD','-s',ip,'-j','ACCEPT','-m','comment','--comment','lab_captive_allow'], check=False)
    except Exception: pass
    # Limpiar conntrack
    try: subprocess.run(['conntrack','-D','-s',ip], check=False)
    except Exception: pass
    try: subprocess.run(['conntrack','-D','-d',ip], check=False)
    except Exception: pass

def remove_dns_wildcard():
    try:
        if not os.path.exists(DNSMASQ_CONF): return
        with open(DNSMASQ_CONF,'r') as f:
            lines=f.readlines()
        new_lines=[L for L in lines if not L.strip().startswith('address=/#/')]
        if lines!=new_lines:
            with open(DNSMASQ_CONF,'w') as f:
                f.writelines(new_lines)
            subprocess.run(['systemctl','restart','dnsmasq'], check=False)
    except Exception as e:
        print("remove_dns_wildcard error:", e, file=sys.stderr)

def authorize_async(ip):
    try:
        mac = add_allowed(ip)
        iptables_allow(ip)
        remove_dns_wildcard()
    except Exception as e:
        print("authorize_async error:", e, file=sys.stderr)

def probe_response_for(host, path):
    h=(host or '').lower(); p=(path or '')
    hdr=dict(NO_CACHE)
    # Android/Chrome
    if ('clients3.google.com' in h) or ('connectivitycheck.gstatic.com' in h) or ('connectivitycheck.android.com' in h) or ('connectivity-check.ubuntu.com' in h) or ('/generate_204' in p):
        return ('', 204, hdr)
    # Apple
    if ('captive.apple.com' in h) or ('apple.com' in h and ('hotspot-detect' in p or 'library/test/success' in p)):
        body=APPLE_SUCCESS_HTML
        hdr.update({'Content-Type':'text/html; charset=utf-8','Connection':'close','Content-Length':str(len(body))})
        return (body, 200, hdr)
    # Windows msftconnecttest
    if ('msftconnecttest' in h):
        body=MSFT_CONNECT
        hdr.update({'Content-Type':'text/plain; charset=utf-8','Connection':'close','Content-Length':str(len(body))})
        return (body, 200, hdr)
    # Windows NCSI legacy
    if ('msftncsi' in h) or ('/ncsi' in p) or ('connecttest.txt' in p):
        body=MSFT_NCSI
        hdr.update({'Content-Type':'text/plain; charset=utf-8','Connection':'close','Content-Length':str(len(body))})
        return (body, 200, hdr)
    # Firefox
    if 'detectportal.firefox.com' in h or 'success.txt' in p:
        body=FIREFOX_SUCCESS
        hdr.update({'Content-Type':'text/plain; charset=utf-8','Connection':'close','Content-Length':str(len(body))})
        return (body, 200, hdr)
    return None

def still_connected(ip, mac):
    # Conectado si:
    # - existe lease de dnsmasq con esa IP y MAC
    # - y hay entrada ARP/neighbor no FAILED para esa IP
    mac_l = get_mac_from_leases(ip)
    if not mac_l or (mac and mac_l.lower()!=mac.lower()):
        return False
    try:
        cmd=['ip','neigh','show','to',ip]
        if LAN_IF: cmd+=['dev',LAN_IF]
        cp=subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1.5)
        out=cp.stdout.lower()
        if ' failed' in out:
            return False
        # si hay entrada, lo consideramos presente (reachable/stale/delay)
        return len(out.strip())>0
    except Exception:
        return True  # si no podemos verificar, no cortar
    return True

def watchdog_revoke_loop():
    # Revisa cada 20s; si IP permitida ya no está conectada (lease o ARP), revoca
    while True:
        try:
            d=read_allowed()
            changed=False
            for ip,meta in list(d.items()):
                mac=meta.get('mac','')
                if not still_connected(ip, mac):
                    iptables_revoke(ip)
                    del d[ip]; changed=True
            if changed: write_allowed(d)
        except Exception as e:
            print("watchdog error:", e, file=sys.stderr)
        time.sleep(20)

@app.route('/', defaults={'path': ''}, methods=['GET','HEAD'])
@app.route('/<path:path>', methods=['GET','HEAD'])
def catch_all(path):
    host = request.headers.get('Host','')
    client_ip = request.remote_addr
    ua = request.headers.get('User-Agent','')
    log_submission(client_ip, ua, path, host, request.args)

    allowed = read_allowed()
    if client_ip in allowed:
        # cliente autorizado: responde probes como esperan; si no es probe, 204
        pr = probe_response_for(host, path)
        if pr is not None:
            body, status, hdr = pr
            resp = make_response(body, status)
            for k,v in hdr.items(): resp.headers[k]=v
            return resp
        resp = make_response('', 204)
        for k,v in NO_CACHE.items(): resp.headers[k]=v
        resp.headers['Connection']='close'
        return resp

    # No autorizado: splash
    resp = make_response(render_template_string(SPLASH, client_ip=client_ip, host=host, path=path), 200)
    resp.headers['Content-Type']='text/html; charset=utf-8'
    for k,v in NO_CACHE.items(): resp.headers[k]=v
    resp.headers['Connection']='close'
    return resp

@app.route('/login', methods=['POST'])
def login():
    client_ip = request.remote_addr
    ua = (request.headers.get('User-Agent','') or '').lower()
    log_submission(client_ip, ua, request.path, request.headers.get('Host',''), request.form)

    # Autorizar en background inmediato (evita cuelgues/doble click)
    threading.Thread(target=authorize_async, args=(client_ip,), daemon=True).start()

    # Responder de forma determinística por plataforma
    if ('iphone' in ua) or ('ipad' in ua) or ('ipod' in ua) or ('mac os x' in ua) or ('captivenetworkassistant' in ua) or ('darwin' in ua) or ('safari' in ua):
        body = APPLE_SUCCESS_HTML
        resp = make_response(body, 200)
        resp.headers['Content-Type']='text/html; charset=utf-8'
        for k,v in NO_CACHE.items(): resp.headers[k]=v
        resp.headers['Content-Length']=str(len(body))
        resp.headers['Connection']='close'
        return resp

    if ('android' in ua) or ('chrome' in ua and 'edge' not in ua):
        resp = make_response('', 204)
        for k,v in NO_CACHE.items(): resp.headers[k]=v
        resp.headers['Connection']='close'
        return resp

    if ('windows' in ua) or ('trident' in ua) or ('edge' in ua) or ('msie' in ua):
        body = MSFT_CONNECT
        resp = make_response(body, 200)
        resp.headers['Content-Type']='text/plain; charset=utf-8'
        for k,v in NO_CACHE.items(): resp.headers[k]=v
        resp.headers['Content-Length']=str(len(body))
        resp.headers['Connection']='close'
        return resp

    resp = make_response('', 204)
    for k,v in NO_CACHE.items(): resp.headers[k]=v
    resp.headers['Connection']='close'
    return resp

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        'now': int(time.time()),
        'allowed': read_allowed(),
        'ttl': ALLOWED_TTL,
        'lan_if': LAN_IF,
        'lan_ip': LAN_IP
    })

if __name__ == '__main__':
    ensure_csv()
    # asegurar archivo allowed
    try:
        if not os.path.exists(ALLOWED_FILE): open(ALLOWED_FILE,'a').close()
    except Exception: pass
    # lanzar watchdog que revoca si el cliente se desconecta (lease/ARP)
    th = threading.Thread(target=watchdog_revoke_loop, daemon=True)
    th.start()
    app.run(host='0.0.0.0', port=APP_PORT)
PY

chmod 700 "$APP_PY"

# --- Hook de dnsmasq: sincroniza iptables/archivo en add/del/old de lease ---
cat > "$DHCP_HOOK" <<'HOOK'
#!/usr/bin/env bash
# dnsmasq dhcp-script hook
# Parámetros: $1=action(add|del|old) $2=mac $3=ip $4=hostname $5=clientid
set -eu

APP_DIR="/opt/captive"
ALLOWED_FILE="/tmp/allowed_ips.txt"
LAN_IF="${LAN_IF:-eth1}"

action="${1:-}"
mac="$(echo "${2:-}" | tr 'A-Z' 'a-z')"
ip="${3:-}"

rule_exists() {
  iptables "$@" >/dev/null 2>&1
}

iptables_allow() {
  # NAT PORTAL RETURN
  rule_exists -t nat -C PORTAL -s "$ip" -j RETURN || iptables -t nat -I PORTAL 1 -s "$ip" -j RETURN
  # PREROUTING BYPASS
  if [ -n "$LAN_IF" ]; then
    rule_exists -t nat -C PREROUTING -s "$ip" -i "$LAN_IF" -p tcp --dport 80 -j ACCEPT -m comment --comment lab_captive_allow_nat || \
      iptables -t nat -I PREROUTING 1 -s "$ip" -i "$LAN_IF" -p tcp --dport 80 -j ACCEPT -m comment --comment lab_captive_allow_nat
  fi
  rule_exists -t nat -C PREROUTING -s "$ip" -p tcp --dport 80 -j ACCEPT -m comment --comment lab_captive_allow_nat || \
    iptables -t nat -I PREROUTING 1 -s "$ip" -p tcp --dport 80 -j ACCEPT -m comment --comment lab_captive_allow_nat
  # FORWARD ACCEPT
  rule_exists -C FORWARD -s "$ip" -j ACCEPT -m comment --comment lab_captive_allow || \
    iptables -I FORWARD 2 -s "$ip" -j ACCEPT -m comment --comment lab_captive_allow
}

iptables_revoke() {
  # Quitar PREROUTING bypass
  if [ -n "$LAN_IF" ]; then
    iptables -t nat -D PREROUTING -s "$ip" -i "$LAN_IF" -p tcp --dport 80 -j ACCEPT -m comment --comment lab_captive_allow_nat 2>/dev/null || true
  fi
  iptables -t nat -D PREROUTING -s "$ip" -p tcp --dport 80 -j ACCEPT -m comment --comment lab_captive_allow_nat 2>/dev/null || true
  # Quitar NAT PORTAL RETURN
  iptables -t nat -D PORTAL -s "$ip" -j RETURN 2>/dev/null || true
  # Quitar FORWARD ACCEPT
  iptables -D FORWARD -s "$ip" -j ACCEPT -m comment --comment lab_captive_allow 2>/dev/null || true
  # conntrack
  conntrack -D -s "$ip" 2>/dev/null || true
  conntrack -D -d "$ip" 2>/dev/null || true
}

read_allowed() {
  [ -f "$ALLOWED_FILE" ] || return 0
  awk -F',' 'NF>=3{print $1","$2","$3}' "$ALLOWED_FILE"
}

write_allowed() {
  tmp="$(mktemp)"
  cat > "$tmp"
  mv "$tmp" "$ALLOWED_FILE"
}

# Lógica:
# - add/old: si IP está en allowed con MESMA MAC -> reasegurar reglas; si MAC distinta -> revocar y quitar del archivo.
# - del: revocar y quitar del archivo (al desconectar, debe reautenticarse).
case "$action" in
  add|old)
    current="$(read_allowed | grep -E "^${ip}," || true)"
    if [ -n "$current" ]; then
      allowed_mac="$(echo "$current" | awk -F',' '{print $2}')"
      if [ "$allowed_mac" = "$mac" ] && [ -n "$mac" ]; then
        iptables_allow
      else
        # MAC cambió -> revocar y quitar
        iptables_revoke
        read_allowed | awk -F',' -v IP="$ip" '$1!=IP{print $0}' | write_allowed
      fi
    fi
    ;;
  del)
    # Lease liberada: revocar y quitar del archivo (obliga a reautenticación)
    iptables_revoke
    read_allowed | awk -F',' -v IP="$ip" '$1!=IP{print $0}' | write_allowed
    ;;
esac

exit 0
HOOK
chmod 700 "$DHCP_HOOK"
# Exportar LAN_IF al entorno del hook (dnsmasq no propaga env; pero el hook manejará ausencia de -i)
sed -i '/^dhcp-script=/!b; s|$||' "$DNSMASQ_CONF" || true

# --- systemd unit ---
cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=Lab Captive Portal (session tied to connection with IP+MAC coherence)
After=network.target

[Service]
Type=simple
Environment=ALLOWED_TTL=${ALLOWED_TTL}
Environment=LAN_IF=${LAN_IF}
Environment=LAN_IP=${LAN_IP%/*}
ExecStart=/usr/bin/python3 $APP_PY
Restart=on-failure
RestartSec=1
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now captive-portal.service

# --- clear_captive.sh en el MISMO directorio que este script ---
cat > "${SCRIPT_DIR}/clear_captive.sh" <<'CLR'
#!/usr/bin/env bash
set -euo pipefail
LAN_IF="${LAN_IF:-eth1}"

systemctl stop captive-portal.service 2>/dev/null || true
pkill -f /opt/captive/portal_allow.py 2>/dev/null || true

iptables -P FORWARD ACCEPT

# Quitar reglas de la cadena PORTAL
iptables -t nat -F PORTAL 2>/dev/null || true
iptables -t nat -D PREROUTING -i "$LAN_IF" -p tcp --dport 80 -j PORTAL 2>/dev/null || true
iptables -t nat -X PORTAL 2>/dev/null || true

# Quitar PREROUTING bypass por comentario
iptables -t nat -S PREROUTING | grep -- '--comment lab_captive_allow_nat' | while read -r line; do
  del=$(echo "$line" | sed 's/^-A /-D /')
  iptables -t nat $del 2>/dev/null || true
done || true

# Quitar FORWARD allow por comentario
while iptables -S FORWARD | grep -q "lab_captive_allow"; do
  RULE=$(iptables -S FORWARD | grep lab_captive_allow | head -n1 || true)
  IP=$(echo "$RULE" | awk '{for(i=1;i<=NF;i++) if($i=="-s") print $(i+1)}' || true)
  if [ -n "${IP:-}" ]; then
    iptables -D FORWARD -s "$IP" -j ACCEPT -m comment --comment lab_captive_allow 2>/dev/null || true
  else
    iptables -S FORWARD | nl -ba | grep lab_captive_allow | awk '{print $1}' | while read -r n; do iptables -D FORWARD "$n" 2>/dev/null || true; done || true
  fi
done

# Reiniciar dnsmasq (restaura si había wildcard)
systemctl restart dnsmasq 2>/dev/null || true
rm -f /tmp/allowed_ips.txt 2>/dev/null || true

echo "Cleanup done"
CLR
chmod 700 "${SCRIPT_DIR}/clear_captive.sh"

echo "Deploy complete. Service: systemctl status captive-portal.service"
echo "Archivo de autorizaciones (IP,MAC,TS): $ALLOWED_FILE"
echo "Hook DHCP: $DHCP_HOOK (dnsmasq llamará a este script en add/old/del de leases)"
echo "clear_captive.sh creado en: ${SCRIPT_DIR}/clear_captive.sh"
