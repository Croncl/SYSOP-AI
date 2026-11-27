#!/usr/bin/env bash
# Coleta da placa depois do laboratório (O3). Roda NA PLACA como o administrador (opad), na pasta do repositório.
# Junta num pacote tudo o que a análise no PC precisa e NADA altera na placa (bancos copiados em modo leitura).
#
#   bash lab/coleta.sh /caminho/gabarito.csv            # o gabarito vem da máquina atacante (lab/ataque.sh)
#
# Variáveis: PY (python do venv), SYSOP_DB (/var/lib/sysopai/sysop.db), APPROVALS_DB, F2B_JAIL (sshd-sombra),
# ANTES (s antes do 1º episódio, padrão 600) e DEPOIS (s depois do último, padrão 3600: cobre a etapa ponta a ponta).
set -euo pipefail
GAB=${1:?uso: bash lab/coleta.sh gabarito.csv}
cd "$(dirname "$0")/.."
PY=${PY:-/home/projetos/SYSOP-AI/venv/bin/python}
SYSOP_DB=${SYSOP_DB:-/var/lib/sysopai/sysop.db}
APPROVALS_DB=${APPROVALS_DB:-/var/lib/sysopai-approvals/approvals.db}
F2B_JAIL=${F2B_JAIL:-sshd-sombra}
ANTES=${ANTES:-600}
DEPOIS=${DEPOIS:-3600}
read -r INI FIM < <(python3 - "$GAB" "$ANTES" "$DEPOIS" <<'PY'
import csv, sys
r = list(csv.DictReader(open(sys.argv[1])))
print(int(min(float(x["inicio"]) for x in r)) - int(sys.argv[2]), int(max(float(x["fim"]) for x in r)) + int(sys.argv[3]))
PY
)
OUT=lab-coleta-$(date +%Y%m%d-%H%M)
mkdir -p "$OUT"
cp "$GAB" "$OUT/gabarito.csv"
[ -f "$(dirname "$GAB")/relogio.txt" ] && cp "$(dirname "$GAB")/relogio.txt" "$OUT/" || true
[ -f "$(dirname "$GAB")/ataque.log" ] && cp "$(dirname "$GAB")/ataque.log" "$OUT/" || true
echo "janela: $(date -d @"$INI") até $(date -d @"$FIM")"

# 1) journal da janela, só as fontes que o SYSOP-AI e o fail2ban leem
sudo journalctl -o json --since "@$INI" --until "@$FIM" -t sshd -t sshd-session -t kernel -t fail2ban-server \
  -t sudo -t sysop-audit > "$OUT/journal.json"
echo "journal: $(wc -l < "$OUT/journal.json") linhas"

# 2) bancos: cópia consistente (API de backup do SQLite) feita por quem pode ler; os originais não mudam
copia_db() { local quem=$1 origem=$2 destino=$3
  sudo -u "$quem" "$PY" - "$origem" "/tmp/coleta-$$.db" <<'PY'
import sqlite3, sys
src = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
dst = sqlite3.connect(sys.argv[2])
src.backup(dst)
dst.close(); src.close()
PY
  sudo cp "/tmp/coleta-$$.db" "$destino"; sudo rm -f "/tmp/coleta-$$.db"; sudo chown "$(id -u):$(id -g)" "$destino"; }
copia_db sysop "$SYSOP_DB" "$OUT/sysop.db"
[ -f "$APPROVALS_DB" ] && copia_db "$(stat -c %U "$APPROVALS_DB")" "$APPROVALS_DB" "$OUT/approvals.db" || true

# 3) fail2ban
for f in /var/log/fail2ban.log /var/log/fail2ban.log.1; do
  [ -f "$f" ] && sudo cp "$f" "$OUT/" && sudo chown "$(id -u):$(id -g)" "$OUT/$(basename "$f")"
done
{ for j in sshd "$F2B_JAIL"; do echo "== $j"; sudo fail2ban-client status "$j" 2>&1
    for k in maxretry findtime bantime ignoreip; do echo "$k: $(sudo fail2ban-client get "$j" "$k" 2>&1 | tr '\n' ' ')"; done
  done; } > "$OUT/fail2ban-estado.txt"

# 4) ambiente e custo de memória do coletor e do agente
{ echo "== data e relógio"; date; date +%s.%N; timedatectl 2>/dev/null | grep -Ei 'synchron|NTP|zone'
  echo "== sistema"; uname -a; free -m
  echo "== código"; git rev-parse HEAD; git describe --tags --always 2>/dev/null; git status --porcelain | head
  echo "== sshd"; sudo sshd -T 2>/dev/null | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|maxauthtries|maxstartups|usedns|loglevel) '
  echo "== ufw"; sudo ufw status verbose 2>&1 | head -20; sudo iptables -S 2>/dev/null | grep -i -- '--limit' | head
  echo "== redes protegidas (banco do agente)"
  sudo -u sysop "$PY" -c "import sqlite3; c=sqlite3.connect('file:$SYSOP_DB?mode=ro', uri=True); print([r[0] for r in c.execute('select cidr from protected_networks')])"
  echo "== llama-server"; curl -s --max-time 5 http://127.0.0.1:8080/props | head -c 2000; echo
  echo "== processos do sysop (RSS em KiB)"; ps -o pid,rss,etime,cmd -u sysop 2>/dev/null || true
  echo "== unidades"; for u in sysopai-collector.service sysopai-agent.service sysopai-agent.timer; do
    systemctl show "$u" -p ActiveState -p MemoryCurrent -p MemoryPeak 2>/dev/null | tr '\n' ' '; echo " $u"; done
} > "$OUT/ambiente.txt" 2>&1

# 5) pacote
(cd "$OUT" && sha256sum * > SHA256SUMS)
tar -czf "$OUT.tar.gz" "$OUT"
sha256sum "$OUT.tar.gz" | tee "$OUT.tar.gz.sha256"
echo "pronto: envie $OUT.tar.gz (e o .sha256) para quem vai analisar no PC"
