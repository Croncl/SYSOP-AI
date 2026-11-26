#!/usr/bin/env bash
# Laboratório de ataques contra a placa (O3). Roda na MÁQUINA ATACANTE, na mesma LAN da placa. Roteiro completo,
# preparação da placa e restauração em lab/RUNBOOK_LAB.md.
#
#   ALVO=192.168.0.4 IFACE=wlp2s0 IPS="192.168.0.201 192.168.0.202 192.168.0.203" bash lab/ataque.sh
#
# Precisa de: ssh, nmap, sudo (IPs extras na interface e nmap -sS) e, se a placa aceitar senha, sshpass.
# IPS: três endereços LIVRES da LAN, fora das redes protegidas (nunca 192.168.0.1, nunca 10.10.0.x) e diferentes do
# IP por onde o administrador acessa a placa (um deles será banido de verdade na etapa ponta a ponta).
# Grava em $OUT: gabarito.csv (início e fim de cada episódio, em epoch), relogio.txt, saídas do nmap e um log.
# Episódios: L1 SSH rápido, L2 SSH no limiar, L3 SSH abaixo do limiar, L4 benigno, L5/L6 varredura 100 e 1000
# portas, L7 varredura de 9 portas, L8 SSH lento (90 s), L9 senha errada (só com SENHA_SSH=1). ≈ 45 min.
set -euo pipefail
: "${ALVO:?defina ALVO (IP da placa)}" "${IFACE:?defina IFACE (interface desta máquina na LAN)}" "${IPS:?defina IPS}"
read -r A B C <<<"$IPS"
[ -n "${C:-}" ] || { echo "IPS precisa de três endereços"; exit 1; }
SENHA_SSH=${SENHA_SSH:-0}           # 1 se a placa aceita senha (sshd -T | grep passwordauthentication => yes)
ADMIN=${ADMIN:-opad}                # usuário real da placa (episódio benigno: login por chave)
JANELA=${JANELA:-660}               # espera mínima entre episódios do mesmo IP (janela de 10 min + folga)
SO_EPISODIOS=${SO_EPISODIOS:-}      # ex.: "L1 L5" para repetir só alguns
OUT=${OUT:-lab-$(date +%Y%m%d-%H%M)}
mkdir -p "$OUT"
GAB=$OUT/gabarito.csv
LOG=$OUT/ataque.log
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR)
declare -A LAST=()
log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
now() { date +%s.%N | cut -c1-14; }

if [ "${DRY:-0}" = 1 ]; then   # ensaio: nada sai da máquina; só confere o fluxo e o gabarito
  sudo() { :; }; ssh() { :; }; nmap() { :; }; sshpass() { :; }; sleep() { :; }; JANELA=0
  ip() { [ "${1:-}" = -o ] && echo "$A $B $C" || :; }
  log "DRY=1: ensaio sem tráfego"
fi
for t in ssh nmap; do type $t >/dev/null 2>&1 || { echo "falta $t"; exit 1; }; done
if [ "$SENHA_SSH" = 1 ]; then type sshpass >/dev/null 2>&1 || { echo "SENHA_SSH=1 pede sshpass"; exit 1; }; fi

# ------------------------------------------------------------------ IPs extras (removidos ao sair)
ADDED=()
cleanup() { for ip in "${ADDED[@]}"; do sudo ip addr del "$ip/24" dev "$IFACE" 2>/dev/null || true; done; }
trap cleanup EXIT
for ip in $A $B $C; do
  if ! ip -o addr show dev "$IFACE" | grep -qw "$ip"; then
    sudo ip addr add "$ip/24" dev "$IFACE" && ADDED+=("$ip")
  fi
done
log "origens: A=$A B=$B C=$C (interface $IFACE), alvo $ALVO"

# ------------------------------------------------------------------ relógios (para --skew nas métricas)
{ echo "atacante_antes $(now)"; ssh "${SSH_OPTS[@]}" "$ADMIN@$ALVO" 'date +%s.%N' 2>/dev/null | sed 's/^/placa /' \
  || echo "placa ? (sem login por chave do $ADMIN; confira o NTP nas duas máquinas)"; echo "atacante_depois $(now)"; } \
  > "$OUT/relogio.txt"
[ -s "$GAB" ] || echo "episodio,tipo,ip,inicio,fim,esperado,ferramenta,notas" > "$GAB"

# ------------------------------------------------------------------ primitivas
quer() { [ -z "$SO_EPISODIOS" ] || [[ " $SO_EPISODIOS " == *" $1 "* ]]; }
espera() { local ip=$1 falta
  if [ -n "${LAST[$ip]:-}" ]; then
    falta=$(( ${LAST[$ip]%.*} + JANELA - $(date +%s) ))
    [ "$falta" -gt 0 ] && { log "aguardando ${falta}s para reusar $ip (janela de 10 min)"; sleep "$falta"; }
  fi; return 0; }
registra() { local id=$1 tipo=$2 ip=$3 ini=$4 fim=$5 esp=$6 ferr=$7 notas=$8
  echo "$id,$tipo,$ip,$ini,$fim,$esp,$ferr,\"$notas\"" >> "$GAB"; LAST[$ip]=$fim
  log "$id $tipo $ip $(awk -v a="$ini" -v b="$fim" 'BEGIN{printf "%.0f", b-a}') s ($esp)"; }
ssh_inv() { local ip=$1 n=$2 dt=$3 user=${4:-labinv}   # conexões com usuário inexistente => "Invalid user"
  for i in $(seq "$n"); do ssh -b "$ip" "${SSH_OPTS[@]}" "${user}$i@$ALVO" true >/dev/null 2>&1 || true; sleep "$dt"; done; }
ssh_senha() { local ip=$1 n=$2 dt=$3                    # senha errada => "Failed password"
  for i in $(seq "$n"); do sshpass -p "errada$i" ssh -b "$ip" -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PubkeyAuthentication=no -o PreferredAuthentications=password \
    -o NumberOfPasswordPrompts=1 "labsenha@$ALVO" true >/dev/null 2>&1 || true; sleep "$dt"; done; }
scan() { local ip=$1 id=$2; shift 2
  sudo nmap -sS -Pn -n -e "$IFACE" -S "$ip" --max-retries 0 "$@" "$ALVO" -oN "$OUT/nmap-$id.txt" >/dev/null; }

ep() { local id=$1 tipo=$2 ip=$3 esp=$4 ferr=$5 notas=$6; shift 6
  quer "$id" || return 0
  espera "$ip"; local ini; ini=$(now); "$@"; registra "$id" "$tipo" "$ip" "$ini" "$(now)" "$esp" "$ferr" "$notas"; }

# ------------------------------------------------------------------ episódios
ep L1 ssh_bruteforce "$A" detectar "ssh BatchMode" "30 usuários inexistentes, 1 a cada 2 s" ssh_inv "$A" 30 2
ep L2 ssh_bruteforce "$B" detectar "ssh BatchMode" "exatamente 10 em ~30 s" ssh_inv "$B" 10 3
ep L3 ssh_bruteforce "$C" nao_detectar "ssh BatchMode" "8 em ~24 s: abaixo do limiar do SYSOP-AI (10), acima do fail2ban (5)" \
   ssh_inv "$C" 8 3
ep L5 port_scan "$A" detectar "nmap -sS" "portas 1-100" scan "$A" L5 -p 1-100
ep L6 port_scan "$B" detectar "nmap -sS -T4" "portas 1-1000" scan "$B" L6 -p 1-1000 -T4
benigno() { ssh_inv "$C" 1 4 opda; ssh_inv "$C" 1 4 opadd
  ssh -b "$C" "${SSH_OPTS[@]}" "$ADMIN@$ALVO" true >/dev/null 2>&1 || log "L4: login por chave falhou (sem chave?); segue benigno"; }
ep L4 benigno "$C" nao_detectar "ssh" "admin erra o usuário 2 vezes e entra com chave" benigno
ep L7 port_scan "$C" nao_detectar "nmap -sS" "9 portas (2000-2008): abaixo do limiar" scan "$C" L7 -p 2000-2008
ep L8 ssh_bruteforce "$A" nao_detectar "ssh BatchMode" "lenta: 12 tentativas, 1 a cada 90 s (~17 min)" ssh_inv "$A" 12 90
if [ "$SENHA_SSH" = 1 ]; then
  ep L9 ssh_bruteforce "$B" detectar "sshpass" "20 senhas erradas, 1 a cada 2 s" ssh_senha "$B" 20 2
fi
log "fim. Copie $GAB para a placa (lab/coleta.sh) ou para quem vai analisar. Etapa ponta a ponta: RUNBOOK_LAB.md, passo 6."
