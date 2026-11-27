#!/usr/bin/env bash
# Rodadas da Unidade III NA PLACA (Orange Pi 4 Pro): latência e memória (O2) com os dois modelos, condição V2,
# sementes 42,43,44, nos 31 casos; mais o planejador só com regras (custo do agente sem LLM). Roteiro completo em
# lab/RUNBOOK_PLACA.md. Rodar como o administrador (opad), na pasta do repositório, com o venv criado.
#
#   bash ab_harness/run_u3_placa.sh            # tudo (≈ 4 h); retoma de onde parou se interrompido
#   nohup bash ab_harness/run_u3_placa.sh > ab_harness/u3_placa.log 2>&1 &
#
# O que o script mexe e DESFAZ ao sair (trap): para o timer do agente (sysopai-agent.timer), troca o contêiner
# de produção (1,5B) pelo de 3B na porta 8080 só durante a rodada do 3B e religa a produção no fim.
# Variáveis: C15 (contêiner 1,5B, padrão llama-plan-15b), SVC15 (serviço systemd --user dele, padrão
# container-llama-plan-15b.service), C3 (contêiner 3B, padrão llama-plan), SEEDS, OUT.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -d venv ] && source venv/bin/activate
unset SYSOP_DB SYSOP_APPROVALS_DB
OUT=${OUT:-ab_harness/results/u3-placa}
SEEDS=${SEEDS:-42,43,44}
C15=${C15:-llama-plan-15b}
SVC15=${SVC15:-container-llama-plan-15b.service}
C3=${C3:-llama-plan}
URL=http://127.0.0.1:8080/v1
D1=ab_harness/dataset.json
F2=ab_harness/dataset_fase2.json
mkdir -p "$OUT"
log() { echo "[$(date '+%F %T')] $*"; }

# ------------------------------------------------------------------ restauração
TIMER_WAS_ACTIVE=0
SAMPLER=""
restore() {
  [ -n "$SAMPLER" ] && kill "$SAMPLER" 2>/dev/null || true
  if podman ps --format '{{.Names}}' | grep -qx "$C3"; then log "parando $C3 (3B)"; podman stop "$C3" >/dev/null || true; fi
  if ! curl -sf http://127.0.0.1:8080/health >/dev/null; then
    log "religando a produção ($SVC15)"; systemctl --user start "$SVC15" || podman start "$C15" || true
  fi
  if [ "$TIMER_WAS_ACTIVE" = 1 ]; then log "religando sysopai-agent.timer"; sudo systemctl start sysopai-agent.timer || true; fi
}
trap restore EXIT

wait_health() { for _ in $(seq 180); do curl -sf http://127.0.0.1:8080/health >/dev/null && return 0; sleep 2; done
  log "llama-server não ficou saudável"; return 1; }

run() { local label=$1; shift
  if [ -s "$OUT/$label.jsonl" ]; then log "$label: já existe, pulando"; return; fi
  log "$label"; python ab_harness/ab_runner.py --out-dir "$OUT" --label "$label" "$@" 2>&1 | tail -1; }

rodada_modelo() { local tag=$1
  curl -s http://127.0.0.1:8080/props > "$OUT/props-$tag.json" || true
  python scripts/mem_sampler.py --match llama-server --match ab_runner --out "$OUT/mem-$tag.csv" &
  SAMPLER=$!
  run placa-$tag-V2-d1 --base-url $URL --dataset $D1 --seeds "$SEEDS"      # com aquecimento (1ª chamada descartada)
  run placa-$tag-V2-f2 --base-url $URL --dataset $F2 --seeds "$SEEDS"
  kill "$SAMPLER"; SAMPLER=""
  python scripts/mem_sampler.py --summary "$OUT/mem-$tag.csv" | tee "$OUT/mem-$tag.resumo.txt"
}

# ------------------------------------------------------------------ 0) conferências
log "commit $(git rev-parse --short HEAD) $(git describe --tags --always 2>/dev/null)"
python -m pytest -q -p no:warnings | tail -1
python ab_harness/selftest.py | tail -1
if systemctl is-active --quiet sysopai-agent.timer 2>/dev/null; then
  TIMER_WAS_ACTIVE=1; log "parando sysopai-agent.timer durante as rodadas"; sudo systemctl stop sysopai-agent.timer
fi
{ uname -a; echo; lscpu; echo; free -m; echo; pip freeze; echo; sha256sum /srv/models/*.gguf 2>/dev/null;
  echo; podman ps -a --format '{{.Names}} {{.Image}} {{.Status}}'; podman image inspect --format '{{.Id}} {{.RepoDigests}}' \
  ghcr.io/ggml-org/llama.cpp:server 2>/dev/null; } > "$OUT/ambiente.txt" 2>&1 || true

# ------------------------------------------------------------------ 1) linha de base de memória (sem carga)
wait_health
[ -s "$OUT/mem-ocioso.csv" ] || { log "memória ociosa (60 s)"; python scripts/mem_sampler.py --match llama-server \
  --match sysopai --duration 60 --out "$OUT/mem-ocioso.csv"; python scripts/mem_sampler.py --summary "$OUT/mem-ocioso.csv" \
  | tee "$OUT/mem-ocioso.resumo.txt"; }

# ------------------------------------------------------------------ 2) agente sem LLM (referência c): custo
run placa-regras-V2-d1 --planner regras --dataset $D1 --seeds 42 --no-warmup
run placa-regras-V2-f2 --planner regras --dataset $F2 --seeds 42 --no-warmup

# ------------------------------------------------------------------ 3) Qwen2.5-1,5B (produção)
rodada_modelo q15

# ------------------------------------------------------------------ 4) Qwen2.5-3B
if [ ! -s "$OUT/placa-q3b-V2-f2.jsonl" ]; then
  log "trocando a produção pelo 3B ($C3)"
  systemctl --user stop "$SVC15" 2>/dev/null || podman stop "$C15" >/dev/null || true
  podman start "$C3" >/dev/null
  wait_health
  rodada_modelo q3b
  podman stop "$C3" >/dev/null
fi

# ------------------------------------------------------------------ 5) relatório e pacote
python ab_harness/u3_report.py "$OUT" --out "$OUT/relatorio_u3_placa.md" --csv-dir "$OUT/csv"
PKG=u3-placa-$(date +%Y%m%d-%H%M).tar.gz
tar -czf "$PKG" -C "$(dirname "$OUT")" "$(basename "$OUT")"
sha256sum "$PKG" | tee "$PKG.sha256"
log "pronto: envie $PKG e $PKG.sha256 para o grupo"
