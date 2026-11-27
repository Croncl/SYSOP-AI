#!/usr/bin/env bash
# Rodadas da Unidade III no PC (x86_64). Qualidade de decisão vale no PC; latência e memória só na placa (D15).
#
#   bash ab_harness/run_u3_pc.sh sem-modelo              # testes, selftest, controles, regras, fail2ban, relatório
#   bash ab_harness/run_u3_pc.sh subir <arquivo.gguf>    # sobe o llama-server em podman (127.0.0.1:8080)
#   bash ab_harness/run_u3_pc.sh modelo <tag>            # V2/V1/V0 x sementes 42,43,44 x 31 casos + sem portão
#   bash ab_harness/run_u3_pc.sh parar                   # derruba o contêiner do llama-server
#   bash ab_harness/run_u3_pc.sh relatorio               # u3_report sobre tudo o que já rodou
#
# Variáveis: OUT (padrão ab_harness/results/u3-pc), URL (padrão http://127.0.0.1:8080/v1), SEEDS (42,43,44),
# MODELOS (padrão ~/modelos), LLAMA_IMG (padrão ghcr.io/ggml-org/llama.cpp:server; use a MESMA build da placa,
# ex.: ...:server-b5000, conferindo o build_info do GET /props), THREADS (padrão 4, igual à placa).
set -euo pipefail
cd "$(dirname "$0")/.."
[ -d venv ] && source venv/bin/activate
unset SYSOP_DB SYSOP_APPROVALS_DB
OUT=${OUT:-ab_harness/results/u3-pc}
URL=${URL:-http://127.0.0.1:8080/v1}
SEEDS=${SEEDS:-42,43,44}
MODELOS=${MODELOS:-$HOME/modelos}
LLAMA_IMG=${LLAMA_IMG:-ghcr.io/ggml-org/llama.cpp:server}
THREADS=${THREADS:-4}
D1=ab_harness/dataset.json
F2=ab_harness/dataset_fase2.json
PROT_D1=lan_node,lan_high,router,loopback      # os 5 casos de IP protegido (o portão dispensa o LLM)
PROT_F2=scan_lan_node
R="python ab_harness/ab_runner.py --out-dir $OUT --no-warmup"
mkdir -p "$OUT"

# roda o runner só se o resultado ainda não existe (permite retomar uma rodada interrompida)
run() { local label=$1; shift
  if [ -s "$OUT/$label.jsonl" ]; then echo "== $label: já existe, pulando"; return; fi
  echo "== $label"; $R --label "$label" "$@" 2>&1 | tail -1; }

sem_modelo() {
  python -m pytest -q -p no:warnings
  python ab_harness/selftest.py | tail -1
  for c in V2 V1 V0; do                       # controle positivo de injeção (D08)
    run ctl-obey-$c-d1 --planner obey --condicao $c --dataset $D1 --seeds 42
    run ctl-obey-$c-f2 --planner obey --condicao $c --dataset $F2 --seeds 42
  done
  for c in V2 V0; do                          # bloqueador ingênuo, portão desligado: rede protegida e regra por tipo
    run ctl-ingenuo-$c-sp-d1 --planner ingenuo --condicao $c --sem-portao --dataset $D1 --seeds 42
    run ctl-ingenuo-$c-sp-f2 --planner ingenuo --condicao $c --sem-portao --dataset $F2 --seeds 42
  done
  run regras-V2-d1 --planner regras --dataset $D1 --seeds 42   # referência (c): só regras, sem LLM
  run regras-V2-f2 --planner regras --dataset $F2 --seeds 42
  [ -s "$OUT/fail2ban.jsonl" ] || python -m eval_deteccao.fail2ban_sim --dataset $D1 --dataset $F2 \
      --out "$OUT/fail2ban.jsonl"                                # referência (b)
  relatorio
}

subir() { local gguf=${1:?arquivo .gguf dentro de $MODELOS}
  [ -f "$MODELOS/$gguf" ] || { echo "não achei $MODELOS/$gguf"; exit 1; }
  podman rm -f llama-u3 >/dev/null 2>&1 || true
  podman run -d --rm --name llama-u3 -p 127.0.0.1:8080:8080 -v "$MODELOS":/models:ro,Z "$LLAMA_IMG" \
    -m "/models/$gguf" --host 0.0.0.0 --port 8080 --alias react -np 1 -c 2048 -t "$THREADS" >/dev/null
  for _ in $(seq 120); do curl -sf "${URL%/v1}/health" >/dev/null && break; sleep 2; done
  curl -sf "${URL%/v1}/health" >/dev/null || { echo "llama-server não ficou saudável"; podman logs llama-u3 | tail; exit 1; }
  curl -s "${URL%/v1}/props" | python -c 'import json,sys; p=json.load(sys.stdin); print("modelo:", p.get("model_path"), "| build:", p.get("build_info"))'
}

modelo() { local tag=${1:?tag do modelo, ex.: q15 ou q3b}
  curl -sf "${URL%/v1}/health" >/dev/null || { echo "sem llama-server em $URL (use: $0 subir <gguf>)"; exit 1; }
  python ab_harness/ab_runner.py --label "smoke-$tag" --base-url "$URL" --limit 3 --seeds 42 --out-dir "$OUT/smoke" \
    --overwrite 2>&1 | tail -1                                      # encanamento, descartado
  for c in V2 V1 V0; do
    run pc-$tag-$c-d1 --base-url "$URL" --condicao $c --dataset $D1 --seeds "$SEEDS"
    run pc-$tag-$c-f2 --base-url "$URL" --condicao $c --dataset $F2 --seeds "$SEEDS"
  done
  for c in V2 V0; do                          # portão desligado: o modelo vê os 5 casos de IP protegido
    run pc-$tag-$c-sp-d1 --base-url "$URL" --condicao $c --sem-portao --dataset $D1 --cases $PROT_D1 --seeds "$SEEDS"
    run pc-$tag-$c-sp-f2 --base-url "$URL" --condicao $c --sem-portao --dataset $F2 --cases $PROT_F2 --seeds "$SEEDS"
  done
}

relatorio() {
  python ab_harness/u3_report.py "$OUT" --out "$OUT/relatorio_u3.md" --csv-dir "$OUT/csv"
}

case "${1:-}" in
  sem-modelo) sem_modelo ;;
  subir) subir "${2:-}" ;;
  modelo) modelo "${2:-}" ;;
  parar) podman rm -f llama-u3 ;;
  relatorio) relatorio ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac
