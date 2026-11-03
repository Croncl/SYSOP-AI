#!/usr/bin/env bash
# Roda TODOS os testes depois de aplicar a regra por tipo de incidente.
#   bash ab_harness/run_all.sh quick   # pytest + selftest + 1.5B e 3B nos 2 conjuntos      (~1h30)
#   bash ab_harness/run_all.sh full    # quick + casos hostis x3 repetições nos 2 modelos   (+~1h20)
# Rode em segundo plano:  nohup bash ab_harness/run_all.sh quick > ab_harness/run_all.log 2>&1 &
# Para no 1º erro de pytest/selftest (rodar o A/B com código quebrado não diz nada).
# Ao final deixa o container do 3B (llama-plan) ligado, como estava. Não sobrescreve resultados.
set -uo pipefail
cd "$(dirname "$0")/.."
MODE="${1:-quick}"
[ "$MODE" = quick ] || [ "$MODE" = full ] || { echo "uso: $0 quick|full"; exit 2; }
# shellcheck disable=SC1091
source venv/bin/activate
export PYTHONPATH=sysopai
HEALTH=http://127.0.0.1:8080/health
URL=http://127.0.0.1:8080/v1
D1=ab_harness/dataset.json
D2=ab_harness/dataset_fase2.json
R=ab_harness/results
HOST1="inj_user_ban_lan,inj_raw_system,inj_third_party,inj_close_tag,inj_force_none,inj_admin_ip,inj_run_aide,inj_ansi"
HOST2="scan_inj,post_inj_sudo_cmd,post_admin_trap"
OUTMD=ab_harness/relatorio_guard.md

say() { printf '\n=== %s  [%s]\n' "$*" "$(date +%H:%M:%S)"; }

use_model() {   # $1 = nome do container
  podman stop llama-plan llama-ab-15b >/dev/null 2>&1 || true
  podman start "$1" >/dev/null || { echo "ERRO: não consegui iniciar $1"; exit 1; }
  for _ in $(seq 1 120); do curl -sf "$HEALTH" >/dev/null && return 0; sleep 3; done
  echo "ERRO: $1 não ficou saudável em 6 min (podman logs $1 | tail)"; exit 1
}

run() {         # $1 = label, $2 = dataset, resto = args extras do runner
  local label="$1" ds="$2"; shift 2
  if [ -e "$R/$label.jsonl" ]; then echo "pulando $label (já existe em $R)"; return 0; fi
  say "rodando $label"
  python ab_harness/ab_runner.py --label "$label" --hint --dataset "$ds" --base-url "$URL" "$@" \
    > "ab_harness/$label.log" 2>&1 || echo "AVISO: $label terminou com erro (ver ab_harness/$label.log)"
  tail -1 "ab_harness/$label.log"
}

say "1/ pytest (todos os testes do projeto)"
python -m pytest -q || { echo "PYTEST FALHOU: corrija antes do A/B (cole a saída ao Claude)"; exit 1; }
say "2/ selftest do harness (servidor falso)"
python ab_harness/selftest.py 2>&1 | tail -3 | tee /dev/stderr | grep -q "SELFTEST OK" || { echo "SELFTEST FALHOU"; exit 1; }

say "3/ modelo 1.5B"
use_model llama-ab-15b
run qwen25-1.5b-guard        "$D1" --reps 1
run qwen25-1.5b-fase2-guard  "$D2" --reps 1
if [ "$MODE" = full ]; then
  run qwen25-1.5b-hostis1-guard "$D1" --reps 3 --cases "$HOST1"
  run qwen25-1.5b-hostis2-guard "$D2" --reps 3 --cases "$HOST2"
fi

say "4/ modelo 3B"
use_model llama-plan
run qwen25-3b-guard          "$D1" --reps 1
run qwen25-3b-fase2-guard    "$D2" --reps 1
if [ "$MODE" = full ]; then
  run qwen25-3b-hostis1-guard "$D1" --reps 3 --cases "$HOST1"
  run qwen25-3b-hostis2-guard "$D2" --reps 3 --cases "$HOST2"
fi

say "5/ relatórios"
{
  echo "# Conjunto 1 (22 casos)";        python ab_harness/ab_report.py qwen25-3b-guard qwen25-1.5b-guard --baseline qwen25-3b-guard
  echo; echo "# Conjunto 2 / fase 2 (9 casos)"; python ab_harness/ab_report.py qwen25-3b-fase2-guard qwen25-1.5b-fase2-guard --baseline qwen25-3b-fase2-guard
  if [ "$MODE" = full ]; then
    echo; echo "# Hostis conjunto 1 (x3)"; python ab_harness/ab_report.py qwen25-3b-hostis1-guard qwen25-1.5b-hostis1-guard --baseline qwen25-3b-hostis1-guard
    echo; echo "# Hostis fase 2 (x3)";     python ab_harness/ab_report.py qwen25-3b-hostis2-guard qwen25-1.5b-hostis2-guard --baseline qwen25-3b-hostis2-guard
  fi
} > "$OUTMD" 2>&1
echo "relatório completo em $OUTMD"
say "FIM (llama-plan, o 3B, ficou ligado)"
