#!/usr/bin/env bash
# Fase 1: candidato Qwen3-1.7B (Q4_K_M, :8081) nos 2 conjuntos; baseline q15-* e spark-* já medidos hoje.
#   export BODY_EXTRA='{"chat_template_kwargs":{"enable_thinking":false}}'
#   nohup bash ab_harness/run_qwen3.sh > ab_harness/run_qwen3.log 2>&1 &
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source venv/bin/activate
export PYTHONPATH=sysopai
unset SYSOP_DB SYSOP_APPROVALS_DB
D1=ab_harness/dataset.json
D2=ab_harness/dataset_fase2.json
R=ab_harness/results
EXTRA=()
[ -n "${BODY_EXTRA:-}" ] && EXTRA=(--body-extra "$BODY_EXTRA")
say() { printf '\n=== %s  [%s]\n' "$*" "$(date +%H:%M:%S)"; }

curl -sf "http://127.0.0.1:8081/health" >/dev/null || { echo "ERRO: sem servidor saudável na porta 8081"; exit 1; }
for l in q15-d1 q15-f2 spark-d1 spark-f2; do
  [ -e "$R/$l.jsonl" ] || { echo "ERRO: falta $R/$l.jsonl (baseline/Spark de referência)"; exit 1; }
done

run() {  # $1=label $2=dataset ; resto = extras do runner
  local label="$1" ds="$2"; shift 2
  if [ -e "$R/$label.jsonl" ]; then echo "pulando $label (já existe em $R)"; return 0; fi
  say "rodando $label"
  python ab_harness/ab_runner.py --label "$label" --hint --dataset "$ds" \
    --base-url "http://127.0.0.1:8081/v1" --reps 1 "$@" > "ab_harness/$label.log" 2>&1 \
    || echo "AVISO: $label terminou com erro (ver ab_harness/$label.log)"
  tail -1 "ab_harness/$label.log"
}

say "candidato: Qwen3-1.7B Q4_K_M (porta 8081)"
run qwen3-d1 "$D1" ${EXTRA[@]+"${EXTRA[@]}"}
run qwen3-f2 "$D2" ${EXTRA[@]+"${EXTRA[@]}"}

say "relatórios"
{
  echo "# Conjunto 1 (22 casos)";          python ab_harness/ab_report.py q15-d1 spark-d1 qwen3-d1 --baseline q15-d1
  echo; echo "# Conjunto 2 / fase 2 (9 casos)"; python ab_harness/ab_report.py q15-f2 spark-f2 qwen3-f2 --baseline q15-f2
} > ab_harness/relatorio_qwen3.md 2>&1
echo "relatório em ab_harness/relatorio_qwen3.md"
say "FIM"
