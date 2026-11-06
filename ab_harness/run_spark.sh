#!/usr/bin/env bash
# A/B no mesmo dia e nas mesmas condições: Qwen2.5-1.5B (produção, :8080) vs candidato Spark (:8081).
#   nohup bash ab_harness/run_spark.sh > ab_harness/run_spark.log 2>&1 &
# Opcional: BODY_EXTRA='{"chat_template_kwargs":{...}}' (só vai para o candidato).
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

for port in 8080 8081; do
  curl -sf "http://127.0.0.1:$port/health" >/dev/null || { echo "ERRO: sem servidor saudável na porta $port"; exit 1; }
done

run() {  # $1=label $2=dataset $3=porta ; resto = extras do runner
  local label="$1" ds="$2" port="$3"; shift 3
  if [ -e "$R/$label.jsonl" ]; then echo "pulando $label (já existe em $R)"; return 0; fi
  say "rodando $label"
  python ab_harness/ab_runner.py --label "$label" --hint --dataset "$ds" \
    --base-url "http://127.0.0.1:$port/v1" --reps 1 "$@" > "ab_harness/$label.log" 2>&1 \
    || echo "AVISO: $label terminou com erro (ver ab_harness/$label.log)"
  tail -1 "ab_harness/$label.log"
}

say "1/ baseline: Qwen2.5-1.5B (porta 8080)"
run q15-d1 "$D1" 8080
run q15-f2 "$D2" 8080
say "2/ candidato: Spark (porta 8081)"
run spark-d1 "$D1" 8081 ${EXTRA[@]+"${EXTRA[@]}"}
run spark-f2 "$D2" 8081 ${EXTRA[@]+"${EXTRA[@]}"}

say "3/ relatórios"
{
  echo "# Conjunto 1 (22 casos)";          python ab_harness/ab_report.py q15-d1 spark-d1 --baseline q15-d1
  echo; echo "# Conjunto 2 / fase 2 (9 casos)"; python ab_harness/ab_report.py q15-f2 spark-f2 --baseline q15-f2
} > ab_harness/relatorio_spark.md 2>&1
echo "relatório em ab_harness/relatorio_spark.md"
say "FIM"
