#!/usr/bin/env python3
"""Atualiza docs/IMPLANTACAO.md e README.md: A/B de candidatos ao nó Plan (Spark-X2.6-1.7B e Qwen3-1.7B) -> seção 13.13. Só texto.
Requer os patches de documentação anteriores (13.12 e passo 14) já aplicados.

  * seguro: texto exato, senão NADA é alterado; idempotente; cópias em *.bak-docs-ab.

    python portscan/apply_docs_ab_candidatos.py        # na raiz do projeto (ou com o script em uma subpasta)
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = "### 13.13 A/B de candidatos ao nó Plan"
ANCHOR = "\n\n---\n\n## Passo 14 — Deploy (em andamento)"

SECTION = """

### 13.13 A/B de candidatos ao nó Plan: Spark-X2.6-1.7B e Qwen3-1.7B (reprovados)
**Data:** 05 e 06/11/2026 · **Host:** `opad-master` · [Medido na placa]. Decisão do responsável (06/11/2026): **manter o Qwen2.5-1.5B** no nó Plan.

**Candidatos.**
| Modelo | Origem | Arquivo | Observações |
|---|---|---|---|
| Spark-X2.6-1.7B | `XHToken/Spark-X2.6-1.7B-GGUF` (repositório do autor, apache-2.0) | `Spark-X2.6-1.7B-Q8_0.gguf`, 1,7 GB, `sha256` `8d96279c95ae…` conferido contra o do repositório | Arquitetura `spark2_5` (carregou na imagem `llama.cpp:server` atual, sem atualizá-la); contexto nativo 1.048.576 (usamos `-c 2048`); o template **liga o raciocínio por padrão** |
| Qwen3-1.7B | `unsloth/Qwen3-1.7B-GGUF` (**terceiros**, reempacota o `Qwen/Qwen3-1.7B`, apache-2.0) | `Qwen3-1.7B-Q4_K_M.gguf`, 1,1 GB, `sha256` `b139949c5bd7…` conferido | Q4_K_M para ficar na mesma classe do baseline; o Q8_0 oficial (1,8 GB) repetiria o custo de banda visto no Spark |

**Não testados, e por quê.** `Qwen3-1.7B-FP8` e `-GPTQ-Int8` (GPU: vLLM e `transformers`; o `llama.cpp` não os lê), `-MLX-*` (só Apple Silicon), `-Base` (sem ajuste para instruções, não segue o prompt do Plan). `Qwen3-0.6B` não foi testado por decisão do responsável: chance baixa de passar em concordância e a latência não é o gargalo hoje.

**Condições (iguais para os três).** Mesma imagem; `-np 1 -c 2048 -t 4 --jinja`, `--memory=4g`, `--cap-drop=ALL`, modelo `:ro`; `temperature` 0,1, `seed` 42, `max_tokens` 160, saída `json_schema`, `--hint`, 1 repetição por caso, dois conjuntos (22 + 9 casos). `enable_thinking: false` nos candidatos (`--body-extra`); **0 saídas com `<think>`** nos três. O baseline foi **medido de novo** no mesmo dia que o Spark (não se reaproveitou rodada antiga, por causa da temperatura); o Qwen3 rodou na manhã seguinte, com a placa mais fria (máx. 84,5 a 89,4 °C contra 91 a 93,7 °C), o que, se algo, o favorece na latência. Critério de substituição **o de 13.2, fixado antes de medir** e não alterado depois.

**Resultados.**
| Métrica | Qwen2.5-1.5B (produção) | Spark-1.7B Q8_0 | Qwen3-1.7B Q4_K_M |
|---|---|---|---|
| Conj. 1: JSON válido na 1ª tentativa | 100% | 89% | 100% |
| Conj. 1: concordância com o esperado | **86%** | 77% | 50% |
| Conj. 1: rejeição do `validate_decision` | 6% | 17% | 50% |
| Conj. 1: decisão final `notify_only` | 6% | 17% | 61% |
| Conj. 1: fallback (`notify_only` 0,0) | 0% | 11% | 0% |
| Conj. 1: erros de HTTP/timeout | 0 | 4 | 0 |
| Conj. 1: latência por incidente, mediana / p95 | **53,5 s** / 65,4 s | 115,1 s / 146,2 s | 89,6 s / 151,7 s |
| Conj. 2: JSON válido na 1ª tentativa | 100% | 100% | 88% |
| Conj. 2: concordância com o esperado | **100%** | **100%** | 89% |
| Conj. 2: latência por incidente, mediana / p95 | 72,3 s / 84,2 s | 205,8 s / 232,4 s | **70,9 s** / 156,3 s |
| Geração (tok/s, mediana) | 5,6 a 5,7 | 3,8 a 3,9 | 3,2 a 4,0 |
| Prefill (tok/s, mediana) | 22,0 a 22,2 | 23,9 a 24,2 | 21,2 a 22,8 |
| Decisão segura (conjunto aceitável) | 100% | 100% | 100% |
| **Escapes de injeção (decisão final)** | **0** | **0** | **0** |
| Tentativas hostis do modelo (conj. 1 / conj. 2) | 0/8 / 0/3 | 0/8 / 1/3 | 0/8 / 0/3 |

**Veredito pelo critério.** Os dois candidatos **não passam**:
- **Spark:** concordância 77% < 86% e JSON válido 89% < 100% no conjunto 1; latência por incidente de 2 a 3 vezes a do baseline nos dois conjuntos. No conjunto 2 a concordância empata (100%), mas a latência reprova. Duas respostas hostis do conjunto 1 (`inj_ansi`, `inj_run_aide`) terminaram em `notify_only`, direção segura mas diferente do esperado; no conjunto 2 uma tentativa hostil do modelo foi barrada pelo `validate_decision`.
- **Qwen3:** concordância 50% (conjunto 1) e 89% (conjunto 2), JSON válido 88% no conjunto 2, latência mediana 68% pior no conjunto 1. Foi **conservador demais**: 61% das decisões finais em `notify_only` e 7 dos 8 casos hostis do conjunto 1 terminaram assim. É seguro (zero escapes), mas o agente quase nunca proporia um ban. No conjunto 2 a mediana de latência (70,9 s) ficou ligeiramente abaixo da do baseline, mas o p95 foi de 156 s e a qualidade reprovou antes.

**Achados.**
1. Os erros do baseline não são exclusivos dele: `aide_change`, `ext_single_valid_user` e `success_after_fails` divergem do esperado também nos candidatos (o Qwen3 acertou só o último). Reforça a pendência de resolver esses casos por **regra em código** (13.8, itens 3 e 5), e não por troca de modelo.
2. **A segurança não distinguiu os modelos:** com a regra por tipo e o `validate_decision`, os três tiveram 0 escapes. O que separou foi qualidade operacional (concordância, JSON de primeira, fallbacks) e latência.
3. O Spark em Q8_0 gerou a 3,8 tok/s contra 5,6 do baseline, com prefill igual: a placa é limitada por banda de memória. A diferença **não** parece ser só a quantização: o Q4_K_M oficial do Spark tem 1769 MB contra 1820 MB do Q8_0 [Estimativa: ganho de velocidade pequeno]; o único arquivo bem menor (`AD-Q4_K_M`, 1168 MB) é de terceiros e usa quantização própria, e **não** foi testado.
4. No Spark, a latência por incidente é quase o dobro da por chamada no conjunto 2 (205,8 s contra 114,2 s): mais de uma chamada por incidente (reprompt e fallback).

**Limites (honestos).**
- **1 repetição por caso**; 22 e 9 casos. Diferença de 1 ou 2 casos (o Spark contra o baseline em concordância) é ruído; a do Qwen3 e a de latência do Spark não são. A fase com 3 repetições **não foi rodada**, porque nenhum candidato passou na primeira.
- **O prompt, a dica e o esquema foram calibrados para o Qwen2.5-1.5B.** Os resultados valem para **este agente como está**, não para os modelos em geral; adaptar o prompt a cada modelo seria outro trabalho.
- O Qwen3 veio de um empacotamento de terceiros (`sha256` conferido, origem não verificável além disso); só foi usado em teste, nunca em produção.
- Spark em Q8_0 e Qwen3 em Q4_K_M: quantizações diferentes entre os candidatos.
- Conjuntos sintéticos (ver 13.7).

**Reproduzir.** `ab_harness/run_spark.sh` (baseline + Spark, portas 8080 e 8081) e `ab_harness/run_qwen3.sh` (só o Qwen3, porta 8081; exige os resultados do baseline e do Spark). Relatórios em `ab_harness/relatorio_spark.md` e `ab_harness/relatorio_qwen3.md`. Os containers de teste (`llama-ab-spark`, `llama-ab-qwen3`) são temporários; a produção (`llama-plan-15b`, porta 8080) não foi alterada.
"""

IMPL_EDITS = [
 ("índice, linha 13",
  "A/B de modelos do Plan, regra por tipo de incidente e detecção de port scan concluídos;",
  "A/B de modelos do Plan (inclui Spark-1.7B e Qwen3-1.7B, reprovados: 13.13), regra por tipo de incidente e detecção de port scan concluídos;"),
]

README_EDITS = [
 ("modelo do Plan",
  "Escolhido em um A/B contra o Qwen2.5-3B (≈ 120 s por incidente); ver passo 13.",
  "Escolhido em um A/B contra o Qwen2.5-3B (≈ 120 s por incidente); em 06/11/2026 o Spark-X2.6-1.7B e o Qwen3-1.7B foram testados e reprovados (ver passo 13, seção 13.13)."),
]


def check(path: Path, edits) -> bool:
    s = path.read_text()
    for name, old, _ in edits:
        if s.count(old) != 1:
            print(f"ERRO em {path.name}: trecho '{name}' não bate exatamente (achei {s.count(old)}x). Nada foi alterado.")
            return False
    return True


def main() -> int:
    impl, readme = ROOT / "docs" / "IMPLANTACAO.md", ROOT / "README.md"
    s = impl.read_text()
    if MARK in s:
        print("já aplicado, nada a fazer")
        return 0
    if "### 13.12 Execução real do ban" not in s or "## Passo 14 — Deploy" not in s:
        print("ERRO: aplique antes os patches de 13.12 e do passo 14. Nada foi alterado.")
        return 1
    if s.count(ANCHOR) != 1:
        print(f"ERRO: âncora do passo 14 não bate (achei {s.count(ANCHOR)}x). Nada foi alterado.")
        return 1
    if not (check(impl, IMPL_EDITS) and check(readme, README_EDITS)):
        return 1
    for _, old, new in IMPL_EDITS:
        s = s.replace(old, new)
    s = s.replace(ANCHOR, SECTION.rstrip("\n") + "\n" + ANCHOR)
    r = readme.read_text()
    for _, old, new in README_EDITS:
        r = r.replace(old, new)
    shutil.copy2(impl, str(impl) + ".bak-docs-ab")
    shutil.copy2(readme, str(readme) + ".bak-docs-ab")
    impl.write_text(s)
    readme.write_text(r)
    print("ok: IMPLANTACAO.md e README.md atualizados (backups .bak-docs-ab)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
