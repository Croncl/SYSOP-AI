# CONFLITOS — C01 a C19 (copiados do contexto mestre v1.0 com o DIFF do v1.1 aplicado)

| ID | Descrição | Resolução proposta |
|---|---|---|
| C01 | [CONFLITO] O resumo técnico (18/11) diz 56 testes [Simulado], nada validado em hardware, sem port scan, modelo 3B e aprovação no mesmo SQLite. O repositório e o README (07/11) têm 170 testes, validação na placa, port scan, 1,5B em produção e `approvals.db` separado | Fonte de verdade = repo + docs; o resumo é só histórico |
| C02 | RESOLVIDO. Contagem real = 193 (E01). Antes: 56 / 133 (03/11) / 139 (04/11) / 170 (07/11) | Re-medido no commit congelado (M01) |
| C03 | [CONFLITO] O rascunho diz "será feita" e "protótipo em desenvolvimento", mas port scan, aprovação separada e execução do ban já existem | Reescrever (M12, M13) |
| C04 | [CONFLITO] O rascunho diz que no 2º conjunto "bloquear não é ação válida", mas isso só vale para `post_login_activity`; port scan aceita `block_ip`. Além disso, a detecção pós-login não existe: o incidente é inserido direto | Corrigir e declarar (M13, M14) |
| C05 | [CONFLITO] O rascunho justifica as 3 repetições por variação da saída, mas o runner usa `seed=42` fixo e temperatura 0,1 | Seeds distintas por repetição (D06) |
| C06 | [CONFLITO] A 1ª rodada "sem regra por tipo" não tem `.jsonl` no repo (só texto em RELATORIO §8; `relatorio_baseline.md` é só do conjunto 1, 3B) | Reproduzir como condição V1 (M07) |
| C07 | [CONFLITO] O resumo técnico dá ~4,3 tok/s de geração e 4,6–9,6 de prefill; os relatórios medem 2,9–3,1 e ≈10 (3B) | Usar o medido |
| C08 | [CONFLITO] O resumo técnico descreve MCP e Tool Forge; o repo não os contém (RELATORIO §9.4) | Fora do artigo (D17) |
| C09 | [?] `docs/IMPLANTACAO.md` não está no anexo; 13.10–13.13 e 14.3 só aparecem nos scripts `portscan/apply_docs_*` | Pedir o arquivo ou usar os scripts como fonte |
| C10 | [?] O 1,5B "bloqueou o admin em rotina normal sem injeção" (RELATORIO §8): caso e `.jsonl` não identificados | Localizar na rodada (M07) |
| C11 | [?] `pseudo.py` e `retention.py` existem, mas não há `tests/test_*` para eles | Não afirmar "testado" (M03) |
| C12 | [?] 11 chaves bibliográficas e valores citados (ex.: US$ 4,99 mi, 75×/37×, 16.231 alertas, 5 milhões de requisições) sem `.bib` anexo | Verificar tudo (M04) |
| C13 | [?] O jail `sshd` do fail2ban bane com poucas falhas (maxretry) e interfere na avaliação do agente e na comparação (b) | Controlar na rodada de lab (D13, M10) |
| C14 | R03 vs revisor 1: tirar a pergunta de pesquisa do texto | Aberto, aguarda autores |
| C15 | R04 vs revisor 1: tirar o parágrafo de objetivos; O1–O3 ficam na avaliação | Aberto, aguarda autores |
| C16 | R13/R14 vs revisor 1: tabela de regras vai para "O que é proposto"; limitações vão para a Conclusão | Aberto, aguarda autores |
| C17 | Limite de 10 páginas vs conteúdo previsto | Aberto (D24) |
| C18 | .bib do rascunho ausente e babel-portuges ausente no ambiente de trabalho | Aberto; pedir o .bib antes do M04 |
| C19 | Harness quebrado sem PYTHONPATH (import 'db') | Resolvido em D23 no M05; até lá usar PYTHONPATH=sysopai |

## Atualizações e novos itens do M02 (propostos; não alteram as linhas acima)
| ID | Descrição | Resolução proposta |
|---|---|---|
| C07 | Resolvido por E19 e E20: medido 2,9–3,1 tok/s (geração) e ≈10 (prefill) no 3B; 5,6–5,9 e 22–24 no 1,5B | Usar E19/E20 |
| C09 | Tratado: 13.10, 13.12, 13.13, 14.1 e 14.3 lidos nos scripts `apply_docs_*` (E49 a E61). O `IMPLANTACAO.md` em si continua ausente; 13.1 a 13.9 não foram lidos | Anexar o arquivo para conferir o resto |
| C10 | Continua [Aberto] (E35): o dump não traz `ab_harness/results/*.jsonl` | Procurar na placa ou refazer no M07 |
| C20 | [CONFLITO] "31 incidentes" no texto, mas 5 são dispensados do LLM (IP protegido): o modelo decide em 26 (E11) | Dizer no texto "31 casos, 26 decididos pelo modelo" |
| C21 | [CONFLITO] "2,4 vezes" vale só para o conjunto 1 na mesma rodada (122,9/51,1). Conjunto 2: 1,68×; outra rodada do conjunto 1: 2,17× (E16) | Citar o conjunto e a rodada, ou usar a mediana de todas as rodadas do M06 |
| C22 | [?] O dump do repo não é claramente o commit c227789: o README dele diz 170 testes e o M01 mediu 193 | Confirmar `git log -1` do dump ou anexar o repo na tag artigo-u3-base |
| C23 | [?] Rodada com 1 repetição por caso e seed 42 fixa (E34): as diferenças de 1 ou 2 casos entre modelos são ruído (o próprio 13.13 diz isso) | Refazer com 3 repetições e seeds 42, 43, 44 no M07 (D06) |
