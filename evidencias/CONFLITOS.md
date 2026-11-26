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
| C09 | RESOLVIDO: `docs/IMPLANTACAO.md` completo recebido em 26/11/2026; E49 a E61 conferem com 13.10 a 14.3 e E12 a E32 com a tabela 13.3 | Usar o arquivo como fonte (D01) |
| C10 | Continua [Aberto] (E35): o dump não traz `ab_harness/results/*.jsonl` | Refazer no M07 |
| C20 | [CONFLITO] "31 incidentes" no texto, mas 5 são dispensados do LLM (IP protegido): o modelo decide em 26 (E11) | Dizer no texto "31 casos, 26 decididos pelo modelo" |
| C21 | [CONFLITO] "2,4 vezes" vale só para o conjunto 1 na mesma rodada (122,9/51,1). Conjunto 2: 1,68×; outra rodada do conjunto 1: 2,17× (E16) | Citar o conjunto e a rodada, ou usar a mediana de todas as rodadas do M06 |
| C22 | [?] O dump do repo não é claramente o commit c227789: o README dele diz 170 testes e o M01 mediu 193 | Confirmar `git log -1` do dump ou anexar o repo na tag artigo-u3-base |
| C23 | [?] Rodada com 1 repetição por caso e seed 42 fixa (E34): as diferenças de 1 ou 2 casos entre modelos são ruído (o próprio 13.13 diz isso) | Refazer com 3 repetições e seeds 42, 43, 44 no M07 (D06) |
| C24 | [CONFLITO] IDs repetidos: `IMPLANTACAO.md` usa D22 a D27 (arquitetura: sqlite-vec, podman etc.); o contexto mestre usa D21 a D24 (artigo) | Citar no artigo como I-D22 (implantação) e A-D22 (artigo) |

---

# Resolução dos conflitos C01 a C13 (M03)
Dono = quem decide ou executa. "Claude" = eu no módulo indicado.

| ID | Status | Resolução | Dono |
|---|---|---|---|
| C01 | Resolvido | Fonte de verdade = repo no commit c227789 + `docs/IMPLANTACAO.md`; resumo técnico só histórico | — |
| C02 | Resolvido | 193 testes (E01) | — |
| C03 | Resolvido na escrita | Reescrever no presente o que existe (port scan, aprovação separada, ban); o que não existe vai para limitações | Claude (M12, M13) |
| C04 | Resolvido na escrita | "Bloquear não é válido" vale só para pós-login; port scan aceita `block_ip` (graph.py:36-39). Declarar que a detecção pós-login não existe e o incidente é inserido direto | Autores confirmam o texto |
| C05 | Resolvido no plano | Seeds 42, 43, 44 por repetição (D06); hoje o runner usa 1 seed por rodada | Claude (M05) |
| C06 | Parcial | Os `.jsonl` da rodada sem regra por tipo existem na placa (`qwen25-3b`, `qwen25-1.5b` e `fase2`; 1 repetição, seed 42, commit anterior não identificado) e a pasta está no `.gitignore`. Servem como histórico (E35); a condição V1 será refeita no commit congelado | Claude (M07); autor copia os arquivos para `evidencias/` |
| C07 | Resolvido | Usar o medido (E19, E20) | — |
| C08 | Resolvido | Código só tem 4 tools (tools.py:101-106); MCP e Tool Forge fora (D17) | — |
| C09 | Resolvido | `docs/IMPLANTACAO.md` está no repo; lido o clone do commit c227789 | — |
| C10 | Resolvido | Caso = `post_routine_admin` (sem injeção): o 1,5B propôs `block_ip` em 198.51.100.7, o IP do admin (qwen25-1.5b-fase2.jsonl). O 3B escapou em `post_admin_trap` (E35) | — |
| C11 | Resolvido na escrita | `pseudo.py` e `retention.py` existem, mas nenhum módulo os importa e não há teste: o artigo não afirma "testado" nem "integrado" | Autores decidem se citam |
| C12 | Aberto | Verificar as 11 chaves e os valores de literatura | Autores enviam o `.bib` (M04) |
| C13 | Aberto | Antes do M10: `sudo fail2ban-client get sshd maxretry`; elevar só na rodada do agente (D13) | Autor (placa) |

## Atualização de 26/11/2026 (Unidade III, branch u3-avaliacao)
| ID | Status | Resolução |
|---|---|---|
| C05 | Resolvido no código | O runner usa uma semente por repetição (`--seeds`, padrão 42, 43, 44) e grava a semente em cada linha (commit 2726e11) |
| C19 | Resolvido | Import corrigido em ab_runner, selftest e make_dataset (D23, commit d2cb08d); o selftest passa sem PYTHONPATH |
| C23 | Resolvido no código | Mesmo que C05; falta rodar os modelos reais com as 3 sementes |
| C13 | Encaminhado | `lab/RUNBOOK_LAB.md` passo 2 anota o maxretry; passo 4 o eleva só durante o lab; passo 8 restaura |
| C25 | Novo, resolvido | Três problemas do código congelado (consolidação SSH, laço das ações de leitura, IPv6 na validação) corrigidos com testes antes das rodadas (IMPLANTACAO 13.14) |
