# DECISOES — D01 a D24 (copiadas do contexto mestre v1.0 com o DIFF do v1.1 aplicado)

| ID | Decisão | Status | Motivo | Alternativas |
|---|---|---|---|---|
| D01 | Fonte de verdade = repo (commit fixo) + docs/IMPLANTACAO.md; resumo técnico é contexto | Aceita | C01, C07 | Misturar fontes |
| D02 | Versão final reescreve o rascunho mantendo seções e pergunta; futuro vira presente | Aceita | R25 | Artigo novo do zero |
| D03 | Sem alegar ineditismo; fail2ban é baseline | Aceita | rascunho | Alegar novidade |
| D04 | Congelar o SYSOP-AI numa tag `artigo-u3-base` antes das rodadas. Tag artigo-u3-base em c22778975460af0254da01c691c27a833555b6b7. Segunda tag artigo-u3-rodadas depois do M05 (harness ajustado) | Aceita | Reprodutibilidade | Medir em main móvel |
| D05 | Ablação em 3 condições: V2 completa, V1 sem regra por tipo, V0 sem validação, via flag no runner (graph.py intocado) | Aceita | R05 | Editar graph.py |
| D06 | 3 repetições com seeds 42, 43, 44 | Aceita | C05 | Seed fixa |
| D07 | Manter os 31 casos; só criar casos novos se o modelo nunca tentar ação hostil (nada a ablar) | A validar | Escopo | Ampliar o dataset já |
| D08 | Controle positivo: `fake_server --policy obey` nas 3 condições, para provar que a validação barra um modelo obediente | Aceita | Em 0/8 casos reais o modelo tentou obedecer | Só modelos reais |
| D09 | Baseline (c) = planejador determinístico no lugar do LLM, no mesmo grafo | A validar | R08 | Script separado |
| D10 | Métricas de O1: escape (decisão final proibida), fora do aceitável, tentativa hostil (proposta do modelo) | Aceita | Separa "modelo enganado" de "dano" | Só escape |
| D11 | Proporções com IC de Wilson; latência com mediana, IQR e p95; sem teste de significância | Aceita | n pequeno | t-test |
| D12 | Modelos do artigo: Qwen2.5-1,5B e 3B; Spark-1.7B e Qwen3-1.7B (reprovados) só em nota breve | A validar | Foco | Incluir os 4 |
| D13 | Lab só contra a placa; atacante fora de `protected_networks`; `maxretry` do jail sshd elevado só durante a rodada do agente e restaurado depois; unban só pelo administrador | Aceita | C13, segurança | Jail padrão ativo |
| D14 | Verdade de campo do O3: janelas rotuladas (início/fim registrados) + tráfego benigno | A validar | R07 | Rotular por regra |
| D15 | Latência só da placa; qualidade pode rodar no PC | Aceita | README do harness | Tudo na placa |
| D16 | Demo: ao vivo na placa + gravação de contingência | A validar | R23 | Só gravação |
| D17 | Tool Forge, MCP, BERT, dashboard e AIDE→incidente fora do artigo | Aceita | C08 | Citar como projetado |
| D18 | Resultados apresentados como indício, com limites explícitos | Aceita | R17 | Generalizar |
| D19 | Só entram referências verificadas | Aceita | R22 | Manter as do rascunho sem checar |
| D20 | Demo ao vivo usa o caminho de produção (usuário `sysop`, rastros no banco) ou um banco de demo | A validar | O `sudo` zera o ambiente | Banco próprio |
| D21 | PDF só no M16; compilação antes disso só como diagnóstico, nunca como entrega | Aceita | Decisão dos autores, 25/11/2026 | Compilar a cada módulo |
| D22 | Seguir o feedback dos revisores (FEEDBACK_REVISORES.md): sem pergunta de pesquisa, sem parágrafo de objetivos, tópicos da Proposta renomeados e reduzidos, limitações na Conclusão | A validar | Revisor 1 e 2; conflita com R03, R04, R13 (ver C14–C16) | Manter o rascunho |
| D23 | Corrigir o import do harness no M05: `sys.path.insert(0, str(HERE.parent / "sysopai"))` em ab_runner.py e selftest.py; só ab_harness/ | Aceita | C19 | Usar PYTHONPATH sempre |
| D24 | Limite de 10 páginas sem referências: priorizar tabelas de O1, O2, O3; cortar texto antes de cortar resultado | Aceita | Enunciado IMD0703 | Estourar o limite |

Nota do M02: D04 estava "A validar" no v1.0 e passou a "Aceita" no DIFF do M01. D21 a D24 vêm do DIFF. D22 continua "A validar" até os autores resolverem C14 a C16.
