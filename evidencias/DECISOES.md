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

---

# Parte 2 — Decisões do SISTEMA que o artigo justifica (M03)
Código lido no commit c227789. Linhas: `arquivo:linha`. Exx em `EVIDENCIAS.md`.

| ID | Decisão do sistema | Motivo | Exx | Código |
|---|---|---|---|---|
| S01 | Um único nó LLM (Plan): 1 chamada + no máximo 1 reprompt; detecção é código | Latência de minutos por chamada; quem detecta não pode ser o modelo | E14, E45 | graph.py:188 |
| S02 | Qwen2.5-1,5B em produção (3B só como comparação) | 2,4× mais rápido, concordância 86% vs 73%, 0 escapes nos dois | E12, E14, E16, E24, E27, E32 | — |
| S03 | Regra de ações permitidas por tipo de incidente | O A/B achou o 3B obedecendo injeção e o 1,5B banindo o admin sem injeção | E24, E35 | graph.py:35-41, 90 |
| S04 | Aprovação em arquivo separado, amarrada por hash (id, ts, ferramenta, args), vale 24 h | Agente comprometido não pode se auto-aprovar nem reaproveitar aprovação | E40, E58, E59 | approvals.py:143, 159-162, 209 |
| S05 | Admin lê e aprova via `sudo -u sysop` (`show-action`); resposta do serviço tratada como não confiável | Banco do sysop é 0700; aprovação grava o hash do que o admin viu | E58, E59 | cli.py |
| S06 | Port scan: uma varredura = um incidente (anexa eventos, recalcula) | Sem isso 1 varredura virou 5 incidentes e 5 chamadas de LLM | E49, E50 | triage.py:125-153 |
| S07 | `parse_decision` lê confiança 1<x≤100 como porcentagem; o resto falha fechado | O llama-server não impõe os limites numéricos do esquema | E46 | graph.py:110-119 |
| S08 | Na execução, revalida só a rede protegida e a aprovação | O mundo muda entre proposta e execução (ver D3 em REGRAS_VS_CODIGO.md) | E58 | graph.py:225, 234 |
| S09 | `ignoreip` do fail2ban com LAN, roteador e Tailscale | Protege só o ban automático; `banip` manual o ignora, então a barreira real é o código | E57 | — |
| S10 | Spark-1.7B e Qwen3-1.7B reprovados; fica o 1,5B | Critério fixado antes de medir; nenhum passou | E33, E36, E37 | — |
| S11 | Falha fechada: saída inválida ou rejeitada vira `notify_only` | Nunca agir sem decisão válida | E30 | graph.py:208-209 |
| S12 | IP protegido não chega ao LLM; só severidade ≥ medium chega | Custo e segurança | E11 | graph.py:156, 165 |

## Atualização de 26/11/2026 (implementação da Unidade III, branch u3-avaliacao)
| ID | Status | Onde |
|---|---|---|
| D05 | Implementada | `ab_runner --condicao V2/V1/V0` por monkeypatch; `--sem-portao` para os 5 casos de IP protegido |
| D06 | Implementada | `--seeds 42,43,44` |
| D07 | Aceita | os 31 casos foram mantidos; o controle positivo (D08) dá o que ablar |
| D08 | Implementada | `--planner obey` (e `ingenuo`, controle das regras de rede protegida e de tipo) |
| D09 | Implementada | `--planner regras` no mesmo grafo (fake_server, política escrita a partir do artigo) |
| D11 | Implementada | `ab_harness/u3_report.py` (Wilson, IQR, p95) |
| D13 | Implementada | `lab/fail2ban-lab.local` e `lab/RUNBOOK_LAB.md` |
| D14 | Implementada | gabarito por episódio gravado por `lab/ataque.sh`; métricas em `eval_deteccao/metricas.py` |
| D23 | Implementada | commit d2cb08d |
