# Regras ↔ código e status dos componentes (M03)
Commit c227789. A Tabela 1 do rascunho **não foi comparada**: o `main_rascunho.tex` não está no repo nem foi enviado. A tabela abaixo é o que o código impõe; compare a Tabela 1 com ela.

## 1. Regra ↔ linha de código
| Regra | Código | Vale para |
|---|---|---|
| Ação permitida por tipo de incidente; tipo desconhecido só notifica/investiga | graph.py:35-41, 90 | todas as ações |
| Eventos citados existem na evidência | graph.py:92 | todas |
| Alvo é IP válido | graph.py:96 | só `block_ip` |
| Alvo está na evidência | graph.py:99 | só `block_ip` |
| Alvo fora de rede protegida | graph.py:101; tools.py:119-124 | só `block_ip` |
| Confiança ≥ 0,80 | graph.py:27, 103 | só `block_ip` |
| ≥ 10 eventos (contados pelo SQL) | graph.py:28, 105 | só `block_ip` |
| IP protegido nem chega ao LLM; só severidade ≥ medium chega | graph.py:156, 165 | todos os incidentes |
| Saída inválida ou rejeitada vira `notify_only` | graph.py:208-209 | todas |
| Escrita fica `pending` até humano aprovar | graph.py:256-258 | `ban_ip_fail2ban` |
| Aprovação em arquivo separado, para a ação exata (hash), vale 24 h | approvals.py:143, 159-162, 209; graph.py:225 | escrita |
| Aprovador não pode ser agent, sysop nem policy:* | approvals.py:152-153, 175, 211 | escrita |
| Ban sem shell, jail fechada (`sshd`), IP normalizado | tools.py:27, 46, 67 | ban |
| Reflect confere no fail2ban/UFW; 1 retry; depois `failed` + ALERT_CRITICAL | graph.py:30, 282, 294-298; tools.py:71-77 | ban |
| Log é sanitizado (sem ANSI, sem `<` `>`; raw 110, user 32) | triage.py:32-36; graph.py:123 | evidência |
| Auditoria append-only | schema.sql:78-81 | audit_log |
| Detecção SSH: ≥ 10 falhas em 10 min; severidade 10/50/200 | triage.py:19-20, 65, 74 | IPv4 |
| Detecção port scan: ≥ 10 portas distintas em 10 min; 100 e 1000 | triage.py:105-106, 129, 154 | UFW |

## 2. Divergências a corrigir no texto (propostas; o código não muda)
| # | O que o código faz | Correção proposta |
|---|---|---|
| D1 | Confiança, alvo, rede protegida e nº de eventos valem só para `block_ip` | Dizer "para bloqueios"; só a regra por tipo vale para todas as ações |
| D2 | O mínimo de 10 eventos nunca barra incidente real: o detector já exige ≥ 10 (triage.py:72, 129) | Chamar de defesa em profundidade, não de filtro |
| D3 | Na execução só revalida rede protegida e aprovação (graph.py:225, 234); não revalida confiança, eventos nem evidência | Não escrever "revalida todas as regras na execução" |
| D4 | `investigate_journal` ignora o alvo e sempre lê a unidade `ssh` (graph.py:245) | Não dizer que investiga o IP |
| D5 | Ações de leitura (`query_journald`, `run_aide_check`) rodam sem aprovação (graph.py:259-261); `run_aide_check` é pesada mas marcada "read" (tools.py:104) | Dizer "escrita exige aprovação", não "toda ação" |
| D6 | `validate_decision` sem `kind` não aplica a regra por tipo (graph.py:90); o grafo sempre passa `kind` (:194) | Detalhe de implementação; vale conferir no V1/V0 do M05 |
| D7 | SSH só reconhece IPv4 (triage.py:16-20); o port scan aceita IPv6 (:22) | Declarar nas limitações; o lab de SSH é IPv4 |

## 3. Status por componente
| Componente | Status | Evidência |
|---|---|---|
| Coletor (journald, UFW, fail2ban) | Validado na placa (banco temporário); unidades systemd no repo, ativação não confirmada | E49; test_deploy_units |
| Detecção SSH força bruta | Só teste unitário | test_triage |
| Detecção port scan | Validado na placa (SYN TCP, 1 varredura) | E49–E52 |
| Detecção pós-login | Não implementado (só tipo no esquema) | RELATORIO §9.5 |
| AIDE → incidente | Não implementado (regra `aide_change` sem IP; triage.py:71 exige IP) | triage.py:25, 71 |
| Validação (`validate_decision`, regra por tipo) | Validado na placa (A/B) e teste unitário | E24, E26 |
| Aprovação humana | Validado na placa | E58, E59 |
| Execução do ban | Validado na placa | E55, E58 |
| Reflect | Validado na placa (caminho feliz); retry e alerta só teste unitário | E58; test_graph |
| Auditoria | Parcial: 2 eventos vistos na placa; resto e espelho no journal só teste | E58; test_audit |
| Retenção e pseudonimização | Implementado, sem teste e sem uso (nenhum import) | C11 |
| RAG / memória | Só teste; `llama-embed` parado na placa | 14.1 |
| Container do LLM no boot | Validado na placa | E61 |
| Resumo em lote | Só teste unitário | test_graph |
| Tool Forge, MCP, BERT, dashboard | Não implementado (BERT tem só o gancho `bert=None`; `tool_registry` é só tabela) | D17 |
