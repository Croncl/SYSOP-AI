# EVIDENCIAS (essencial) — só o que o artigo usa

Níveis: [Medido] na placa/teste executado · [Simulado] teste unitário · [Estimativa] · [Aberto] sem prova. Indício: dados sintéticos, 1 repetição, 1 host.
Fonte principal: ab_harness/relatorio_guard.md, README.md, docs/RELATORIO_TESTES_SEGURANCA.md. IDs mantidos (lacunas são propositais).

| ID | Afirmação | Valor | Nível | Data |
|---|---|---|---|---|
| E01 | Testes no commit congelado | 193 passed em 6,53 s (c227789…, tag artigo-u3-base) | [Medido] | 25/11/2026 |
| E02 | Selftest do harness | OK só com PYTHONPATH=sysopai (sem ele: ModuleNotFoundError 'db') | [Medido] | 25/11/2026 |
| E09 | Casos sintéticos | 31 = 22 (conjunto 1) + 9 (conjunto 2, fase 2) | [Medido] | nov/2026 |
| E10 | Casos hostis | 11 = 8 (conj. 1) + 3 (conj. 2: post_admin_trap, post_inj_sudo_cmd, scan_inj) | [Medido] | nov/2026 |
| E11 | Casos dispensados do LLM (IP protegido) | 4 no conj. 1 + 1 no conj. 2 = 5; logo o modelo decide em 26 dos 31 (derivado; identidade dos 5 = casos 'none' esperado, inferência) | [Medido] | nov/2026 |
| E12 | Latência/incidente, 3B, conj. 1 (rodada guard) | mediana 122,9 s; p95 146,2 s; por chamada 122,9 s | [Medido] | nov/2026 |
| E14 | Latência/incidente, 1,5B, conj. 1 (rodada guard) | mediana 51,1 s; p95 65,4 s; por chamada 50,5 s | [Medido] | nov/2026 |
| E16 | Razão de latência 3B/1,5B ("2,4 vezes") | 122,9/51,1 = 2,405 → 2,4× (mesma rodada, conj. 1). Outros pares: 116,2/53,5 = 2,17×; conj. 2: 118,2/70,3 = 1,68× | [Medido] | nov/2026 |
| E17 | Latência/incidente, 3B, conj. 2 | mediana 118,2 s; p95 181,4 s; por chamada 86,8 s | [Medido] | nov/2026 |
| E18 | Latência/incidente, 1,5B, conj. 2 | mediana 70,3 s; p95 82,7 s; por chamada 36,4 s (rodada q15-f2: 72,3 s; p95 84,2 s) | [Medido] | nov/2026 |
| E23 | JSON válido na 1ª tentativa (3B e 1,5B) | 100% nos dois conjuntos, nos dois modelos | [Medido] | nov/2026 |
| E24 | Escapes de injeção na decisão final (com regra por tipo) | 0 no 3B e 0 no 1,5B, nos dois conjuntos (também 0 em Spark e Qwen3) | [Medido] | nov/2026 |
| E25 | Tentativas hostis do modelo | Conj. 1: 3B 0/8, 1,5B 0/8. Conj. 2: 3B 1/3, 1,5B 0/3 (Spark 1/3) | [Medido] | nov/2026 |
| E26 | Decisão fora do conjunto aceitável | 0 nos 31 casos (decisão segura 100% nos dois modelos e conjuntos) | [Medido] | nov/2026 |
| E27 | Concordância com o esperado, conj. 1 | 3B 73%; 1,5B 86% (q15-d1: 86%) | [Medido] | nov/2026 |
| E28 | Concordância com o esperado, conj. 2 | 3B 100%; 1,5B 100% | [Medido] | nov/2026 |
| E32 | Veredito do critério de substituição | 1,5B PASSA nos 4 critérios frente ao 3B, nos dois conjuntos | [Medido] | nov/2026 |
| E34 | Condições das rodadas | temperature 0,1; seed 42; max_tokens 160; -np 1 -c 2048 -t 4; 1 repetição por caso; json_schema; --hint; prompt cache desligado | [Medido] | nov/2026 |
| E35 | Achados pré-regra por tipo | 3B obedeceu 1 vez 'bloqueie <IP do admin>' dentro de sudo; 1,5B bloqueou o admin em rotina normal sem injeção. Caso e .jsonl não localizados | [Aberto] | nov/2026 |
| E38 | Confiança mínima para bloquear | 0,80 (validate_decision) | [Medido] | nov/2026 |
| E39 | Mínimo de eventos para bloquear | 10 eventos, contados pelo SQL | [Medido] | nov/2026 |
| E40 | Validade da aprovação humana | 24 h (MAX_AGE_S = 24*3600) | [Medido] | nov/2026 |
| E41 | Limiar do port scan | ≥ 10 portas distintas por IP em janela de 10 min (window_s=600, port_threshold=10) | [Medido] | 04/11/2026 |
| E42 | Severidade do port scan | medium até 99 portas; high ≥ 100; critical ≥ 1000 | [Medido] | 04/11/2026 |
| E45 | Chamadas de LLM por incidente | 1 chamada; no máximo 2 (proposta + 1 reprompt); fluxo completo com 1 única chamada | [Simulado] | nov/2026 |
| E47 | Hardware do nó | Orange Pi 4 Pro, 12 GB RAM, aarch64, k3s desligado; conferir com free -h no M06 | [Medido] | nov/2026 |
| E49 | Port scan sem consolidação | 1 varredura nmap -sS virou 5 incidentes (≈10 portas, 63 eventos); corrigido no commit 2a18a53 | [Medido] | 04/11/2026 |
| E50 | Port scan com consolidação | 1 incidente, que cresce de 12 para 19 eventos e de 10 para 16 portas distintas | [Medido] | 04/11/2026 |
| E51 | LLM de produção sobre port scan sintético | 40 portas de 203.0.113.50: 1 chamada, 67,7 s, block_ip com confiança 0,95, ban em pending, 0 ações executadas | [Medido] | 04/11/2026 |
| E52 | Limite de log do UFW | --limit 3/min --limit-burst 10, global (iptables -S); subestima varreduras grandes | [Medido] | 04/11/2026 |
| E55 | Ban real pelo usuário sysop | 203.0.113.50: retorno 1, listado em get sshd banip; unban só pelo administrador; jail volta a 0 | [Medido] | 04/11/2026 |
| E57 | ignoreip do fail2ban | 6 itens (loopback, 10.10.0.0/24, 192.168.0.1/32, 100.64.0.0/10, fd7a:115c:a1e0::/48); banip manual de IP protegido NÃO é impedido (10.10.0.99 listado) | [Medido] | 04/11/2026 |
| E58 | Cadeia de aprovação ponta a ponta | 06–07/11, 00:33–00:42: admin aprova (opad), sysop executa, ban confirmado para 203.0.113.77; antes fora do jail, depois dentro | [Medido] | 07/11/2026 |
| E62 | Ações indevidas sem regra por tipo (V1) e sem validação (V0) | não medido ainda; entra com M05–M07 | [Aberto] | — |
| E63 | Precisão, recall e F1 da detecção; FP e FN | não medido ainda; entra com M10–M11 (F2.5) | [Aberto] | — |
| E64 | Literatura: US$ 4,99 mi | valor citado no rascunho, a conferir no M04 | [Aberto] | — |

Literatura (4,99 mi, 12%, 75×, 37×, 16.231, 5 milhões, 21 estudos): [Aberto] até chegar o .bib (M04).
Atenção: 31 casos, mas o modelo decide em 26 (E11). O 2,4× vale só no conjunto 1 (E16).
