# Evidências da Unidade III

Gerado no PC (Fedora, x86_64, Python 3.14), sem modelo de linguagem, em 26/11/2026. Os `meta.json` registram:
- o commit `3116db6`, com a árvore limpa;
- o sha256 de cada dataset;
- o host;
- as sementes.

Para reproduzir: `bash ab_harness/run_u3_pc.sh sem-modelo` e `python -m eval_deteccao.cenarios --out-dir evidencias/u3/cenarios`.

| Pasta | O que é | Como foi gerado |
|---|---|---|
| `pc-sem-modelo/` | Decisões nos 31 casos sem LLM: controles positivos (`obey` em V2/V1/V0; `ingenuo` sem portão em V2/V0), referência (c) `regras` e referência (b) `fail2ban` simulado. `relatorio_u3.md` e `csv/` agregam tudo | `run_u3_pc.sh sem-modelo` (log em `execucao.log`) |
| `cenarios/` | Detecção em 59 episódios **sintéticos** de fronteira, com gabarito, journal e relatório | `python -m eval_deteccao.cenarios` |
| `historico-placa/` | Reanálise, com o relatório novo, das rodadas feitas na placa em nov/2026 (`evidencias/rodadas/`, 1 repetição, semente 42). Serve à análise do limiar de confiança | `u3_report.py evidencias/rodadas` |

Ainda faltam:
- as rodadas com os modelos reais no PC (V2/V1/V0, 3 sementes): `run_u3_pc.sh modelo`;
- as rodadas de latência e memória na placa: `lab/RUNBOOK_PLACA.md`;
- o laboratório de ataques: `lab/RUNBOOK_LAB.md`.

## Leitura rápida dos resultados sem modelo

- **A validação segura um modelo que obedece toda injeção.**
  - V2: 0 de 11 escapes.
  - V1, sem a regra por tipo: 3 escapes (`inj_force_none`, `inj_run_aide`, `post_admin_trap`).
  - V0, sem validação: 11 escapes.
- **O preço é a omissão.** Em V2, o modelo obediente cai em `notify_only` em 9 dos 17 casos que pedem bloqueio: a injeção não produz bloqueio indevido, mas consegue que o atacante não seja bloqueado. Um humano é notificado.
- **Bloqueador ingênuo, com o portão desligado.** Ele sempre bloqueia o IP do incidente.
  - V0: 12 de 31 decisões indevidas, inclusive IPs da LAN, do roteador e o do administrador em pós-login.
  - V2: 0 decisões indevidas. As rejeições foram 12 pela regra por tipo, 10 pela rede protegida e 2 por poucos eventos.
- **Só com regras, sem LLM:** concorda em 30 de 31 casos, sem decisão indevida e sem omissão. O único desvio é bloquear onde notificar era o esperado, e bloquear também é aceitável ali.
- **fail2ban simulado:** 0 escapes, porque não lê o log como instrução. Tem 5 omissões em 17 (varreduras e linhas fora do formato do sshd) e não trata pós-login nem integridade.
- **Limiar de confiança 0,80.** Na placa, as 114 propostas de `block_ip` vieram com confiança 0,95 (110) ou 1,00 (4). O limiar nunca barrou nada: a confiança declarada pelo modelo é saturada e não serve como probabilidade.
- **Detecção, cenários sintéticos.**
  - O SYSOP-AI falha só onde foi projetado para falhar: abaixo do limiar, ataques lentos, distribuídos, IPv6 no SSH e 9 portas. Não tem falso positivo.
  - O fail2ban (5 falhas em 10 min) pega os lentos e o IPv6 do SSH, mas não vê varredura e bane o administrador que errou a senha 6 vezes.
