# SYSOP-AI

Agente **defensivo** de administração de sistema que roda localmente no `opad-master` (Orange Pi 4 Pro, 12 GB, Linux aarch64, k3s desligado). Observa quem acessa o master e o que acontece nele, detecta ataques e gera resumos que um administrador consegue ler. Caso inicial: força bruta no SSH. Escopo: só o próprio cluster. **Nada depende de serviço externo.**

## Como funciona
```
journald · UFW · fail2ban · AIDE · (auditd, fase 2)
        └─ coletor ─▶ SQLite ─▶ regras (triagem) ─▶ incidentes (agregação em SQL)
                                                         │
        Triage ─▶ Analyze ─▶ Plan (LLM, 1 chamada) ─▶ Execute ─▶ Reflect ─▶ Summarize
                                      │                    │
                      JSON validado por código      escrita só após aprovação humana
```
1. Quem **detecta** é código (regras e SQL), não IA.
2. Para cada incidente relevante, **um** nó chama o LLM local, que propõe **uma** ação em JSON guiado por esquema. O código valida a proposta antes de qualquer coisa.
3. Ações de leitura rodam sozinhas. Ações de **escrita** (ex.: banir um IP) ficam `pending` até um **humano** aprovar, e a aprovação mora num arquivo separado, fora do alcance do serviço.
4. Depois de executar, o Reflect confere se o efeito é real (o ban realmente ficou ativo).

## Garantias (o que o código impõe, independente do modelo)
- Nunca bloqueia a LAN do cluster, o roteador, o loopback, nem IPs de `protected_networks`; IP protegido nem chega ao LLM.
- **Ações permitidas por tipo de incidente:** `post_login_activity` só aceita notificar/investigar; `none` e `run_aide_check` só onde o tipo os pede; tipo desconhecido nunca escreve.
- O alvo de um bloqueio tem de estar na evidência; confiança mínima 0,80; mínimo de 10 eventos (número vindo do SQL).
- Log é entrada do atacante: passa por `sanitize` e fica dentro de `<evidence>`, tratado como dado.
- Falha fechada: saída inválida, dúvida ou erro viram `notify_only`.
- Ferramentas novas propostas pelo agente só valem após validação AST, sandbox sem rede e aprovação humana.

## Estado
Passos 1 a 11 concluídos; passo 13 (testes) em andamento; 12 (auditoria) e 15 (hardening) pendentes; 14 (deploy) em andamento. **139 testes** passando. Detalhes, medições e decisões em [`docs/IMPLANTACAO.md`](docs/IMPLANTACAO.md).

**LLM do nó Plan: Qwen2.5-1.5B** (Q4_K_M) via `llama.cpp` em container podman, `127.0.0.1:8080`, ≈ 50 s por incidente [Medido]. Escolhido em um A/B contra o Qwen2.5-3B (≈ 120 s por incidente); ver passo 13. **Nada é em tempo real.**

Detectores prontos: força bruta no SSH e **port scan** (validado na placa em 04/11/2026; ver o passo 13.10). Faltam: detecção de atividade pós-login, cadeia completa de aprovação do ban no deploy (o trecho `sudo` + `fail2ban` já foi validado na placa), auditd, dashboard, alertas, unidades `systemd` do coletor e do agente e hardening de produção. O container do LLM já sobe sozinho no boot (passo 14.1).

## Estrutura
| Pasta | Conteúdo |
|---|---|
| `sysopai/` | código: coletor, triagem, banco, RAG, grafo (`graph.py`), tools, aprovações, CLI |
| `tests/` | testes (`pytest`) |
| `scripts/` | avaliação do RAG e benchmark do Plan |
| `kb/` | base curada de procedimentos para o RAG |
| `docs/` | documento de implantação incremental |
| `ab_harness/` | A/B de modelos do nó Plan, dados sintéticos e relatórios (ver o README dele) |

## Rodando
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=sysopai
python -m pytest -q                      # testes
python sysopai/cli.py --help             # comandos (init, run-once, approve, ...)
```
Pré-requisitos do sistema: Python 3, SQLite, journald, ufw, fail2ban, aide, podman e a imagem `ghcr.io/ggml-org/llama.cpp:server`. Os modelos (`.gguf`) ficam em `/srv/models` e **não** estão no repositório.

Avaliar um modelo novo para o Plan: `bash ab_harness/run_all.sh quick` (ver `ab_harness/README.md`).

## Compatibilidade
Feito e validado no **Orange Pi 4 Pro** (Debian, aarch64). **Outros Linux são viáveis**, com ajustes pequenos; os testes unitários já passam em Debian 13 x86_64, mas o sistema completo só foi executado na placa. Alvo primário: Debian e Ubuntu (systemd/journald, UFW, `fail2ban`). Em outras distribuições, a unidade SSH, a origem de log do firewall e o `fail2ban` mudam. O ponto mais sensível é `protected_networks`, que vem com a LAN do cluster e **precisa ser reescrita em cada instalação**. Avaliação completa e proposta no passo 13.11 do [`docs/IMPLANTACAO.md`](docs/IMPLANTACAO.md).

## Limites conhecidos
- O LLM é **conselheiro**: a segurança vem das validações em código, e o modelo não é prova de nada.
- Latência alta em 6×A55 com ≈10 GB/s de banda; o gargalo é o prefill do prompt.
- Testes de A/B são sintéticos, com 1 repetição por caso nos números atuais.
- O port scan só é visto na medida em que o UFW registra: o log dele tem limite global (3/min, rajada de 10), então varreduras grandes são subestimadas. O ruído conhecido (ex.: Tailscale, UDP 41641) deve ser descartado sem log (`ufw deny`).
- A separação de aprovação só é real com as permissões do deploy (passo 14).

## Documentação
- [`docs/IMPLANTACAO.md`](docs/IMPLANTACAO.md): histórico, decisões, medições e pendências, passo a passo.
- Arquitetura de referência: doc 14 (`14-sysop-ai-arquitetura-agentica.md`, mantido no Projeto Claude, fora deste repositório).
