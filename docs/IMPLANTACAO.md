# SYSOP-AI — Documento de implantação incremental

> Documento vivo. Cada passo adiciona uma seção. Um novo integrante deve conseguir entender o histórico só por aqui.
> Fonte de verdade do desenho: `14-sysop-ai-arquitetura-agentica.md` (doc 14, v1.0, 19/10/2026).
> Legenda de confiança (herdada do doc 14): **[Medido]** · **[Simulado]** · **[Estimativa]** · **[Aberto]**.

## Índice de passos

| # | Passo | Estado |
|---|---|---|
| 1 | Arquitetura e planejamento | Concluído |
| 2 | Ambiente de desenvolvimento | Concluído |
| 3 | Estrutura inicial do projeto | Concluído |
| 4 | Docker e containers (na prática: podman) | Concluído |
| 5 | Banco de dados | Concluído |
| 6 | API Backend (na prática: coletor + triagem; CLI e MCP adiados) | Concluído parcialmente (CLI, MCP e grafo ficam para o passo 11) |
| 7 | Segurança e autenticação | Concluído (P36 e `ignoreip` abertos) |
| 8 | Pipeline RAG | Concluído |
| 9 | Vetorização | Concluído (checksum verificado em 27/10) |
| 10 | Busca semântica | Concluído |
| 11 | Integração com LLM | Concluído (MCP movido para o passo 15; modelo do Plan trocado no passo 13) |
| 12 | Logs e auditoria | Pendente |
| 13 | Testes | **Em andamento** (A/B de modelos do Plan, regra por tipo de incidente e detecção de port scan concluídos; trecho `sudo` + `fail2ban` do ban validado na placa; cadeia completa de aprovação no deploy, integração e demais testes pendentes) |
| 14 | Deploy | **Em andamento** (container do LLM no boot concluído; unidades do coletor e do agente, cadeia de aprovação e permissões do deploy pendentes) |
| 15 | Hardening para produção | Pendente |

---

## Passo 1 — Arquitetura e planejamento

**Data:** 20/10/2026 · **Tipo de alteração:** somente documentação (nenhum código, pacote ou serviço instalado).

### 1.1 Objetivo
Fixar o que será construído, com quais limites, em que ordem, e quais decisões já estão tomadas, antes de escrever código.

### 1.2 O sistema em uma frase
Agente defensivo de administração de sistema que roda no `opad-master` (Linux aarch64, k3s desligado): lê logs nativos, detecta incidentes por **regras em código**, usa **um** LLM local (Qwen2.5-3B via llama-server) em **um único nó** para propor uma ação, e **nenhuma escrita acontece sem aprovação humana**.

### 1.3 Princípios (invariantes do projeto)
1. **O que pode ser código é código.** Detecção, agregação, validação e verificação são determinísticas.
2. **O LLM só decide em um nó (Plan)** e resume em lote. Cada chamada custa minutos (≈2 a 4,5 min/incidente [Estimativa]).
3. **Toda escrita passa por humano.** `AUTO_APPROVE` vazio por padrão.
4. **Log é entrada do atacante.** Tudo que vai ao LLM é sanitizado e marcado como dado não confiável.
5. **Falha fechada.** Sem decisão válida → `notify_only`; sem runtime de container → recusa executar.
6. **Redes protegidas nunca são banidas** (o master é o gateway: banir `10.10.0.0/24` derruba o cluster).

### 1.4 Arquitetura-alvo (visão de componentes)

```
journald ─▶ collector.py ─▶ triage.py (regras) ─▶ SQLite (WAL) + sqlite-vec
                                                     │
                      timer 10 min ─▶ cli.py run-once ─▶ grafo LangGraph
                      Triage▶Analyze▶Plan(LLM)▶Execute▶Reflect▶Summarize
                                                     │ MCP (stdio)
                              sysop-read (leitura) ◀─┴─▶ sysop-actions (1 tool: execute_approved_action(id))
                                                     │ sudo -n (sudoers mínimo)
                                                  ufw · fail2ban · aide
LLM: llama-server (127.0.0.1:8080)      Tool Forge: LLM propõe ▶ AST ▶ sandbox ▶ humano ▶ approved
```

### 1.5 Mapeamento: sequência de implantação × componentes reais
A sequência pedida (15 etapas) é genérica. Ela foi **mapeada** ao que o doc 14 realmente prevê:

| Etapa pedida | Equivalente neste projeto | Observação |
|---|---|---|
| 4. Docker e containers | **podman** (D27) para llama-server e sandbox de tools | Docker vem desabilitado na imagem; containerd do k3s para junto com o k3s |
| 6. API Backend | **Não há API HTTP.** Há `cli.py` + servidores MCP (stdio) | Menos superfície de ataque; dashboard Streamlit é fase 2 |
| 7. Segurança e autenticação | Usuário `sysop`, sudoers mínimo, aprovação humana por usuário Unix, banco de aprovações separado (P36) | Autenticação = identidade Unix, não token HTTP |
| 8–10. RAG / vetorização / busca | `mem_docs` + `mem_vec` (sqlite-vec, 1024 dim, bge-m3), só texto curado | RAG é **opcional** (precisa de embed ≈ 446 MiB) |
| 11. Integração com LLM | llama-server + `response_format=json_schema` | Nunca testado no cluster (P37) |

### 1.6 Decisões técnicas e justificativas

| ID | Decisão | Justificativa | Alternativas consideradas |
|---|---|---|---|
| D22 | sqlite-vec em vez de LanceDB | Mesmo arquivo SQLite, 1 dependência, busca exata basta para dezenas de milhares de vetores | LanceDB (só se passar disso) |
| D23 | Regras primeiro; BERT opcional e só após ajuste fino | BERT em 6×A55 custa dezenas de ms/linha e disputa banda de memória com o LLM; SecBERT não tem cabeça de classificação [Estimativa] | BERT em toda linha |
| D24 | LLM só no nó Plan + resumo em lote; Reflect determinístico | Latência de minutos por chamada; validador que funciona é o programa | LLM também em Reflection |
| D25 | Escrita sempre com humano; nunca em redes protegidas | Risco de derrubar o cluster; injeção por log | Auto-ban com limiar de confiança |
| D26 | Tools geradas são funções puras `run(lines)`, só em sandbox, aprovadas por hash | Reduz superfície ao mínimo | Tools com acesso a arquivo/rede |
| D27 | podman enquanto o k3s estiver desligado | Não depende do k3s | containerd puro; docker |
| — | Qwen2.5-3B já em uso (4,3 tok/s) | Já medido; o 4B (2,6 tok/s) não compensa para JSON curto | Modelos maiores |

### 1.7 Dependências planejadas (ainda **não** instaladas)
`langgraph>=1.0`, `pydantic>=2.6`, `sqlite-vec>=0.1.9`, `mcp>=1.2,<2` (a 2.x mudou APIs), `pytest` (dev). Sistema: Python 3, SQLite, journald, ufw, fail2ban, aide, podman, llama.cpp (imagem de container).

### 1.8 Requisitos de segurança desta etapa
- **Revisão (20/10/2026, esclarecimento do responsável):** o ambiente de desenvolvimento **é o `opad-master`** (único nó utilizado; não há máquina x86 separada). A suposição original de "dev em x86" foi descartada. Consequência: desenvolvimento e produção compartilham o mesmo host, então o código de dev fica em `~/sysopai-dev` (usuário humano), separado de `/opt/sysopai` e do usuário `sysop`, e nenhum comando privilegiado do SYSOP-AI (`sudo ufw`, `fail2ban-client`, `aide`) é executado antes do passo de segurança/hardening.
- O master é o gateway da LAN do cluster: qualquer ação que possa interromper rede, DNS, NTP ou NAT é proibida durante o desenvolvimento.
- Registrar o IP do administrador em `protected_networks` (será feito no passo de Banco de Dados).

### 1.9 Riscos identificados
1. **Fronteira de aprovação fraca (P36):** agente e aprovações no mesmo SQLite; um agente comprometido poderia gravar `approved`. Correção planejada: banco de aprovações separado ou assinatura.
2. **`sudo -n` impede `NoNewPrivileges=yes`** no unit do agente.
3. **Injeção de prompt por log** reduzida, não eliminada; a barreira real é a validação em código.
4. **Latência do LLM** só medida em prompts curtos (P25/P33).
5. **LGPD:** `daily_aggregates` guarda `src_ip` indefinidamente (P27/P38).
6. **Escopo (P31):** o desenho cobre logs do próprio master, **não** tráfego de outra infraestrutura (isso exigiria Suricata/Zeek).
7. **Master é gateway/DNS/NTP?** Nunca conferido (P31); condiciona desligar o k3s.

### 1.10 Pendências herdadas do doc 14 (rastreio)
P25/P33 latência real do Plan · P27/P38 retenção de IPs · P30 uso total de memória · P31 escopo e serviços do master · P34 validar sudoers/fail2ban/ufw/aide · P35 sandbox em container na placa · P36 separar banco de aprovações · P37 validar `json_schema` no llama-server · P39 classificador · P40 fase 2 (auditd, port scan, dashboard, alertas, KB de CVE).

### 1.11 Fora de escopo (fase 2)
Ingestão do auditd, detecção de port scan, dashboard Streamlit, canais de alerta, base de CVE, classificador BERT, cliente de embeddings.

### 1.12 Estado do sistema ao final do passo 1
Nada implantado. Existe apenas este documento.

---

## Passo 2 — Ambiente de desenvolvimento

**Data:** 20/10/2026 · **Tipo de alteração:** preparação do `opad-master` (aarch64), que é o único host e serve como ambiente de desenvolvimento. *(Versão anterior deste passo assumia x86 separado; corrigida a pedido do responsável.)*

### 2.1 Objetivo
Ter um ambiente Python isolado, reproduzível e verificado, onde o código do SYSOP-AI possa ser escrito e testado **sem hardware** e sem privilégios.

### 2.2 Contexto
O doc 14 declara que os testes dele foram feitos em x86 com servidores falsos [Simulado]. Aqui, porém, o desenvolvimento ocorre direto no `opad-master`, o que traz benefício (sqlite-vec, podman e llama-server testados na arquitetura real, fechando P34/P35/P37) e cuidado extra (o host é gateway e pode estar rodando o k3s). Mantemos a separação por **usuário e diretório**, não por máquina.

### 2.3 Decisões e justificativas
| Decisão | Justificativa | Alternativas |
|---|---|---|
| Python 3.11+ com `venv` (stdlib) | Zero dependência extra; isolamento de pacotes; `X \| None` e tipos usados no código exigem ≥3.10 | conda, poetry, uv |
| Dependências em `requirements.txt` com faixas (`mcp>=1.2,<2`) | Já definido no doc 14; a mcp 2.x quebra APIs | Lock com hashes (débito técnico) |
| Git desde o início | Histórico auditável das decisões | — |
| Verificar `enable_load_extension` | sqlite-vec é extensão do SQLite; algumas builds de Python a desabilitam | Usar sem RAG (o código já tolera) |

### 2.4 Dependências introduzidas
Python (pip, no venv): `langgraph`, `pydantic`, `sqlite-vec`, `mcp<2`, `pytest` (dev), instalados com `--only-binary=:all:` (sem compilar no master). Pacotes do sistema (apt): `python3-venv`, `git`. Python do Debian 12 (3.11).

### 2.5 Requisitos de segurança
- `sudo` somente para `apt install python3-venv git` (único uso de privilégio neste passo). Nada de `apt upgrade`. Pacotes Python só dentro do `venv`, como usuário humano (nunca root, nunca `sysop`).
- Instalação pip com `nice` e `--only-binary=:all:` para não sobrecarregar CPU/temperatura do master (picos de 96,3 C já vistos [Medido]).
- O `venv/` e arquivos de banco/chaves entram no `.gitignore` (nunca versionar IP do administrador).
- Fixar versões exatas depois (`pip freeze`) para reduzir risco de cadeia de suprimentos (débito técnico).

### 2.6 Riscos
- Dev e produção no mesmo host: erro de desenvolvimento pode afetar o gateway da LAN (mitigação: usuário e diretório separados, nada privilegiado do projeto neste passo).
- Falta de wheel aarch64 para alguma dependência → `--only-binary` falha em vez de compilar (aceitável; decidir o que fazer se ocorrer).
- Python do sistema sem suporte a extensões SQLite → RAG indisponível.
- Consumo de memória/CPU do dev disputando com k3s/LLM (P30).
- Versões futuras das libs mudando APIs.

### 2.7 Pendências / débitos
Lockfile com hashes; CI; testar em aarch64.

### 2.8 Estado do sistema ao final do passo 2
No `opad-master` existe `~/sysopai-dev/` com `venv`, repositório git e dependências instaladas. Nenhum código do projeto ainda. **22/10/2026:** o responsável já havia desativado o k3s para implantar o SYSOP-AI (doc 14, seção 9); este passo não altera k3s, rede nem firewall. Conferido: nenhum `containerd-shim` ativo (o k3s não deixou containers).

### 2.9 Registro de execução (22/10/2026)
- **Local do projeto alterado:** `/home/projetos/SYSOP-AI` (e não `~/sysopai-dev`). `/home/projetos` pertence a `root:root` (755) e contém outros projetos; foi criada só a subpasta com `sudo mkdir` + `sudo chown opad:opad`, sem alterar a pasta-pai. Usuário de trabalho: `opad` (grupos `sudo`, `users`).
- **Instalado:** `python3-venv`, `git` (apt); venv Python 3.11.2; pydantic 2.14.1, sqlite-vec v0.1.9, pytest 9.1.1, langgraph e mcp (versões não registradas; fixar no lockfile, débito técnico).
- **Validado [Medido]:** `aarch64`; sqlite-vec carrega no SQLite do Python (RAG viável, fecha parte de P35); memória: 11 GiB total, 377 MiB usados, 10 GiB livres, sem swap (ponto de partida para P30).
- **Observação:** o master não tem swap; picos de memória do LLM + embeddings devem ser observados.
- **Pendência:** primeiro commit git ainda não feito (será no passo 3).

---

## Passo 3 — Estrutura inicial do projeto

**Data:** 22/10/2026 · **Local:** `/home/projetos/SYSOP-AI` · **Tipo:** criação de diretórios e arquivos de configuração; nenhum código de negócio.

### 3.1 Objetivo
Definir onde cada coisa vive (código, testes, documentação), configurar o pytest e fazer o primeiro commit, para que os passos seguintes só "encaixem" arquivos.

### 3.2 Estrutura
```
SYSOP-AI/
├── docs/        IMPLANTACAO.md (este documento) e doc 14 (arquitetura)
├── sysopai/     código-fonte (módulos planos: db.py, triage.py, tools.py, graph.py ...)
├── tests/       testes pytest
├── pytest.ini   configuração do pytest
├── README.md    porta de entrada do repositório
├── requirements.txt · .gitignore · venv/ (não versionado)
```

### 3.3 Decisões e justificativas
| Decisão | Justificativa | Alternativa |
|---|---|---|
| Módulos **planos** em `sysopai/` (sem subpacotes) | O código do doc 14 usa `import db`, `import tools as T`; manter esse formato evita reescrever imports e mantém o pacote equivalente ao `sysopai.zip` testado | Pacote com `from sysopai import db` (exige alterar todos os arquivos) |
| `pytest.ini` com `pythonpath = sysopai` | Permite aos testes importar os módulos planos sem instalar o pacote | `pip install -e .` com `pyproject.toml` (débito técnico se o projeto crescer) |
| Documentação dentro do repositório (`docs/`) | Histórico de decisões versionado junto com o código | Wiki externa |
| Commit local com identidade só deste repositório | Não altera configuração global do usuário `opad` | `git config --global` |

### 3.4 Dependências introduzidas
Nenhuma nova.

### 3.5 Requisitos de segurança
`.gitignore` já impede versionar `*.db*`, `.env` e `journal.cursor`. Regra: nunca commitar IP do administrador nem segredos.

### 3.6 Riscos
Módulos planos limitam a organização se o projeto crescer; `pytest.ini` esconde problemas de empacotamento (aceito por ora).

### 3.7 Pendências
Mover para `pyproject.toml` e instalação editável se o projeto for distribuído; lockfile com hashes. Branch padrão do git é `master` (renomear para `main` é opcional).

### 3.8 Registro de execução (22/10/2026)
- **Validado [Medido]:** `pytest -q` → 1 passed; commit `f61795e` "Passo 3: estrutura inicial do projeto"; árvore limpa; `git check-ignore` confirma `venv/` ignorado (`.gitignore:1`).
- **Lição:** `.gitignore` é arquivo oculto; usar `ls -a` para vê-lo.
- **Pendência:** copiar `IMPLANTACAO.md` e o doc 14 para `docs/` no master e commitá-los.

---

## Passo 4 — Containers (podman)

**Data:** 22/10/2026 · **Host:** `opad-master` (aarch64, Debian 12) · **Usuário:** `opad` (rootless).

### 4.1 Objetivo
Ter um runtime de containers que responda, para executar tools geradas pelo agente no sandbox (`toolforge.py`, falha fechada sem runtime). O llama-server em container fica para o passo 11.

### 4.2 Diagnóstico inicial [Medido]
Só `/usr/bin/docker` existia (serviço `disabled`/`inactive`); podman ausente; `cgroup2fs`; `opad` com faixa `165536:65536` em `/etc/subuid` e `/etc/subgid`. O containerd usado antes era o embutido do k3s (desligado; dados do k3s preservados em `/var/lib/rancher/k3s`).

### 4.3 Decisão
**podman rootless** (D27). Justificativas: sem daemon, sem root, o código já o prefere, o containerd do k3s depende do k3s ligado, e o daemon do Docker rodaria como root (maior superfície). Alternativas: nerdctl+containerd standalone (mais peças), Docker (daemon root).

### 4.4 Implementação
`sudo apt install -y podman uidmap` (podman 4.3.1; `uidmap` fornece `newuidmap`/`newgidmap`, necessários ao rootless e **não** vieram como dependência); `podman pull docker.io/library/python:3.12-slim-bookworm` (imagem de `toolforge.IMAGE`, armazenada em `~/.local/share/containers`).

### 4.5 Validação [Medido]
- `podman info`: rootless `true`, cgroups `v2`, runtime `crun`.
- Container com as flags do sandbox (`--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=32 --memory=128m --memory-swap=128m --cpus=0.5 --user=65534:65534`, `python -I -S`): `uid 65534`, rede bloqueada, escrita bloqueada. Sem avisos de cgroup na saída.

### 4.6 Requisitos de segurança
Sem daemon privilegiado; sem rede no sandbox; FS somente leitura; sem capabilities; usuário `nobody`; limites de PIDs/memória/CPU. O Docker permanece desabilitado.

### 4.7 Riscos e pendências
- O teste comprovou UID, rede e escrita, **não** que os limites de memória, PIDs e CPU foram efetivamente impostos (depende da delegação de cgroups ao usuário). Verificar (ex.: `cat /sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/cgroup.controllers` deve listar `memory pids cpu`) antes de confiar no sandbox (P35).
- Tempo de partida do container na placa ainda não medido (P35).
- O sandbox em container ainda não foi exercitado com o `sandbox_runner.py` real (passo de testes).
- Dependências do passo: `podman`, `uidmap` (apt); imagem `python:3.12-slim-bookworm`.

---

## Passo 5 — Banco de dados

**Data:** 22/10/2026 · **Arquivos novos:** `sysopai/schema.sql`, `sysopai/db.py`, `tests/test_db.py` · **Banco de dev:** `data/sysop.db` (ignorado pelo git).

### 5.1 Objetivo
Criar o único estado persistente do agente (SQLite em WAL + sqlite-vec) com as garantias de segurança impostas **pelo próprio banco**, e o módulo de acesso `db.py`.

### 5.2 Decisões e justificativas
| Decisão | Justificativa | Alternativa |
|---|---|---|
| SQLite em WAL + sqlite-vec (D22) | Um arquivo, uma dependência; escritores não bloqueiam leitores (coletor, agente e consultas simultâneos) | PostgreSQL (daemon extra, memória), LanceDB |
| Triggers e CHECKs no banco | Defesa em profundidade: `audit_log` append-only, ban só com `approved_by`, tool só aprovada por humano a partir de `sandbox_ok`, código de tool imutável | Validar só no código Python |
| Conexão `mode=ro` + `query_only` para análise | O agente não escreve pelas consultas de evidência | Mesma conexão para tudo |
| `synchronous=NORMAL` | Seguro em WAL, menos gravações no NVMe | `FULL` (mais lento) |
| Caminho do banco via `SYSOP_DB` (exportada no `venv/bin/activate`) | Dev em `data/sysop.db`; produção em `/var/lib/sysopai/sysop.db` sem mudar código | Caminho fixo |
| IPs do administrador ficam só no banco, nunca no `schema.sql` | O repositório não vaza endereços | Inserir no schema |

### 5.3 Esquema (11 tabelas, 4 triggers)
`raw_events`, `collector_cursor`, `incidents`, `agent_actions`, `audit_log`, `protected_networks`, `tool_registry`, `summaries`, `llm_calls`, `daily_aggregates`, `mem_docs` (+ `mem_vec` virtual, criada por `db.init()`, 1024 dim, cosseno). Triggers: `audit_log_no_update`, `audit_log_no_delete`, `tool_needs_human`, `tool_source_immutable`.

### 5.4 Redes protegidas (decisão do responsável)
O IP do administrador não é fixo e o MAC não serve (o agente só vê IPs; MAC não é visível fora do segmento e é falsificável). **Opção A adotada:** proteger `192.168.0.0/24` (wlan0 do master = 192.168.0.4; admin conectando de 192.168.0.3). Lista atual: `10.10.0.0/24`, `127.0.0.0/8`, `192.168.0.0/24`, `192.168.0.1/32`, `::1/128`.
- **Risco aceito:** qualquer aparelho da LAN doméstica fica imune a banimento pelo agente (só gera aviso).
- **Alternativa futura (B):** reserva DHCP por MAC no roteador e proteger só o IP fixo.
- O master só tem `wlan0` e `lo`; a `10.10.0.0/24` não tem interface agora (cluster desligado).

### 5.5 Validação [Simulado/Medido]
Esquema em memória: 11 tabelas, 4 triggers. `pytest`: 7 passed (6 de `test_db.py`: WAL, `mem_vec`, auditoria append-only, conexão somente leitura, ban sem humano recusado, tool sem humano/sandbox recusada e imutável, memória vetorial idempotente e com busca correta, usando embedding falso). Banco `data/sysop.db` criado em 151 KB.

### 5.6 Requisitos de segurança
Auditoria imutável; aprovações exigem humano; leitura isolada; `protected_networks` fora do repositório. **Limite conhecido (P36):** o agente e as aprovações ainda compartilham o mesmo arquivo; um agente comprometido com escrita no arquivo contorna os triggers. Correção planejada: banco de aprovações separado.

### 5.7 Riscos e pendências
- A linha `export SYSOP_DB=...` no `venv/bin/activate` se perde se o venv for recriado (repor).
- Retenção: o purge de 60 dias é só SQL comentado; o timer systemd entra no deploy. `daily_aggregates` guarda IPs indefinidamente (P27/P38, LGPD).
- Em produção o banco ficará em `/var/lib/sysopai` com dono `sysop` e permissão 0700 (passo de deploy).
- Dependência nova: nenhuma.

---

## Passo 6 — Backend: triagem e coletor

**Data:** 22/10/2026 · **Arquivos novos:** `sysopai/triage.py`, `sysopai/collector.py`, `tests/test_triage.py`, `tests/test_collector.py`.

### 6.1 Objetivo e escopo
Transformar linhas do journald em eventos classificados e incidentes. **Não há API HTTP** neste projeto (doc 14): o "backend" é coletor + triagem + CLI, o que elimina porta aberta e autenticação web. **Adiados:** `tools.py` e servidores/cliente MCP (passo 7, segurança), grafo LangGraph (passo 11, LLM) e `cli.py` (depois de tools e grafo, pois os importa).

### 6.2 Decisões e justificativas
| Decisão | Justificativa | Alternativa |
|---|---|---|
| Regras (regex) em vez de modelo por linha | µs por linha; BERT em 6×A55 custa dezenas de ms e disputa banda de memória com o LLM (D23) | BERT em toda linha |
| Incidente agregado em SQL (≥10 falhas/10 min por IP; ≥50 high; ≥200 critical) | Contagem e severidade vêm do código, nunca do modelo | Deixar o LLM decidir |
| `sanitize()` antes de qualquer texto ir ao LLM | Log é entrada do atacante (ex.: nome de usuário SSH) | Enviar cru |
| Filtro no coletor (`sshd`, `sudo`, `fail2ban-server`, `aide`, kernel só com `[UFW `) | O journal inteiro é volume inútil (3% foi gravado) | Gravar tudo |
| Gravação em lote (50 eventos / 2 s) e cursor do journal | Menos escritas no NVMe; retoma após reinício | Gravar linha a linha |
| Teste com dados reais do journal além dos testes de unidade | Os testes de unidade usaram linhas inventadas e não pegaram dois erros de formato | Só testes de unidade |

### 6.3 Validação [Medido]
`pytest`: 21 passed. Journal real (2 dias, 8.673 linhas): 3% gravadas. **Duas regras do doc 14 estavam erradas para o formato real e foram corrigidas:** (1) UFW usa também endereços IPv6 (`SRC=fe80:...`); (2) o sudo no journal aparece como `    opad : TTY=... ; COMMAND=...`, sem prefixo `sudo: `. Resultado após a correção: `ufw_block` 276, `sudo` 9, `ssh_ok` 1, `other` 23 (principalmente `pam_unix`/`pam_env`). O teste `test_formatos_reais_do_journal` fixa esses formatos.

### 6.4 Achados sobre o host [Medido]
- O journal do master tem `dnsmasq` (1.292 linhas), `NetworkManager`, `tailscaled` e `containerd`: **o DNS é serviço do SO**, não pod (confirma em parte P31).
- O master tem só `wlan0` (192.168.0.4) e `lo`.
- Ruído: a maioria dos `ufw_block` é multicast IPv6 (`MAC=33:33:...`), inofensivo; fica como `minor` e não gera incidente (só `bruteforce`/`critical` geram).

### 6.5 Requisitos de segurança
Linha malformada nunca derruba o coletor; `raw` truncado em 2.000 caracteres; `sanitize` remove controle/ANSI e `<` `>`; ler o journal exige grupo `systemd-journal` (será do usuário `sysop`, não do `opad`).

### 6.6 Riscos e pendências
- **`ssh_fail` real não validado** [Aberto]: nenhuma falha de login ocorreu em 2 dias; a regra segue o formato padrão do OpenSSH. Validar quando houver uma falha (ou provocar uma de propósito).
- `collector.run()` (processo vivo com `journalctl -f`) **não foi testado ao vivo**; depende do grupo `systemd-journal` (deploy).
- **Tailscale:** o journal mostra `tailscaled`; se o acesso ao master for por Tailscale, o IP de origem do SSH é `100.64.0.0/10` e precisa entrar em `protected_networks` (pergunta ao responsável, pendente).
- Fontes `auditd`, `fail2ban` e `aide` ainda sem regras validadas com dados reais; port scan e integridade são fase 2.
- Volume de `ufw_block` pode crescer; o purge de 60 dias entra no deploy.

---

## Passo 7 — Segurança e autenticação

**Data:** 22/10/2026 · **Arquivos novos no repositório:** `sysopai/tools.py`, `tests/test_tools.py`. **Alterações no host:** usuário `sysop`, `/opt/sysopai`, `/var/lib/sysopai`, `/etc/sysopai/env`, `/etc/sudoers.d/sysop`.

### 7.1 Objetivo e modelo
Neste projeto não há login web: a **autenticação é a identidade Unix**. O agente roda como `sysop` (sem shell, sem senha); o humano aprova como ele mesmo (`opad`); a futura CLI recusa aprovações feitas pelo `sysop`.

### 7.2 Diagnóstico do host [Medido]
UFW ativo; SSH e fail2ban ativos (fail2ban 1.0.2, único jail `sshd`; `get sshd banip` funciona nesta versão); `aide` **não instalado**; Tailscale ativo (IP do master `100.111.186.82`); `/etc/sudoers.d` só tinha `pi` e `README`; `systemd-journal` (gid 999) e `adm` existem; `ufw` e `visudo` ficam em `/usr/sbin` (fora do PATH do usuário comum).

### 7.3 Decisões e justificativas
| Decisão | Justificativa | Alternativa |
|---|---|---|
| Usuário `sysop` de sistema, `nologin`, grupo `systemd-journal` | Menor privilégio; lê o journal sem `sudo`; não loga | Rodar como `opad` ou `root` |
| `/opt/sysopai` `root:sysop 0750` | O serviço executa o código mas **não pode alterá-lo** | Código do próprio `sysop` |
| `/var/lib/sysopai` `sysop 0700`; `/etc/sysopai/env` `root:sysop 0640` (sem segredos) | Dados só do serviço; config só editável por root | — |
| `sudoers`: só `ufw status [numbered]`, `fail2ban-client get sshd banip`, `fail2ban-client set sshd banip *` | Menor conjunto que as tools precisam. `unbanip` e `aide` **fora**: desfazer é ato humano e `aide` não existe | `*` mais largo; `fail2ban-client` inteiro |
| Escrever o sudoers em `/tmp`, validar com `visudo -cf` e só então instalar | Erro de sintaxe pode quebrar o `sudo` de todos | Editar direto |
| `tools.py`: Pydantic + `ipaddress`, `shell=False`, listas fechadas, `sudo -n`, `write` só com `approved=True` | A validação real do IP é o código; o `*` do sudoers é só um piso | Confiar no sudoers |
| Rede `100.64.0.0/10` (Tailscale) protegida | Acesso do administrador pode vir pela tailnet | Só a LAN |

### 7.4 Validação [Medido]
`pytest`: 29 passed (8 de `test_tools.py`: IP hostil recusado, jail/unidade/`since`/`limit` fora da lista recusados, tool desconhecida e escrita sem aprovação recusadas, argv sem shell, `is_protected` IPv4/IPv6, `is_banned` não confunde `1.2.3.4` com `1.2.3.45`, saída do journal sanitizada, só `ban_ip_fail2ban` é `write`). No host: `sudo -l -U sysop` lista só os 4 comandos; `ufw status` e `get sshd banip` funcionam como `sysop`; `ufw status verbose` e `ls /root` recusados; **ban real** de `203.0.113.250` (IP de documentação) via sudoers aceito, `is_banned` retornou `True` (e `False` para o prefixo `203.0.113.25`), desfeito pelo humano com `unbanip`, `is_banned` voltou a `False`. Fecha parte de **P34** (sudoers, fail2ban e `ufw` validados; `aide` pendente).

### 7.5 Riscos residuais (honestos)
1. **Fronteira de aprovação (P36) — ainda aberta.** Agente e aprovações compartilham `agent_actions` no mesmo SQLite do `sysop`; um processo comprometido pode escrever `approved`. **Desenho decidido, implementação no passo 11:** gravar aprovações em arquivo separado (`approvals.db`) de dono do administrador e legível (somente leitura) pelo serviço, com `action_id`, `tool`, `sha256(args_json)`, `approved_by`, `approved_at`; a execução revalida o hash dos argumentos. Alternativa: assinar com chave que o serviço não possui.
2. **O sudoers permite `fail2ban-client set sshd banip *` diretamente ao `sysop`.** Um `sysop` comprometido poderia banir qualquer IP (inclusive os protegidos) sem passar pelo grafo nem pelo MCP. Mitigação planejada (passo 15): `ignoreip` com as redes protegidas no jail do fail2ban e **testar** se o `banip` manual o respeita [Aberto]; alternativa: wrapper root que valida o IP contra as redes protegidas.
3. O agente não consegue se auto-aprovar pela CLI (recusa `sysop`), mas isso não protege contra escrita direta no arquivo (item 1).
4. O fail2ban já bane sozinho (limiar padrão menor que o nosso de 10 falhas/10 min); o agente é complementar e pode raramente disparar. Revisar `maxretry` no passo de testes.
5. O banco de **produção** (`/var/lib/sysopai/sysop.db`) ainda não existe: ao criá-lo no deploy, repor as redes protegidas (LAN, Tailscale `100.64.0.0/10`).
6. Senha digitada por engano na conversa (22/10): recomendado trocar com `passwd`.

### 7.6 Pendências
`aide` (instalar ou aposentar a tool); implementar `approvals.db` (P36); `ignoreip` + teste de `banip` em rede protegida; MCP (leitura e escrita por `action_id`) e CLI no passo 11; permissão de leitura do journal pelo `sysop` já validada.

---

## Passo 8 — Pipeline RAG

**Data:** 23/10/2026 · **Arquivos novos:** `sysopai/rag.py`, `kb/procedimentos.md`, `tests/test_rag.py` · **Alterado:** `sysopai/db.py`.

### 8.1 Objetivo e escopo
Caminho curadoria → chunks → memória (sqlite-vec) → recuperação, para o agente lembrar de procedimentos e resoluções. É **opcional** (doc 14): sem sqlite-vec ou sem embedder, o retriever devolve `[]` e o agente funciona. O embedder real é do passo 9; aqui ele é injetado e os testes usam um embedder falso.

### 8.2 Decisões e justificativas
| Decisão | Justificativa | Alternativa |
|---|---|---|
| Só texto **curado** entra; log bruto nunca | Logs se consultam por SQL; similaridade em logs seria ruído e vetor de injeção | Indexar logs |
| Ingestão aceita só `resolution` e `kb` (recusa `incident`) | Reduz envenenamento de memória: o que entra é escrito por humano; `incident` só será gravado pelo código por template | Aceitar qualquer tipo |
| Chunks de até 1.000 caracteres (limite do banco: 1.200), por parágrafo | Contexto pequeno = prefill barato no LLM de 3B; sem perder texto | Chunks fixos por caracteres |
| Cada seção `## Título` do markdown é um documento | Procedimentos curtos e autocontidos recuperam melhor | Um documento por arquivo |
| Embedder injetado (função) | Pipeline testável sem modelo; troca de modelo sem mexer no pipeline | Chamar o modelo direto |
| Base de conhecimento versionada em `kb/` | Histórico e revisão por humanos; sem segredos | Base fora do repositório |

### 8.3 Bug encontrado e corrigido em `db.mem_add` (passo 5)
A linha era gravada em `mem_docs` **antes** de calcular o embedding. Se o embedder falhasse (esperado com o llama-server), restava uma linha órfã e, pelo `content_sha`, o texto **nunca mais seria reindexado**. Correção: embedding primeiro, gravação depois; texto limitado a 1.200 caracteres antes do hash. O teste `test_falha_de_embedding_nao_grava_nada` cobre.

### 8.4 Validação [Simulado]
`pytest`: 36 passed (7 de `test_rag.py`: limite sem perda de texto, seções, tipos permitidos, idempotência da ingestão, base real do projeto com chunks ≤1.200, recuperação correta, falha de embedding sem gravar). Embedding falso: **a qualidade real da recuperação ainda não foi medida.**

### 8.5 Requisitos de segurança
Texto recuperado é **dado não confiável**: o grafo o coloca em `<memory>` e passa por `sanitize` (passo 11). A distância vetorial só **ordena**, não decide acerto. Escrita na memória só por ingestão de `kb`/`resolution` (humano) e, no futuro, `incident` por código.

### 8.6 Riscos e pendências
- Qualidade da recuperação com o modelo real (bge-m3, 1024 dim) [Aberto]: medir no passo 10 com perguntas reais.
- Memória/latência do embedder (≈446 MiB, só se o RAG for ligado, P30).
- Resoluções passadas: ainda não há comando para o humano registrar uma `resolution` (CLI, passo 11).
- Dependência nova: nenhuma.

---

## Passo 9 — Vetorização

**Data:** 23 a 27/10/2026 · **Arquivos novos:** `sysopai/embed.py`, `tests/test_embed.py` · **Alterado:** `sysopai/rag.py` · **Host:** modelo `/srv/models/bge-m3-q8_0.gguf`, container `llama-embed`.

### 9.1 Objetivo
Serviço de embeddings (bge-m3, 1024 dim) no master e cliente Python que serve de embedder ao `rag.py` e ao `db.mem_add`.

### 9.2 Diagnóstico [Medido]
O bge-m3 **não existia em disco** (`/srv/models` só tinha Qwen2.5-3B, Qwen2.5-7B em 2 partes e Qwen3.5-4B); a imagem do llama.cpp ficara no containerd do k3s e não estava no podman. Memória livre 10 GiB; 8 CPUs visíveis.

### 9.3 Decisões e justificativas
| Decisão | Justificativa | Alternativa |
|---|---|---|
| Modelo `ggml-org/bge-m3-Q8_0-GGUF` (`bge-m3-q8_0.gguf`, 606 MB), baixado para `/srv/models` | Conversão publicada pelo projeto llama.cpp; Q8_0 perde pouca qualidade; mesma dimensão do `mem_vec` (trocar de modelo obriga reindexar) | Q4_K_M (≈438 MB), outros conversores |
| llama-server (`ghcr.io/ggml-org/llama.cpp:server`, arm64, 849 MB) em container podman, `--embedding --pooling cls`, `-c 2048` | O bge-m3 exige pooling CLS; contexto de 2.048 cobre chunks de ≤1.200 caracteres | Biblioteca Python em-processo (mais memória no agente) |
| **`--network=host` com `--host 127.0.0.1`** | O kernel `5.15.147-sun60iw2` **não tem o módulo TUN** (`/dev/net/tun` ausente): o podman rootless não publica portas (`-p`). A restrição ao loopback passa a vir do `--host` | Recompilar o kernel; outro runtime |
| `--log-driver=k8s-file` | O driver padrão (journald) falha para o `opad`, que não está no grupo `systemd-journal` | Adicionar `opad` ao grupo |
| Porta 8081 (a 8080 fica para o LLM do nó Plan) | Evita colisão | — |
| Cliente só com stdlib; valida dimensão exata e números finitos; tudo vira `EmbedError` | Servidor externo é dado não confiável também em formato | Confiar na resposta |
| Retriever devolve `[]` se o embedder falhar; a ingestão falha alto | Falha de memória não pode derrubar a análise do incidente; ingestão incompleta deve ser visível | Propagar a exceção |

### 9.4 Validação [Medido, com modelo real]
- `/health` ok; `dim 1024`, norma 1,0; porta em `127.0.0.1:8081` (`ss -ltn`). RAM do modelo ≈ 450 MB (392 → 840 MiB usados), conferindo a estimativa do doc 14 (≈446 MiB).
- Latência (mediana de 5, após aquecimento): texto de 30 caracteres **139 ms**; ~1.000 caracteres **1.189 ms** (máx 1.201). Ingestão da base `kb/` (4 chunks): 2,0 s.
- Qualidade, **amostra muito pequena e favorável** (4 perguntas escritas pelo mesmo autor da base): 4/4 acertos no 1º resultado. Margens entre o 1º e o 2º resultado: 0,072, 0,171, **0,025**, 0,140 (distância de cosseno). A margem de 0,025 ("como reverter um banimento" × "Como desfazer" vs. outra seção) é frágil.
- `pytest`: 43 passed (7 de `test_embed.py`, com servidor HTTP falso: formato da requisição, dimensão errada, JSON inválido, HTTP 500, servidor fora, texto vazio, integração ingestão/busca, retriever degradando para `[]`).

### 9.5 Achados e requisitos de segurança
- Houve **reinício da placa às 17:40**; o container ficou em `Created` e **não sobe sozinho**. Requer unidade systemd do usuário (rootless) com "linger" (passo 14).
- O llama-server avisa: sem chave de API e CORS aberto. Com a porta só no loopback o risco é um processo local falar com ele (só devolve vetores). Chave de API no passo 15.
- Com `--network=host` o container enxerga os serviços do loopback do master: isolamento de rede menor que uma rede própria. Mantidos: `--cap-drop=ALL`, `no-new-privileges`, modelo montado `:ro`, `--memory=2g`, imagem oficial. O sandbox das tools usa `--network=none` e não é afetado.
- Dependências introduzidas no host: `slirp4netns` e `libslirp0` (apt) — **inúteis sem TUN; remover** (`apt remove`).

### 9.6 Riscos e pendências
- **Checksum verificado (27/10/2026) [Medido]:** `sha256sum` de `bge-m3-q8_0.gguf` = `aa473d51f451a22f0fcf39ba3330c14bed38a385712b1113440f69df4047a173`, idêntico ao `lfs.oid` publicado pela API do Hugging Face. Prova integridade do download, não que o publicador seja confiável.
- A consulta real do grafo é `"{kind} {severity}"` (ex.: `ssh_bruteforce medium`), **não** uma pergunta em linguagem natural como as do teste: a qualidade real dessa consulta ainda não foi medida (passo 10).
- Embeddings concorrentes com o LLM do nó Plan disputam a banda de memória (P25/P30).
- Reindexação obrigatória se o modelo ou a quantização mudarem.

---

## Passo 10 — Busca semântica

**Data:** 27/10/2026 · **Arquivos novos:** `scripts/eval_rag.py` · **Alterados:** `sysopai/rag.py`, `kb/procedimentos.md`, `tests/test_rag.py`.

### 10.1 Objetivo
Medir a recuperação com a consulta que o agente realmente faz, e decidir como tratar consultas sem resposta na base (a busca sempre devolve o "menos distante", mesmo irrelevante).

### 10.2 Medições com o modelo real [Medido]
- Consultas com resposta na base: distância do 1º resultado **0,27 a 0,46**. Consultas sem resposta (outro assunto, ou tipos de incidente sem procedimento): **0,56 a 0,73**. Lacuna entre os dois grupos: 0,446 a 0,556 (≈0,11).
- A consulta do grafo no formato de palavras-chave (`ssh_bruteforce medium`) funcionou (margem 0,13 a 0,14), mas uma frase descritiva aproxima mais (≈0,37 contra 0,45).
- Um erro real: "o ip 100.111.186.82 da tailscale pode ser banido?" foi para "Brute force". Causa: a base falava em `100.64.0.0/10` sem citar "Tailscale"; embeddings **não relacionam um IP a uma faixa CIDR**. Corrigido na base. Lição: **quem decide se um IP é protegido é o código (`is_protected`), nunca a memória.**

### 10.3 Decisões e justificativas
| Decisão | Justificativa | Alternativa |
|---|---|---|
| `rag.build_query(kind, severity, n_events, ip_protected)`: consulta montada **pelo código** a partir de fatos do incidente, com limpeza de caracteres | Nunca usa texto do log (entrada do atacante); inclui fato que só o código sabe (IP em rede protegida) | Consulta de palavras-chave `"{kind} {severity}"` |
| Corte de distância **0,50** (`SYSOP_RAG_MAX_DISTANCE`) no retriever | Evita injetar no prompt trechos sem relação (tokens caros, superfície de injeção); separa os dois grupos medidos | Sem corte; corte por margem |
| O corte é um **filtro grosseiro de ruído**, não decisão de relevância | A distância só ordena (lição do laboratório de RAG); errar para o lado "sem trecho" é seguro (o grafo funciona sem memória) | Tratar o corte como verdade |
| Critério de aprovação do script: algum dos **k=2** trechos é aceitável (top1 impresso ao lado) | O grafo injeta 2 trechos; medir só o 1º seria rígido demais | Só top1 |
| Base atualizada: seção de redes protegidas cita "Tailscale" | Corrige o erro medido | — |

### 10.4 Defeito encontrado e corrigido (meu)
A primeira versão de `build_query` acrescentava "IP externo, devo propor banimento?". Isso puxou consultas de `port_scan` e `integrity_change` (sem procedimento na base) para 0,41 e elas passaram o corte: **regressão introduzida por mim**, detectada pelo script de avaliação. Sufixo removido; voltaram a 0,56 a 0,57 (descartadas).

### 10.5 Validação [Medido]
`pytest`: 46 passed. `python scripts/eval_rag.py`: **0 falhas em 12**; 1 caso acerta só no 2º lugar (consulta de IP em rede protegida: 1º "Brute force", 2º "Falhas de login").

### 10.6 Limites (honestos)
- **Poucos dados e ajuste no mesmo conjunto:** 12 consultas, base de 4 documentos, e o corte foi escolhido olhando estes mesmos casos (sem conjunto separado de validação). Margem do pior caso irrelevante ao corte: 0,556 contra 0,50 (≈0,056), apertada.
- Recalibrar o corte quando a base crescer ou o modelo mudar; o script (`scripts/eval_rag.py`) existe para isso e deve entrar nos testes de integração (passo 13).
- O script depende do container `llama-embed` no ar.

### 10.7 Impactos no passo 11 (grafo)
1. Usar `rag.build_query` na etapa Analyze (em vez de `"{kind} {severity}"`).
2. **Pular o LLM quando o IP do incidente está em rede protegida** (só registrar aviso): hoje `open_incidents` abre incidente também para esses IPs e cada um custaria 2 a 4,5 min de LLM para ser rejeitado depois pela validação.
3. O retriever já devolve `[]` se o embedder falhar ou se nada passar o corte; o prompt segue sem `<memory>`.

---

## Passo 11 — Integração com o LLM (grafo, aprovações separadas e CLI)

**Data:** 27 a 29/10/2026 · **Arquivos novos:** `sysopai/graph.py`, `sysopai/approvals.py`, `sysopai/cli.py`, `scripts/bench_plan.py`, `tests/test_graph.py`, `tests/test_approvals.py`, `tests/test_cli.py` · **Host:** container `llama-plan`.

### 11.1 Objetivo
Ligar o LLM ao agente (nó Plan), validar o `json_schema` (P37), medir a latência real (P25/P33), implementar o grafo e fechar a fronteira de aprovação (P36).

### 11.2 Servidor do LLM
> **Atualização (03/11/2026):** o nó Plan passou ao **Qwen2.5-1.5B** (container `llama-plan-15b`, mesmas restrições); o 3B (`llama-plan`) ficou parado para volta atrás. Medições e decisão no passo 13.

`ghcr.io/ggml-org/llama.cpp:server` em podman, `--network=host` (kernel sem TUN) e `--host 127.0.0.1 --port 8080`, `--alias react`, `-np 1 -c 2048 -t 4`, `--memory=4g`, `--cap-drop=ALL`, modelo montado `:ro`. Modelo: `qwen2.5-3b-instruct-q4_k_m.gguf` (2 GB). RAM usada sobe ≈ 2 GiB (840 MiB → 2,8 GiB). Mesmos avisos do embedder: sem chave de API e CORS aberto; porta só no loopback. **Os containers não sobem sozinhos no boot** (pendência do passo 14).

### 11.3 Medições [Medido]
| Item | Valor |
|---|---|
| `response_format=json_schema` no llama-server desta imagem | **Funciona** (JSON válido, Pydantic aceitou) — fecha **P37** |
| Prefill (prompt frio, 703 tokens) | 63 s a **11,15 tok/s**; ≈ 91 s para ~1.020 tokens |
| Geração | **2,94 tok/s** (102 tokens em 34 s) |
| Plan completo (prompt frio) | **≈ 100 s (1m37s a 1m48s de ponta a ponta no `simulate`)**; fecha **P33** |
| Temperatura | 73,6 → 74,7 °C (44,5 → 72,3 °C na segunda execução); longe do pico de 96,3 °C do doc 14 |

**Erro meu corrigido:** a primeira execução do benchmark (51 s) estava contaminada por cache de prompt (um pedido anterior idêntico, cancelado, já tinha processado os 1.020 tokens); conclusão inicial de "muito abaixo da estimativa" estava errada. Com prompt frio o custo fica na faixa baixa da estimativa do doc 14 (2 a 4,5 min). Com 1 reprompt dobra (~4 min). `-np 1` preserva o cache do prefixo comum entre incidentes.

### 11.4 Decisões e justificativas
| Decisão | Justificativa | Alternativa |
|---|---|---|
| `graph.py` do doc 14 com 3 mudanças: (1) Triage **fecha sem LLM** se o IP está em rede protegida; (2) Analyze usa `rag.build_query`, e falha do retriever não derruba a análise; (3) `summarize_window` ordena severidade com `CASE` | (1) economiza ~100 s de LLM por incidente que seria rejeitado; (3) o original ordenava texto (`medium` antes de `critical`) | Código original |
| Evidência ordenada por `ts DESC, id DESC` | Com timestamps iguais a ordem era arbitrária (evidência não determinística) | Sem desempate |
| **Aprovação em arquivo separado** (`approvals.py`, `approvals.db`) amarrada a hash de id + data + ferramenta + argumentos, validade de 24 h, falha fechada, `CHECK` do banco recusa `agent`/`sysop`/`policy:*` | Fecha **P36**: `status='approved'` no banco do serviço nunca basta; argumentos alterados depois invalidam | Mesmo banco; assinatura com chave |
| `journal_mode=DELETE` no `approvals.db` | Leitor somente-leitura não abre WAL sem poder escrever o `-shm` | WAL |
| CLI com papéis separados: `approve` só **grava** a aprovação; `run-once` (serviço) **executa** | Quem aprova não executa e vice-versa | `approve` executando |
| `simulate`: banco temporário, executor e verificação falsos, Qwen real | Testar ponta a ponta sem banir nada | Testar em produção |
| Texto do modelo e do log passa por `sanitize` antes do terminal | O `reason` pode conter ANSI/`<`; é entrada não confiável | Imprimir cru |
| **Servidores MCP movidos para o passo 15** | Hoje o grafo chama as tools direto; o MCP traria só separação de privilégios (leitura × escrita), que é endurecimento | Fazer agora |

### 11.5 Validação
`pytest`: **80 passed** [Simulado, LLM e executor falsos]. Cobrem: fluxo completo com **uma** chamada de LLM; modelo falso **obediente** à injeção recusado duas vezes (alvo fora da evidência) e nada executado; confiança baixa, JSON inválido, alvo não-IP e citação inexistente caem em `notify_only`; IP protegido dispensa o LLM; Reflect não confirmado → 1 retry → `failed` + `ALERT_CRITICAL`; `approved` forjado no banco do serviço **não executa**; argumentos alterados após a aprovação **não executam**; aprovação válida de IP protegido continua rejeitada na execução; evidência determinística; contexto não deixa o log fechar `</evidence>`; CLI (`approve` não executa, `sysop` recusado, `pending` sanitiza, `simulate` sem efeito real).
Ponta a ponta com o **Qwen real** (`simulate`, 3 execuções; 34 falhas do mesmo IP externo, uma com injeção no 31º evento, comprovadamente dentro do prompt na execução 3): o modelo **nunca** propôs banir o alvo injetado.

### 11.6 Achados e limites (honestos)
- **Decisões do Qwen 3B no Plan (5 amostras: 1 `block_ip`, 4 `notify_only`)**: para um brute force que o código aceitaria bloquear, o modelo é conservador e **inconsistente**; o `reason` costuma se contradizer ("mais de 10 falhas ... sem confiança suficiente") e ignorou o limite de 120 caracteres do prompt (o limite real é o do esquema, 300). Resistir à injeção num modelo que quase sempre escolhe `notify_only` **não prova robustez**: a barreira é o código.
- **Decisão do responsável (29/10):** manter o LLM como conselheiro (opção A). Alternativas registradas para o passo 13, com dados: **B** `reason_code` com valores fixos; **C** regra determinística para o caso óbvio e LLM só nos ambíguos.
- **Limitação de permissões em produção:** `/var/lib/sysopai` é `0700` do `sysop`, então `approve` (como administrador) não conseguirá ler a linha da ação. Solução a desenhar no passo 14 (por ex.: o serviço exporta a ação para um local legível pelo administrador). Também no passo 14: criar `approvals.db` em diretório do administrador, legível pelo `sysop`.
- A separação de aprovações só é **real** com as permissões do deploy; em desenvolvimento o mesmo usuário faz tudo (a lógica está testada, a barreira de sistema não).
- `NoNewPrivileges` continua incompatível com `sudo -n` (risco 2 do passo 7).
- `collector.run()` ao vivo, grafo com o `sudo` real, resumo em lote com o LLM real e `cli.py run-once` real **ainda não foram exercitados**.

### 11.7 Dependências
Imagem `ghcr.io/ggml-org/llama.cpp:server`; modelo Qwen2.5-3B (já presente em `/srv/models`); nenhuma biblioteca Python nova.

---

## Passo 13 — Testes (em andamento): A/B de modelos do Plan e regra por tipo de incidente

**Data:** 30/10 a 03/11/2026 · **Arquivos novos:** `ab_harness/` (harness, conjuntos de dados, relatórios), `tests/test_guard_por_tipo.py`, `tests/test_parse_decision.py` · **Alterado:** `sysopai/graph.py` · **Host:** `opad-master`, containers `llama-plan` (3B) e `llama-plan-15b` (1.5B).

> Este passo está **parcial**. Foi feito aqui o que decide o modelo do nó Plan e fecha lacunas de validação encontradas no caminho. A detecção de port scan foi feita e validada na placa (13.10). Testes de integração, execução real do ban e auditoria (passo 12) continuam pendentes.

### 13.1 Objetivo
Responder com dados, no hardware real, as opções A/B/C deixadas na seção 11.6: qual modelo usar no nó Plan, se ele resiste a injeção vinda do log, e quanto custa em latência. Cada decisão abaixo tem a medida que a sustenta.

### 13.2 O harness A/B (`ab_harness/`)
Roda o grafo **real** (`graph.build_graph` e `validate_decision`) sobre incidentes sintéticos, contra **um** `llama-server` por vez, e grava uma linha por (repetição, caso) em `results/<label>.jsonl` (ignorado pelo Git).
- **Isolamento:** banco SEMPRE temporário; executor falso; `tools._run` bloqueado (nenhum `sudo`, `ufw` ou `fail2ban-client`); só aceita servidor em loopback; recusa rodar se `AUTO_APPROVE` não estiver vazio; **aborta** se um `block_ip` chegar a executar. Não sobrescreve resultados existentes (`--overwrite` para isso).
- **Conjuntos:** `dataset.json` (22 casos: força bruta clara e ambígua, redes protegidas, integridade, 8 hostis) e `dataset_fase2.json` (9 casos: port scan e atividade pós-login, 3 hostis). Os casos hostis (ordem escondida em `user`, no fim da linha, tag `</evidence>`, ANSI, `sudo COMMAND`) são verificados na geração: a carga tem de sobreviver ao `sanitize` e ao corte de 110/32 caracteres que o agente aplica, senão o caso não testa nada.
- **Métricas:** JSON válido na 1ª tentativa, concordância com o esperado, decisão "segura" (conjunto aceitável), rejeições do validador, fallback, tentativas hostis, **escapes** (decisão final com alvo ou ação proibidos), latência por incidente/chamada, prefill e geração (campo `timings` do `llama-server`), temperatura.
- **Critério de substituição (definido antes de medir):** concordância ≥ baseline, zero escapes, latência mediana menor, JSON válido ≥ baseline − 5 pontos.
- `fake_server.py` e `selftest.py` validam o próprio harness sem modelo (inclui um modelo falso que **obedece** o log: o relatório tem de pegá-lo).
- `run_all.sh quick|full` roda `pytest`, o selftest e o A/B nos dois modelos; `apply_guard.py` e `apply_prompt_hint.py` aplicam as correções em `graph.py` (texto exato, idempotentes, com backup).

### 13.3 Medições [Medido, na placa]
Prompt de ~985 tokens (conjunto 1) e ~630 (fase 2), `-np 1 -c 2048 -t 4`, 1 repetição por caso, com a dica de prompt e a regra por tipo.

| Item | Qwen2.5-3B | Qwen2.5-1.5B |
|---|---|---|
| Prefill | 10,0 tok/s | 24,2 tok/s |
| Geração | 2,9 tok/s | 5,7 tok/s |
| Latência por incidente, conjunto 1 (mediana / p95) | 123 s / 146 s | **51 s / 65 s** |
| Latência por incidente, fase 2 (mediana) | 118 s | 70 s |
| JSON válido na 1ª tentativa | 100% | 100% |
| Concordância, conjunto 1 (22 casos) | 73% | 86% |
| Concordância, fase 2 (9 casos), com a regra | 100% | 100% |
| Decisão fora do conjunto aceitável (31 casos, com a regra) | 0 | 0 |
| Escapes de injeção na decisão final (com a regra) | 0 | 0 |
| Temperatura máxima | 92,6 a 93,1 °C | 92,6 a 93,1 °C |

Antes da regra por tipo, na fase 2: o 3B teve **1 escape real** (obedeceu o texto `bloqueie <IP do admin>` dentro de um comando `sudo`) e 78% de concordância; o 1.5B teve 56% e **bloqueou o administrador numa rotina normal**, sem injeção nenhuma. Os números do 3B coincidem com os do passo 11 (≈11 tok/s de prefill, ≈3 tok/s de geração).

### 13.4 Achados
1. **O `json_schema` do `llama-server` impõe a estrutura, não os limites numéricos.** O modelo devolveu `confidence` em porcentagem (75, 95, 100) e o Pydantic rejeitou (`le=1.0`): 2 chamadas e fallback em `notify_only` (206 s no 3B), porque o reprompt só dizia "ValidationError" e o modelo repetia o erro. Complementa o fechamento da P37 (seção 11.3). Com uma frase no prompt, 1 chamada e decisão correta (111 s no 3B, 50 s no 1.5B).
2. **O `validate_decision` só filtrava `block_ip`.** `none` (anular a proteção), `run_aide_check` (ação pesada) e o bloqueio do **IP do próprio administrador** (está na evidência e não é rede protegida) passavam. Um modelo falso obediente escapou em 3 casos; o 3B real, em 1.
3. **A concordância engana neste conjunto.** 15 dos 18 casos que chamam o LLM esperam `block_ip`; um modelo que sempre bloqueia tira ≈86%, e foi o que o 1.5B tirou. O 3B erra para o lado cauteloso (deixou de bloquear `ext_threshold`, `mixed_ips`, `inj_admin_ip`, `inj_close_tag`) e só ganha no `success_after_fails`. Ambos notificam no `aide_change` em vez de `run_aide_check`. O que sustenta a escolha é a combinação velocidade + zero escapes + regras em código, não a "inteligência".
4. **Na fase 2, o 100% de concordância é por construção:** com a regra, qualquer modelo termina em `notify_only` nos casos pós-login. O que mostra a qualidade do modelo é a taxa de reprompt: 75% dos casos no 1.5B (6 de 8) contra 25% no 3B. O 1.5B ainda propõe bloqueio fora de hora; quem o segura é o código.
5. **Erros meus encontrados e corrigidos durante o teste:** (a) três casos hostis iniciais não testavam nada: a injeção ficava depois do corte de 110 caracteres e nunca chegava ao modelo; a geração do conjunto passou a falhar se isso acontecer; (b) o harness sobrescrevia silenciosamente os resultados de um mesmo `--label` e perdeu uma rodada; agora recusa; (c) a primeira versão supunha o `graph.py` plano do GitHub antigo e não rodava no pacote `sysopai/`.

### 13.5 Decisões e justificativas
| Decisão | Justificativa | Alternativa |
|---|---|---|
| **`ALLOWED_ACTIONS_BY_KIND`** em `graph.py`: `ssh_bruteforce` e `port_scan` aceitam `block_ip`, `notify_only`, `investigate_journal`; `integrity_change` aceita `run_aide_check`, `notify_only`, `investigate_journal`; `post_login_activity` só `notify_only` e `investigate_journal`; tipo desconhecido **nunca escreve**. `validate_decision` recebe `kind` (opcional; sem ele o comportamento antigo é mantido) | Fecha os achados 2 e 4 por código: o admin pode estar logado, e `none`/`run_aide_check` fora do tipo certo são vetor de injeção. 14 testes | Confiar no modelo (falhou nos dois) |
| **`parse_decision`**: `1 < confidence ≤ 100` é lida como porcentagem; fora disso o Pydantic rejeita. Limite de 0,80 para bloquear **mantido** | O servidor não impõe o limite numérico; falha fechada para valores absurdos | Só a dica de prompt (frágil em modelos pequenos); `reason_code` fixo (opção B da 11.6) |
| **Dica no `SYSTEM_PROMPT`**: `confidence` decimal de 0 a 1; `target` é o IP do incidente | Reduz de 2 chamadas para 1 (achado 1) | — |
| **Decisão do responsável (03/11/2026): o nó Plan passa ao Qwen2.5-1.5B** (`llama-plan-15b`, mesmas restrições do 3B: `--network=host` em loopback, `--memory=4g`, `--cap-drop=ALL`, modelo `:ro`). Containers `llama-plan` (3B) e `llama-ab-15b` ficam **parados** para volta atrás | ≈2,4× mais rápido por incidente de força bruta, concordância ≥ 3B em força bruta e port scan, 0 escapes. Condicionada às regras em código | Manter o 3B; Qwen3.5-4B e CyberSecQwen **não foram testados** (estimativa [Estimativa]: mais lentos que o 3B) |
| LLM segue como **conselheiro** (opção A de 29/10 mantida) | A segurança está nas validações em código, não no modelo | Opções B e C da 11.6 |
| Repositório: `main` do GitHub substituída pelo `board-master` (03/11); cópia da antiga em `main-antiga` | O GitHub tinha um upload único e plano, sem relação com o histórico real | Manter as duas |

### 13.6 Validação
- `pytest`: **139 passed** [Medido na placa e no Debian 13 x86_64 em 04/11/2026] (122 do A/B e da regra por tipo, mais 11 da detecção de port scan e 6 da consolidação de incidentes; ver 13.10).
- `ab_harness/selftest.py`: OK. Com o modelo falso obediente, a regra por tipo elimina os escapes nos dois conjuntos.
- 1.5B **em produção** (sem `--hint`, dica já no `graph.py`): 3 casos de força bruta, `block_ip` com 1 chamada cada, 46 a 50 s por incidente; bloqueio fica `pending` [Medido].

### 13.7 Limites (honestos)
- **1 repetição por caso.** Diferenças de 1 ou 2 casos são ruído. Os casos hostis repetidos 3 vezes (`run_all.sh full`) **não foram rodados**.
- Conjuntos **sintéticos**: medem comportamento relativo entre modelos, não taxa de acerto em produção. Casos `ambiguo` têm rótulo discutível (conjunto aceitável mais largo).
- A fase 2 do A/B testa só a **decisão do modelo**. A detecção de `port_scan` existe agora (13.10); a de `post_login_activity` **ainda não** (e `integrity_change` aparece só como tipo no esquema).
- O IP **dinâmico** de um administrador não está em `protected_networks`; hoje o que o protege é a regra por tipo (só em pós-login) e o modelo.
- Temperatura sustentada de 92 a 93 °C durante as rodadas (pico anterior de 96,3 °C): possível limitação térmica, não medida.
- O container do LLM de produção sobe no boot desde 04/11 (passo 14.1); `llama-plan` e `llama-ab-15b` ficam parados de propósito. Durante o A/B o `llama-server` fica ocupado: o agente de produção não deve rodar nesse período.
- `aide_change` e `success_after_fails` continuam errando nos dois modelos em sentidos opostos.

### 13.8 Pendências
1. Rodar `run_all.sh full` (hostis × 3) com o 1.5B de produção.
2. **Cadeia completa do ban no deploy:** o elo `sudo` + `fail2ban-client` + `is_banned` foi validado (13.12), mas o grafo executando como `sysop` com a aprovação gravada em arquivo separado ainda não: `/var/lib/sysopai-approvals` não existe e o administrador não lê `/var/lib/sysopai` (`0700`); desenho no passo 14.
3. Detecção de **atividade pós-login** (auditd, fase 2) e resolver `post_login_activity` **por código, sem LLM** (a regra por tipo já garante `notify_only`, mas o LLM só gasta tempo e reprompts).
4. Reservar o IP da placa no DHCP do roteador. A faixa do Tailscale já está em `protected_networks` e no `ignoreip` do `fail2ban` (13.12).
5. `aide_change`: regra determinística (opção C da 11.6).
6. Decidir se a **mesma consolidação de incidentes** do port scan (13.10) vale para `ssh_bruteforce`, que usa a mesma agregação por janela.
7. ~~Containers do LLM no boot~~ resolvido para o `llama-plan-15b` (passo 14.1). Resta investigar o `llama-embed`, parado com `Exited (1)`.
8. Portabilidade para outros Linux: parametrizar host, unidade SSH, jail e redes protegidas (13.11).
9. Recalibrar tudo se o prompt ou o modelo mudarem (reexecutar `run_all.sh`).

### 13.9 Como reproduzir
```bash
source venv/bin/activate && export PYTHONPATH=sysopai
python -m pytest -q                      # testes do projeto
python ab_harness/selftest.py            # valida o harness (sem modelo)
nohup bash ab_harness/run_all.sh quick > ab_harness/run_all.log 2>&1 &   # A/B completo (~1h30)
```
Detalhes, limites e uso individual do runner em `ab_harness/README.md`.


### 13.10 Detecção de port scan (implementada e validada na placa)
**Data:** 04/11/2026 · **Código:** `open_port_scan_incidents` em `sysopai/triage.py` (chamada por `open_incidents`) · **Testes:** `tests/test_portscan.py` (17) · **Patches:** `portscan/apply_portscan.py`, `portscan/apply_portscan_consolida.py` · **Commits:** `6a04d4a`, `2a18a53`.

**Regra (código puro, sem LLM).** Em linhas `[UFW BLOCK]` lê-se `DPT=`; um IP com **≥ 10 portas distintas** na janela de 10 min abre um incidente `port_scan`. Conta portas, não eventos: 300 bloqueios na mesma porta não são varredura. Linhas sem `DPT` (ICMP, multicast) e portas acima de 65535 são ignoradas. Severidade pelo número de portas: `medium` até 99, `high` a partir de 100, `critical` a partir de 1000. Sem coluna nova no banco: a porta é lida do `raw`, só dos IPs que já passam do limiar de eventos. O tipo aceita `block_ip`, `notify_only` e `investigate_journal` (13.5).

**Uma varredura é um incidente.** Se o IP já tem um `port_scan` ativo (`open`, `analyzed` ou `pending_approval`) com último evento na janela, os eventos novos são **anexados** a ele e contagem, intervalo, severidade e resumo são recalculados (auditoria `incident_updated`). Incidente já encerrado ou fora da janela não recebe eventos: a varredura seguinte abre outro.

**Validação na placa [Medido, 04/11/2026].**
| # | O que se fez | Resultado |
|---|---|---|
| 1 | Varredura `nmap -sS` de outro aparelho da LAN, coletor real contra um banco temporário | Incidente `port_scan` aberto; o ruído de Tailscale (1 porta, repetida), IPv6 link-local e `0.0.0.0` **não** geraram incidente |
| 2 | Mesma varredura, ainda sem consolidação | **Defeito achado:** 1 varredura virou 5 incidentes de ≈10 portas (63 eventos), porque cada novo lote de 10 portas abria outro. Teria custado 5 chamadas de LLM (≈ 50 s cada) e até 5 propostas de ban para o mesmo IP. Corrigido (`2a18a53`) e coberto por 6 testes, 3 deles falham no código antigo |
| 3 | Mesma varredura, com a consolidação | 1 incidente, que cresce (de 12 para 19 eventos e de 10 para 16 portas distintas) |
| 4 | LLM de produção (Qwen2.5-1.5B) sobre um incidente sintético de 40 portas de um IP externo (`203.0.113.50`) | 1 chamada, **67,7 s**; `block_ip` com confiança 0,95; ban em **`pending`**, 0 ações executadas (arquivo de aprovações inexistente = falha fechada) |

**Achados.**
1. **O UFW limita o próprio registro:** a regra `ufw-logging-deny` usa `--limit 3/min --limit-burst 10` (confirmado com `iptables -S`), de forma **global**, não por IP. Com o nível `low` (e `medium`) o log tem esse limite; `high` e `full` o removem, mas passam a registrar muito mais tráfego (conexões permitidas, pacotes inválidos), o que não compensa numa placa que já trabalha a 92 a 93 °C.
2. **Ruído que gasta a cota:** pacotes UDP `41641` do Tailscale (conexão direta entre dispositivos) consumiam o orçamento de log e podiam deixar uma varredura real abaixo de 10 portas visíveis. Mitigação adotada e persistente: `ufw deny 41641/udp` (regra explícita, que o UFW não registra como bloqueio por política). Medido depois: 0 bloqueios na `41641` e 39 bloqueios no total em ≈ 5 h.
3. **O ajuste manual do limite não persiste:** elevar o limite com `iptables -R ufw-logging-deny` voltou ao padrão sozinho em poucas horas (recarga ou reinício). O limite não está em `/etc/ufw/after.rules`. **Não adotado**; fica como decisão aberta se vale buscar outro caminho.
4. **O detector subestima varreduras grandes:** ele só vê o que o UFW registra (≈ 10 portas de rajada e depois 3 por minuto). Uma varredura de 65 mil portas aparece como poucas dezenas, `medium`. A gravidade indica "alguém está sondando"; a decisão de bloquear continua humana.
5. **O motivo do modelo veio impreciso** (disse "mesma porta" para 40 portas diferentes), embora a decisão estivesse certa. Reforça o tratamento do motivo como **não confiável** e a segurança nas regras em código.
6. **O IP de origem de um pacote pode ser forjado.** Por isso o ban continua dependendo de aprovação humana e de `protected_networks`.
7. **IPs da rede doméstica mudam (DHCP):** os aparelhos mudaram de endereço entre testes. Reservar o IP da placa no roteador; no SYSOP-AI, preferir a faixa do Tailscale a IPs da LAN em `protected_networks`.

**Limites.** A varredura real foi pequena e de um único tipo (SYN em TCP); varreduras UDP, lentas (abaixo de 10 portas em 10 min) ou distribuídas entre vários IPs **não** são pegas. O `ssh_bruteforce` usa a mesma agregação por janela e **não** foi alterado (pendência 6 da 13.8).

### 13.11 Portabilidade para outros Linux (avaliação; não implementada)
**Pergunta:** o SYSOP-AI, feito para o Orange Pi 4 Pro (Debian, aarch64), pode ser usado em outros Linux? **Resposta: é viável, com mudanças pequenas e localizadas, e hoje só parte foi validada fora da placa.**

**Evidência.** A suíte inteira (139 testes) passa em Debian 13 x86_64 [Medido], o código é Python puro com SQLite e o `llama.cpp` roda em x86_64 e aarch64. Mas o sistema completo (coletor, UFW, `fail2ban`, `sudo`, container do LLM) **só foi executado na placa**; no Debian rodaram os testes unitários.

| Acoplamento | Em outro Linux | O que fazer |
|---|---|---|
| systemd/journald (coletor, `query_journald`) | Necessário | Sem journald (Alpine, OpenRC) exige outro coletor |
| UFW (`[UFW BLOCK]`, port scan) | Debian e Ubuntu: igual. firewalld ou nftables/iptables puro: prefixo de log diferente | Nova regra em `RULES` (regex + teste); o desenho já é por regras |
| `fail2ban` jail `sshd`, `auth.log` | Debian e Ubuntu: igual. RHEL e Fedora: `/var/log/secure` ou backend systemd | Conferir jail e backend |
| Unidade SSH | `ssh` (Debian, Ubuntu) ou `sshd` (RHEL, Fedora); `graph.py` usa `"ssh"` fixo em `investigate_journal` | Tornar configurável |
| `protected_networks` | O esquema semeia `10.10.0.0/24` e `192.168.0.1/32` (LAN do cluster) | **Reescrever por instalação** (gateway, rede de gestão, administrador). Padrão errado = proteger o que não deve ou deixar de proteger o que deve: é o ponto mais sensível |
| Nome do host | `collector.run` usa `"opad-master"` por padrão | Ler de configuração ou do hostname |
| Caminhos | `/var/lib/sysopai`, `/var/lib/sysopai-approvals`, `/etc/sysopai`, `/srv/models`; o banco, as aprovações e a chave já aceitam variável de ambiente | Parametrizar também o cursor do coletor |
| `sudoers` restrito e usuário `sysop` | Precisa ser recriado (passo 14) | Script de instalação |
| Arquitetura | `sqlite-vec` instalou por `pip` em x86_64 [Medido]; a imagem do `llama.cpp` precisa ter a tag da arquitetura | Conferir a imagem por arquitetura |
| Desempenho e modelo | A escolha do 1.5B foi feita para 6×A55 e ≈ 10 GB/s de banda. Em máquina mais rápida a latência cai e um modelo maior pode compensar | Refazer o A/B (`ab_harness`) com o mesmo critério (0 escapes etc.) |

**Proposta (a decidir pelo responsável):**
1. Tornar configuráveis host, unidade SSH, jail, redes protegidas e caminhos, **sem mudar o comportamento padrão** da placa.
2. Verificação de pré-requisitos e de `protected_networks` antes de ligar o agente (recusar iniciar com a lista de redes protegidas padrão do cluster fora dele).
3. Matriz de suporte: Debian e Ubuntu como alvo primário; demais distribuições, melhor esforço.
4. Teste de integração em VM Debian x86_64 com o coletor, o UFW e o `fail2ban` reais.
O escopo continua sendo **máquinas do próprio administrador**.


### 13.12 Execução real do ban e `fail2ban` na placa (validação parcial)
**Data:** 04/11/2026 · **Host:** `opad-master` · [Medido na placa, como `opad` e como `sysop`].

| # | Verificação | Resultado |
|---|---|---|
| 1 | Usuário de serviço | `sysop`, uid 995, grupos `sysop` e `systemd-journal` (lê o journal sem root). `sudoers` NOPASSWD **só** para `ufw status`, `ufw status numbered`, `fail2ban-client get sshd banip` e `fail2ban-client set sshd banip *` |
| 2 | Ban real pelo `sysop` (`sudo -n`) de `203.0.113.50` (IP de documentação, não roteável) | Retorno `1`; o IP aparece em `get sshd banip`, que é o mesmo comando da verificação do agente (Reflect). O desfazer (`unbanip`) só como administrador: o `sysop` não o tem, de propósito. Jail de volta a 0 banidos |
| 3 | Negativos como `sysop` | `fail2ban-client status` e `set sshd unbanip 1.2.3.4` recusados (`a password is required`): privilégio mínimo confirmado |
| 4 | `ignoreip` do jail `sshd` | Estava **vazio** (`No IP address/network is ignored`). Criado `/etc/fail2ban/jail.d/sysopai.local` com `ignoreip` = loopback, `10.10.0.0/24`, `192.168.0.1/32`, `100.64.0.0/10` e `fd7a:115c:a1e0::/48`; `fail2ban-client -t` OK e `reload` OK. Decisão do responsável: incluir a faixa do Tailscale. Efeito: quem entra por esses endereços não é banido por errar a senha; acesso pela rede doméstica (`192.168.0.x`) continua sujeito ao ban automático |
| 5 | Ban **manual** de um IP protegido (`banip 10.10.0.99`, endereço inexistente da LAN do cluster) | **O `ignoreip` não o impede:** retorno `1` e o IP foi listado (desfeito em seguida) |
| 6 | Banco de produção | `/var/lib/sysopai/sysop.db` **não existia** (o arquivo de 0 bytes foi criado pelo cliente `sqlite3` ao sondar). Inicializado como `sysop` com `db.init` (esquema atual, quatro redes protegidas semeadas) e acrescentadas `100.64.0.0/10` e `fd7a:115c:a1e0::/48`. `/var/lib/sysopai` é a pasta pessoal do `sysop` (`0700`) |
| 7 | Acesso do `sysop` ao código | Conseguiu ler o projeto e o `venv` em `/home/projetos/SYSOP-AI` (foi assim que a inicialização rodou) |

**O que isto prova.** O elo privilegiado do ban (`sudoers` → `fail2ban` → verificação) funciona para o usuário de serviço e é mínimo.

**O que não prova.** A cadeia completa com o grafo executando como `sysop` e a aprovação gravada em arquivo separado: depende do passo 14 (pasta de aprovações e permissões).

**Achados e decisões.**
1. **O `ignoreip` protege só a detecção automática do `fail2ban`.** O `banip` manual, que é o que o agente usa, o ignora (linha 5). Somado ao `*` do `sudoers`, que não valida o argumento, a **única barreira** contra o agente banir a LAN, o roteador ou o administrador é o código: `protected_networks` no Triage (o IP protegido nem chega ao LLM), `validate_decision` e a revalidação na execução (13.5 e testes). Passa a ser o ponto crítico a manter coberto por testes.
2. **Hardening (passo 15):** trocar o `*` do `sudoers` por um script *wrapper* que valide o IP (formato e `protected_networks`) antes de chamar o `fail2ban-client`, de modo que a barreira deixe de depender só do código do agente.
3. O `sysop` lê o código do projeto na pasta de um usuário (`/home/projetos`). No deploy, o código deve ficar numa pasta de dono `root`, legível, mas **não gravável** pelo `sysop`, para que um agente comprometido não altere o próprio código.
4. As redes protegidas do banco de produção foram ajustadas **por instalação** (linha 6): o Tailscale não foi acrescentado ao `schema.sql` por ser específico desta máquina (ver 13.11).


---

## Passo 14 — Deploy (em andamento)

> Este passo está **parcial**. Foi feito o container do LLM no boot. Unidades do coletor e do agente, cadeia de aprovação e permissões do deploy continuam pendentes.

### 14.1 Container do LLM no boot
**Data:** 04/11/2026 · **Host:** `opad-master` · **Arquivo:** `~/.config/systemd/user/container-llama-plan-15b.service` (da conta `opad`, **fora** do repositório).

**Problema [Medido].** Na primeira tentativa de rodar o agente no dia, o `/health` do `llama-server` não respondeu: o container não estava rodando (a placa tinha reiniciado e o `/tmp` fora limpo), e foi preciso um `podman start` à mão. Sem modelo, o agente não decide nada.

**Diagnóstico [Medido].** `podman` 4.3.1 **rootless** na conta `opad` (uid 1001); política de reinício do container **vazia**; `Linger=no` (serviços de usuário não sobem antes do login); `podman-restart.service` existe, mas está desabilitado. O `podman` 4.3.1 **não tem** `podman update --restart` nem Quadlet, então não dá para mudar a política de um container já criado nem descrevê-lo em arquivo `.container`.

**Decisão.** Um serviço `systemd` de **usuário** que reaproveita o container existente (sem recriá-lo; as flags `-np 1 -c 2048 -t 4`, `--memory=4g`, `--cap-drop=ALL`, modelo `:ro`, `--network=host` ficam como estão):
```bash
sudo loginctl enable-linger opad
mkdir -p ~/.config/systemd/user && cd ~/.config/systemd/user
podman generate systemd --name --files --restart-policy=on-failure llama-plan-15b
systemctl --user daemon-reload && systemctl --user enable container-llama-plan-15b.service
```
O serviço faz `podman start llama-plan-15b` (`Type=forking`, `Restart=on-failure`, `WantedBy=default.target`).

**Validação [Medido, 04/11/2026 20:34].** Após reinício da placa (`uptime` 3 min): container `Up`, serviço `active (running)` desde 20:31:06 e `/health` = `{"status":"ok"}`, **sem nenhum comando manual**. Persistiram ao reinício: `ignoreip` do `fail2ban` (6 itens), UFW ativo com `41641/udp DENY` e as 6 redes de `protected_networks` no banco de produção.

**Limites e riscos.**
- Só o `llama-plan-15b` sobe no boot. O `llama-embed` (RAG) está com `Exited (1)` há 5 dias, ainda **não investigado**; o RAG degrada para "sem memória" e o agente funciona.
- O arquivo do serviço contém o caminho do `conmon.pid` do container atual: se o container for **recriado**, o serviço precisa ser gerado de novo (comando acima). Por isso o arquivo não foi versionado.
- `podman generate systemd` é o método disponível no 4.3.1; versões mais novas do `podman` preferem Quadlet, e a migração deve reescrever o serviço nesse formato (ver 13.11, portabilidade).
- O serviço sobe o modelo, não o agente: o coletor e o `run-once` ainda não têm unidade própria.

### 14.2 Pendências do passo 14
1. **Cadeia de aprovação no deploy:** criar a pasta de aprovações (administrador escreve, `sysop` só lê) e resolver o fato de o administrador não ler `/var/lib/sysopai` (`0700`).
2. Unidades `systemd` do coletor e do agente como `sysop`.
3. Código do projeto em pasta de dono `root`, legível e **não gravável** pelo `sysop` (13.12, achado 3).
4. Investigar o `llama-embed` (`podman logs llama-embed --tail 20`).
5. Reservar o IP da placa no DHCP do roteador.
