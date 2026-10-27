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
| 9 | Vetorização | **Concluído (aguardando confirmação; checksum do modelo pendente)** |
| 10 | Busca semântica | Pendente |
| 11 | Integração com LLM | Pendente |
| 12 | Logs e auditoria | Pendente |
| 13 | Testes | Pendente |
| 14 | Deploy | Pendente |
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
- **Checksum do modelo não verificado.** Comparar `sha256sum` do arquivo com o `lfs.oid` publicado pela API do Hugging Face (prova integridade do download, não que o publicador seja confiável).
- A consulta real do grafo é `"{kind} {severity}"` (ex.: `ssh_bruteforce medium`), **não** uma pergunta em linguagem natural como as do teste: a qualidade real dessa consulta ainda não foi medida (passo 10).
- Embeddings concorrentes com o LLM do nó Plan disputam a banda de memória (P25/P30).
- Reindexação obrigatória se o modelo ou a quantização mudarem.

