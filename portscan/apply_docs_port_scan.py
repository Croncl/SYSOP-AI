#!/usr/bin/env python3
"""Atualiza docs/IMPLANTACAO.md e README.md: detecção de port scan feita e validada na placa (13.10) e
avaliação de portabilidade para outros Linux (13.11). Só texto.

  * seguro: cada trecho é procurado por texto exato; se algum não bater, NADA é alterado;
  * idempotente: se já aplicado, não faz nada;
  * guarda cópias em *.bak-docs-portscan.

    python portscan/apply_docs_port_scan.py        # na raiz do projeto (ou com o script em uma subpasta)
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = "### 13.10 Detecção de port scan"

IMPL_EDITS = [
 # (descrição, antigo, novo)
 ("índice, linha 13",
  "| 13 | Testes | **Em andamento** (A/B de modelos do Plan e regra por tipo de incidente concluídos; integração e demais testes pendentes) |",
  "| 13 | Testes | **Em andamento** (A/B de modelos do Plan, regra por tipo de incidente e detecção de port scan concluídos; execução real do ban, integração e demais testes pendentes) |"),
 ("cabeçalho do passo 13",
  "Testes de integração, detecção de port scan e auditoria (passo 12) continuam pendentes.",
  "A detecção de port scan foi feita e validada na placa (13.10). Testes de integração, execução real do ban e auditoria (passo 12) continuam pendentes."),
 ("13.6, contagem de testes",
  "- `pytest`: **122 passed** [Medido na placa] (107 após a regra por tipo; +15 de `parse_decision`, dica e grafo de ponta a ponta com `confidence: 95`).",
  "- `pytest`: **139 passed** [Medido na placa e no Debian 13 x86_64 em 04/11/2026] (122 do A/B e da regra por tipo, mais 11 da detecção de port scan e 6 da consolidação de incidentes; ver 13.10)."),
 ("13.7, limite da fase 2",
  "- A fase 2 testa só a **decisão do modelo**: a detecção que cria incidentes `port_scan` e `post_login_activity` **ainda não existe** (a agregação atual do `triage.py` é de força bruta no SSH; `port_scan` e `integrity_change` aparecem só como tipos no esquema).",
  "- A fase 2 do A/B testa só a **decisão do modelo**. A detecção de `port_scan` existe agora (13.10); a de `post_login_activity` **ainda não** (e `integrity_change` aparece só como tipo no esquema)."),
 ("13.8, pendências",
  """### 13.8 Pendências
1. Rodar `run_all.sh full` (hostis × 3) com o 1.5B de produção.
2. **Detecção de port scan** (`DPT=` no UFW, ≥ N portas distintas por IP em 10 min, via SQL) com testes em `tests/`; depois, de atividade pós-login (auditd, fase 2).
3. Resolver `post_login_activity` **por código, sem LLM** (a regra por tipo já garante `notify_only`, mas o LLM só gasta tempo e reprompts).
4. Registrar o IP do administrador em `protected_networks` quando for fixo.
5. `aide_change`: regra determinística (opção C da 11.6).
6. Recalibrar tudo se o prompt ou o modelo mudarem (reexecutar `run_all.sh`).
""",
  """### 13.8 Pendências
1. Rodar `run_all.sh full` (hostis × 3) com o 1.5B de produção.
2. **Validar na placa a execução real do ban** (`sudo` + `fail2ban-client` + `is_banned`), usando um IP de documentação (ex.: `203.0.113.50`), com o arquivo de aprovações no deploy real. Ainda não foi exercitada.
3. Detecção de **atividade pós-login** (auditd, fase 2) e resolver `post_login_activity` **por código, sem LLM** (a regra por tipo já garante `notify_only`, mas o LLM só gasta tempo e reprompts).
4. Proteger o administrador em `protected_networks`: a faixa do Tailscale (os endereços `100.x` são fixos por dispositivo) em vez do IP da rede doméstica, que é DHCP. Reservar o IP da placa no roteador.
5. `aide_change`: regra determinística (opção C da 11.6).
6. Decidir se a **mesma consolidação de incidentes** do port scan (13.10) vale para `ssh_bruteforce`, que usa a mesma agregação por janela.
7. Containers do LLM **no boot**: em 04/11 a placa aparentemente reiniciou (o `/tmp` foi limpo) e o `llama-plan-15b` não estava rodando, com o `/health` sem resposta; foi preciso `podman start` à mão (passo 14).
8. Portabilidade para outros Linux: parametrizar host, unidade SSH, jail e redes protegidas (13.11).
9. Recalibrar tudo se o prompt ou o modelo mudarem (reexecutar `run_all.sh`).
"""),
]

IMPL_APPEND = """

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
"""

README_EDITS = [
 ("estado: contagem de testes",
  "**122 testes** passando.",
  "**139 testes** passando."),
 ("estado: faltam",
  "Faltam: detecção de port scan e de atividade pós-login, auditd, dashboard, alertas, containers no boot e hardening de produção.",
  "Detectores prontos: força bruta no SSH e **port scan** (validado na placa em 04/11/2026; ver o passo 13.10). Faltam: detecção de atividade pós-login, validação na placa da execução real do ban, auditd, dashboard, alertas, containers no boot e hardening de produção."),
 ("limites: UFW",
  "- Testes de A/B são sintéticos, com 1 repetição por caso nos números atuais.",
  "- Testes de A/B são sintéticos, com 1 repetição por caso nos números atuais.\n"
  "- O port scan só é visto na medida em que o UFW registra: o log dele tem limite global (3/min, rajada de 10), então varreduras grandes são subestimadas. O ruído conhecido (ex.: Tailscale, UDP 41641) deve ser descartado sem log (`ufw deny`)."),
 ("compatibilidade",
  "## Limites conhecidos",
  """## Compatibilidade
Feito e validado no **Orange Pi 4 Pro** (Debian, aarch64). **Outros Linux são viáveis**, com ajustes pequenos; os testes unitários já passam em Debian 13 x86_64, mas o sistema completo só foi executado na placa. Alvo primário: Debian e Ubuntu (systemd/journald, UFW, `fail2ban`). Em outras distribuições, a unidade SSH, a origem de log do firewall e o `fail2ban` mudam. O ponto mais sensível é `protected_networks`, que vem com a LAN do cluster e **precisa ser reescrita em cada instalação**. Avaliação completa e proposta no passo 13.11 do [`docs/IMPLANTACAO.md`](docs/IMPLANTACAO.md).

## Limites conhecidos"""),
]


def apply(path: Path, edits, append: str = "") -> int:
    src = path.read_text()
    for name, old, _ in edits:
        if src.count(old) != 1:
            print(f"ERRO em {path.name}: trecho '{name}' não bate exatamente (achei {src.count(old)}x). Nada foi alterado.")
            return 1
    new = src
    for _, old, repl in edits:
        new = new.replace(old, repl)
    new = new.rstrip("\n") + "\n" + append if append else new
    shutil.copy2(path, str(path) + ".bak-docs-portscan")
    path.write_text(new)
    print(f"ok: {path} atualizado (backup .bak-docs-portscan)")
    return 0


def main() -> int:
    impl, readme = ROOT / "docs" / "IMPLANTACAO.md", ROOT / "README.md"
    if MARK in impl.read_text():
        print("já aplicado, nada a fazer")
        return 0
    # valida os dois antes de escrever qualquer um
    for path, edits in ((impl, IMPL_EDITS), (readme, README_EDITS)):
        s = path.read_text()
        for name, old, _ in edits:
            if s.count(old) != 1:
                print(f"ERRO em {path.name}: trecho '{name}' não bate exatamente (achei {s.count(old)}x). Nada foi alterado.")
                return 1
    if apply(impl, IMPL_EDITS, IMPL_APPEND) or apply(readme, README_EDITS):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
