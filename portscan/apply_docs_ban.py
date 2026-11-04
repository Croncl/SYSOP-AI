#!/usr/bin/env python3
"""Atualiza docs/IMPLANTACAO.md e README.md com a validação, na placa, do trecho privilegiado do ban
(sudoers + fail2ban), do `ignoreip` e do banco de produção (13.12). Só texto.
Requer o patch anterior (apply_docs_port_scan.py) já aplicado.

  * seguro: cada trecho é procurado por texto exato; se algum não bater, NADA é alterado;
  * idempotente; guarda cópias em *.bak-docs-ban.

    python portscan/apply_docs_ban.py        # na raiz do projeto (ou com o script em uma subpasta)
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = "### 13.12 Execução real do ban"

IMPL_EDITS = [
 ("índice, linha 13",
  "execução real do ban, integração e demais testes pendentes) |",
  "trecho `sudo` + `fail2ban` do ban validado na placa; cadeia completa de aprovação no deploy, integração e demais testes pendentes) |"),
 ("13.8, item 2",
  "2. **Validar na placa a execução real do ban** (`sudo` + `fail2ban-client` + `is_banned`), usando um IP de documentação (ex.: `203.0.113.50`), com o arquivo de aprovações no deploy real. Ainda não foi exercitada.",
  "2. **Cadeia completa do ban no deploy:** o elo `sudo` + `fail2ban-client` + `is_banned` foi validado (13.12), mas o grafo executando como `sysop` com a aprovação gravada em arquivo separado ainda não: `/var/lib/sysopai-approvals` não existe e o administrador não lê `/var/lib/sysopai` (`0700`); desenho no passo 14."),
 ("13.8, item 4",
  "4. Proteger o administrador em `protected_networks`: a faixa do Tailscale (os endereços `100.x` são fixos por dispositivo) em vez do IP da rede doméstica, que é DHCP. Reservar o IP da placa no roteador.",
  "4. Reservar o IP da placa no DHCP do roteador. A faixa do Tailscale já está em `protected_networks` e no `ignoreip` do `fail2ban` (13.12)."),
]

IMPL_APPEND = """

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
"""

README_EDITS = [
 ("faltam",
  "validação na placa da execução real do ban, auditd,",
  "cadeia completa de aprovação do ban no deploy (o trecho `sudo` + `fail2ban` já foi validado na placa), auditd,"),
]


def check(path: Path, edits) -> bool:
    s = path.read_text()
    for name, old, _ in edits:
        if s.count(old) != 1:
            print(f"ERRO em {path.name}: trecho '{name}' não bate exatamente (achei {s.count(old)}x). Nada foi alterado.")
            return False
    return True


def write(path: Path, edits, append: str = "") -> None:
    s = path.read_text()
    for _, old, new in edits:
        s = s.replace(old, new)
    if append:
        s = s.rstrip("\n") + "\n" + append
    shutil.copy2(path, str(path) + ".bak-docs-ban")
    path.write_text(s)
    print(f"ok: {path} atualizado (backup .bak-docs-ban)")


def main() -> int:
    impl, readme = ROOT / "docs" / "IMPLANTACAO.md", ROOT / "README.md"
    if MARK in impl.read_text():
        print("já aplicado, nada a fazer")
        return 0
    if "### 13.11 Portabilidade" not in impl.read_text():
        print("ERRO: aplique antes apply_docs_port_scan.py. Nada foi alterado.")
        return 1
    if not (check(impl, IMPL_EDITS) and check(readme, README_EDITS)):
        return 1
    write(impl, IMPL_EDITS, IMPL_APPEND)
    write(readme, README_EDITS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
