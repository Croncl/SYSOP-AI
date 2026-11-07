#!/usr/bin/env python3
"""Atualiza docs/IMPLANTACAO.md e README.md: cadeia de aprovação do ban validada na placa (seção 14.3). Só texto.
Requer os patches de documentação anteriores (até 13.13) já aplicados.

  * seguro: texto exato, senão NADA é alterado; idempotente; cópias em *.bak-docs-aprov.

    python portscan/apply_docs_aprovacao.py        # na raiz do projeto (ou com o script em uma subpasta)
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = "### 14.3 Cadeia de aprovação no deploy"

IMPL_EDITS = [
 ("índice, linha 14",
  "| 14 | Deploy | **Em andamento** (container do LLM no boot concluído; unidades do coletor e do agente, cadeia de aprovação e permissões do deploy pendentes) |",
  "| 14 | Deploy | **Em andamento** (container do LLM no boot e cadeia de aprovação do ban concluídos; unidades do coletor e do agente e demais permissões do deploy pendentes) |"),
 ("13.6, pytest",
  "- `pytest`: **139 passed** [Medido na placa e no Debian 13 x86_64 em 04/11/2026] (",
  "- `pytest`: **170 passed** [Medido na placa em 07/11/2026: os 139 abaixo mais 31 de `test_cli_via_sysop.py`, ver 14.3; os 139 foram medidos na placa e no Debian 13 x86_64 em 04/11/2026] ("),
 ("13.8, item 2",
  "2. **Cadeia completa do ban no deploy:** o elo `sudo` + `fail2ban-client` + `is_banned` foi validado (13.12), mas o grafo executando como `sysop` com a aprovação gravada em arquivo separado ainda não: `/var/lib/sysopai-approvals` não existe e o administrador não lê `/var/lib/sysopai` (`0700`); desenho no passo 14.",
  "2. ~~Cadeia completa do ban no deploy~~ validada de ponta a ponta na placa em 07/11/2026 (passo 14.3): administrador aprova, `sysop` executa e verifica."),
 ("14.2, item 1",
  "1. **Cadeia de aprovação no deploy:** criar a pasta de aprovações (administrador escreve, `sysop` só lê) e resolver o fato de o administrador não ler `/var/lib/sysopai` (`0700`).",
  "1. ~~Cadeia de aprovação no deploy~~ resolvida e validada (14.3)."),
]

IMPL_APPEND = """

### 14.3 Cadeia de aprovação no deploy (validada de ponta a ponta)
**Data:** 06 e 07/11/2026 · **Host:** `opad-master` · [Medido na placa]. Alterados: `sysopai/cli.py`, novo `tests/test_cli_via_sysop.py`.

**Causa do `approvals.db` não ser criado [Medido].** O `venv/bin/activate` da placa exportava `SYSOP_DB`, `SYSOP_APPROVALS_DB` e `SYSOP_PSEUDONYM_KEY` apontando para `/home/projetos/SYSOP-AI/data/` (linhas 70 a 73, uma duplicada, acrescentadas no desenvolvimento). Toda sessão com o `venv` carregado gravava o banco de aprovações no `data/` do projeto em vez de `/var/lib/sysopai-approvals`; um `approve` do administrador teria gravado no banco **errado**. Correção local (o `venv` não é versionado): as quatro linhas foram comentadas, com backup `activate.bak-sysop`. Lição: `exec bash -l` **herda** as variáveis exportadas; para testar ambiente limpo, `env -i`. Com o ambiente vazio, o código já usa por padrão os caminhos de produção, `/var/lib/sysopai/sysop.db` e `/var/lib/sysopai-approvals/approvals.db`, então não foi preciso um arquivo de ambiente para os bancos. O `data/` está no `.gitignore` (a `pseudonym.key` não é versionada).

**Permissões [Medido, 06/11/2026].** Pasta `/var/lib/sysopai-approvals` (dono `opad`, grupo `sysop`, `2750`) e `approvals.db` (`opad:sysop`, `0640`). Como `sysop`: **lê** (abre em `mode=ro`), **não escreve** (`attempt to write a readonly database`) e **não apaga** (`Permission denied`). Um agente comprometido não consegue se auto-aprovar.

**O problema de leitura e a solução.** A ação pendente fica no banco do `sysop` (pasta pessoal `0700`), que o administrador não lê; `pending` e `approve` não funcionariam como `opad`. Mudanças no `cli.py`:
- novo subcomando `show-action ID`: a ação em JSON de uma linha, somente leitura (a codificação JSON escapa caracteres de controle);
- `pending` e `approve`: se o usuário atual não abre o banco do serviço, a leitura vai por `sudo -u sysop <python> cli.py show-action|pending`. O `sudo` zera o ambiente, então valem os caminhos padrão de produção;
- a resposta do serviço é **não confiável**: `_parse_action` exige JSON de objeto, `id` igual ao pedido, `ts` inteiro, ferramenta existente no registro, argumentos em JSON de objeto e status `pending`; o resto é recusado. O texto do modelo continua sanitizado antes de ir ao terminal;
- a aprovação grava o hash de id, data, ferramenta e argumentos **que o administrador viu**. Se o serviço mostrasse uma coisa e guardasse outra, o hash não bate e o `run-once` não executa (falha fechada; coberto por teste).

**Testes.** 31 novos; suíte inteira: **170 passed** [Medido na placa]. Teste de sanidade dos próprios testes: três sabotagens do validador (aceitar qualquer ferramenta, aceitar qualquer status, aceitar `id` diferente do pedido) foram **todas detectadas**.

**Teste de ponta a ponta, caminho real de produção [Medido, 07/11/2026 00:33 a 00:42].** Alvo: `203.0.113.77` (IP de documentação, não roteável).
| # | Etapa | Resultado |
|---|---|---|
| 1 | Inserida como `sysop` uma ação pendente `ban_ip_fail2ban` (motivo "TESTE E2E") no banco de produção | Ação `#1` |
| 2 | `cli.py pending` como `opad` (lê pelo `sysop`) | `#1 ... aguardando aprovação`; motivo do modelo marcado como não confiável |
| 3 | `cli.py approve 1` como `opad`, com confirmação `s` | `aprovada por opad`; `pending` passa a `APROVADA (aguarda o run-once)`; `approvals.db` lido pelo `sysop`: `(1, 'ban_ip_fail2ban', 'opad')` |
| 4 | `run-once --max 0` como `sysop` (executa só o aprovado, sem analisar incidentes nem chamar o LLM) | `ação #1 executada ... reflect: ban confirmado para 203.0.113.77`; o IP **não** estava no jail antes e **estava** depois (`fail2ban-client get sshd banip`) |
| 5 | Auditoria da hora | `action_approved` (ator `admin:opad`) e `action_executed` (ator `agent`) |
| 6 | Desfazer como administrador (`unbanip`) | Jail vazio |

**Limites e cuidados.**
- A ação, o incidente `#1` e a aprovação de `action_id` 1 **permanecem** no banco de produção como registro do teste. Não apagar a ação de teste: o `approvals.db` guarda o id 1, e um novo registro com o mesmo id seria recusado como "já aprovada" (e a chave primária não usa `AUTOINCREMENT`, então um id apagado pode ser reutilizado).
- O ensaio inseriu uma ação direta, sem passar por incidente aberto pelo Triage nem por decisão do LLM; o LLM e o grafo completo continuam validados à parte (13.6 e 13.10). A execução também foi manual (`run-once`), não por unidade `systemd`.
- O `opad` precisa digitar a senha do `sudo` ao listar e aprovar (interativo). O `sudo -u sysop` do administrador é aceito: um administrador comprometido está fora do modelo de ameaça deste desenho.
- Continua valendo o limite de 13.12: o `ban` manual ignora o `ignoreip` do `fail2ban` e o `sudoers` aceita qualquer IP; a barreira é o código (`protected_networks`, `validate_decision`, revalidação na execução). Wrapper com validação no passo 15.
"""

README_EDITS = [
 ("testes",
  "**139 testes** passando.",
  "**170 testes** passando."),
 ("detectores",
  "Faltam: detecção de atividade pós-login, cadeia completa de aprovação do ban no deploy (o trecho `sudo` + `fail2ban` já foi validado na placa), auditd,",
  "Faltam: detecção de atividade pós-login, auditd,"),
 ("boot e aprovação",
  "O container do LLM já sobe sozinho no boot (passo 14.1).",
  "O container do LLM já sobe sozinho no boot (passo 14.1), e a cadeia de aprovação do ban (o administrador aprova, o serviço executa e verifica) foi validada de ponta a ponta na placa em 07/11/2026 (passo 14.3)."),
 ("limite de aprovação",
  "- A separação de aprovação só é real com as permissões do deploy (passo 14).",
  "- A separação de aprovação vale com as permissões do deploy (passo 14.3): `approvals.db` do administrador, só leitura para o `sysop`. Ainda faltam o código do projeto fora do alcance de escrita do `sysop` e as unidades `systemd`."),
]


def check(path: Path, edits) -> bool:
    s = path.read_text()
    for name, old, _ in edits:
        if s.count(old) != 1:
            print(f"ERRO em {path.name}: trecho '{name}' não bate exatamente (achei {s.count(old)}x). Nada foi alterado.")
            return False
    return True


def main() -> int:
    impl, readme = ROOT / "docs" / "IMPLANTACAO.md", ROOT / "README.md"
    s = impl.read_text()
    if MARK in s:
        print("já aplicado, nada a fazer")
        return 0
    if "### 13.13 A/B de candidatos ao nó Plan" not in s or "### 14.2 Pendências do passo 14" not in s:
        print("ERRO: aplique antes os patches de documentação anteriores (até 13.13). Nada foi alterado.")
        return 1
    if not (check(impl, IMPL_EDITS) and check(readme, README_EDITS)):
        return 1
    for _, old, new in IMPL_EDITS:
        s = s.replace(old, new)
    s = s.rstrip("\n") + "\n" + IMPL_APPEND
    r = readme.read_text()
    for _, old, new in README_EDITS:
        r = r.replace(old, new)
    shutil.copy2(impl, str(impl) + ".bak-docs-aprov")
    shutil.copy2(readme, str(readme) + ".bak-docs-aprov")
    impl.write_text(s)
    readme.write_text(r)
    print("ok: IMPLANTACAO.md e README.md atualizados (backups .bak-docs-aprov)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
