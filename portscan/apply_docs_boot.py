#!/usr/bin/env python3
"""Atualiza docs/IMPLANTACAO.md e README.md: container do LLM sobe no boot (passo 14, em andamento). Só texto.
Requer os patches de documentação anteriores (13.10 a 13.12) já aplicados.

  * seguro: texto exato, senão NADA é alterado; idempotente; cópias em *.bak-docs-boot.

    python portscan/apply_docs_boot.py        # na raiz do projeto (ou com o script em uma subpasta)
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = "## Passo 14 — Deploy (em andamento)"

IMPL_EDITS = [
 ("índice, linha 14",
  "| 14 | Deploy | Pendente |",
  "| 14 | Deploy | **Em andamento** (container do LLM no boot concluído; unidades do coletor e do agente, cadeia de aprovação e permissões do deploy pendentes) |"),
 ("13.7, containers no boot",
  "- Os containers do LLM **não sobem sozinhos no boot** (continua no passo 14). Durante o A/B",
  "- O container do LLM de produção sobe no boot desde 04/11 (passo 14.1); `llama-plan` e `llama-ab-15b` ficam parados de propósito. Durante o A/B"),
 ("13.8, item 7",
  "7. Containers do LLM **no boot**: em 04/11 a placa aparentemente reiniciou (o `/tmp` foi limpo) e o `llama-plan-15b` não estava rodando, com o `/health` sem resposta; foi preciso `podman start` à mão (passo 14).",
  "7. ~~Containers do LLM no boot~~ resolvido para o `llama-plan-15b` (passo 14.1). Resta investigar o `llama-embed`, parado com `Exited (1)`."),
]

IMPL_APPEND = """

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
"""

README_EDITS = [
 ("estado",
  "12 (auditoria), 14 (deploy) e 15 (hardening) pendentes.",
  "12 (auditoria) e 15 (hardening) pendentes; 14 (deploy) em andamento."),
 ("faltam",
  "alertas, containers no boot e hardening de produção.",
  "alertas, unidades `systemd` do coletor e do agente e hardening de produção. O container do LLM já sobe sozinho no boot (passo 14.1)."),
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
    shutil.copy2(path, str(path) + ".bak-docs-boot")
    path.write_text(s)
    print(f"ok: {path} atualizado (backup .bak-docs-boot)")


def main() -> int:
    impl, readme = ROOT / "docs" / "IMPLANTACAO.md", ROOT / "README.md"
    if MARK in impl.read_text():
        print("já aplicado, nada a fazer")
        return 0
    if "### 13.12 Execução real do ban" not in impl.read_text():
        print("ERRO: aplique antes apply_docs_ban.py. Nada foi alterado.")
        return 1
    if not (check(impl, IMPL_EDITS) and check(readme, README_EDITS)):
        return 1
    write(impl, IMPL_EDITS, IMPL_APPEND)
    write(readme, README_EDITS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
