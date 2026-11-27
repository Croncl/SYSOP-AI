# Laboratório de ataques contra a placa (O3: detecção e bloqueio aprovado)

**Para quem opera a Orange Pi 4 Pro.** São de 1h30 a 2h no total, com uma segunda máquina na mesma LAN. Os ataques partem só dessa máquina, só contra a placa e só dentro da rede local.

O laboratório mede três coisas:
- precisão, recall e F1 da detecção do SYSOP-AI e do fail2ban sozinho, no mesmo tráfego;
- o tempo até detectar;
- a cadeia completa: detecção → decisão do LLM → aprovação humana → ban no fail2ban → conferência.

Resumo dos passos:

| # | Onde | O quê | Tempo |
|---|---|---|---|
| 1–2 | placa | pré-checagens (anotar) | 10 min |
| 3–4 | placa | coletor rodando e fail2ban temporário | 10 min |
| 5 | atacante | `lab/ataque.sh` (9 episódios) | ≈ 45 min |
| 6 | placa + atacante | ponta a ponta: aprovar e conferir 1 ou 2 bans | 20 min |
| 7 | placa | `lab/coleta.sh` e enviar o pacote | 5 min |
| 8 | placa + atacante | **restaurar** | 5 min |

## 1. O que é preciso

- **Placa:** com o código na tag `artigo-u3-rodadas` (`git checkout artigo-u3-rodadas`).
- **Máquina atacante na mesma LAN da placa:** um notebook com Linux e `sudo`.
  - Ferramentas: `ssh`, `nmap` e, se a placa aceitar senha, `sshpass`.
  - Debian/Ubuntu: `sudo apt install nmap sshpass`. Fedora: `sudo dnf install nmap sshpass`.
- **Três IPs livres da LAN:**
  - Ficam fora do DHCP, se possível. Confira com `ping -c1` que não respondem.
  - **Nunca** use `192.168.0.1` (roteador) nem `10.10.0.x` (cluster): são redes protegidas, e o agente não os bloquearia.
  - **Nunca** use o IP pelo qual você administra a placa: um desses IPs **será banido de verdade** no passo 6.
- **Relógio sincronizado nas duas máquinas:** `timedatectl | grep -i synchronized` deve dar `yes`.

## 2. Pré-checagens na placa (anote as respostas e mande para o grupo)

```bash
sudo sshd -T | grep -Ei '^(passwordauthentication|maxauthtries|maxstartups) '
journalctl -t sshd -n 2 --no-pager; journalctl -t sshd-session -n 2 --no-pager
sudo fail2ban-client get sshd maxretry; sudo fail2ban-client get sshd ignoreip
grep -i '^logtarget' /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local 2>/dev/null
sudo ufw status verbose | head -4                 # deve ter "Logging: on"
sudo -u sysop /home/projetos/SYSOP-AI/venv/bin/python -c "import sqlite3; c=sqlite3.connect('file:/var/lib/sysopai/sysop.db?mode=ro', uri=True); print([r[0] for r in c.execute('select cidr from protected_networks')])"
```

- **`passwordauthentication`**:
  - `yes`: rode o passo 5 com `SENHA_SSH=1`. Entra o episódio L9 (senha errada).
  - `no`: os ataques usam só usuários inexistentes ("Invalid user"), que o sshd registra mesmo sem senha.
- **Identificador do sshd:** se as linhas aparecem em `sshd-session` e não em `sshd` (OpenSSH 9.8 ou mais novo), **pare e avise o grupo**. O coletor não lê esse identificador; é um achado, e o código precisa de ajuste antes.
- **`maxretry`:** anote o valor atual. O passo 8 confere que ele voltou.

## 3. Coletor rodando (o agente fica parado durante os ataques)

**Opção A (recomendada): instalar as unidades do repositório.** É o pendente do passo 14.2.

```bash
cd /home/projetos/SYSOP-AI
sudo cp deploy/systemd/sysopai-collector.service deploy/systemd/sysopai-agent.service deploy/systemd/sysopai-agent.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sysopai-collector.service
sudo systemctl stop sysopai-agent.timer 2>/dev/null || true     # o agente só roda no passo 6, à mão
systemctl status sysopai-collector --no-pager | head -5
```

**Opção B: coletor à mão**, num `tmux` ou `screen`:

```bash
sudo -u sysop /home/projetos/SYSOP-AI/venv/bin/python /home/projetos/SYSOP-AI/sysopai/collector.py
```

**Teste rápido.** Da máquina atacante, rode `ssh -o BatchMode=yes teste-coletor@IP_DA_PLACA true` (vai falhar). Depois, na placa:

```bash
sudo -u sysop /home/projetos/SYSOP-AI/venv/bin/python -c "import sqlite3; c=sqlite3.connect('file:/var/lib/sysopai/sysop.db?mode=ro', uri=True); print(c.execute(\"select ts,event_type,src_ip from raw_events order by id desc limit 3\").fetchall())"
```

Deve aparecer um `ssh_invalid_user` com o IP da máquina atacante.

## 4. fail2ban temporário: jail-sombra e `maxretry` alto (D13)

```bash
sudo cp lab/fail2ban-lab.local /etc/fail2ban/jail.d/zz-sysopai-lab.local
sudo fail2ban-client -t && sudo fail2ban-client reload
sudo fail2ban-client get sshd maxretry            # 1000: o fail2ban real não bane sozinho durante o lab
sudo fail2ban-client status sshd-sombra           # jail-sombra ativa (ação dummy: registra "Ban", não bloqueia)
```

O motivo da configuração: com o `maxretry` padrão (5), o fail2ban baniria o atacante na 5ª falha, e o SYSOP-AI (limiar 10) nunca veria o ataque. A jail-sombra tem os parâmetros padrão e mede o "fail2ban sozinho" no mesmo tráfego, sem bloquear nada.

Se `action = dummy` der erro (fail2ban antigo), apague o bloco `[sshd-sombra]` do arquivo e siga. A comparação com o fail2ban fica com a simulação no PC.

## 5. Ataques (na máquina atacante, ≈ 45 min)

```bash
git clone <repositório> && cd SYSOP-AI        # ou copie só lab/ataque.sh
ip -o -4 addr                                  # descubra a interface da LAN (ex.: wlp2s0)
# ensaio sem tráfego (confere o fluxo e o gabarito):
DRY=1 ALVO=192.168.0.4 IFACE=wlp2s0 IPS="192.168.0.201 192.168.0.202 192.168.0.203" bash lab/ataque.sh
# para valer:
ALVO=192.168.0.4 IFACE=wlp2s0 IPS="192.168.0.201 192.168.0.202 192.168.0.203" SENHA_SSH=0 bash lab/ataque.sh
```

Troque `ALVO`, `IFACE` e `IPS` pelos seus. O script põe os três IPs na interface (e tira ao sair). Ele roda os episódios abaixo e grava `lab-AAAAMMDD-HHMM/gabarito.csv` com o início e o fim de cada um:

| Ep. | Origem | O quê | O SYSOP-AI deve | O fail2ban (5 em 10 min) deve |
|---|---|---|---|---|
| L1 | A | 30 usuários inexistentes, 1 a cada 2 s | detectar | detectar |
| L2 | B | exatamente 10 em ~30 s | detectar (no limiar) | detectar |
| L3 | C | 8 em ~24 s | **não** detectar (abaixo do limiar) | detectar |
| L5 | A | `nmap -sS` portas 1–100 | detectar | não (a jail sshd não lê o UFW) |
| L6 | B | `nmap -sS -T4` portas 1–1000 | detectar | não |
| L4 | C | erra o usuário 2× e entra com chave (benigno) | não detectar | não detectar |
| L7 | C | `nmap` de 9 portas | **não** detectar (abaixo do limiar) | não |
| L8 | A | 12 tentativas, 1 a cada 90 s (~17 min) | **não** detectar (lento) | detectar |
| L9 | B | 20 senhas erradas (só com `SENHA_SSH=1`) | detectar | detectar |

O script espera 11 min antes de reusar um IP, para que cada episódio seja independente da janela de 10 min. Durante os ataques:
- não faça outros acessos SSH à placa a partir desses três IPs;
- evite logins com erro de outras máquinas: tudo isso entra no journal e pode virar falso positivo.

## 6. Ponta a ponta: aprovar, banir e conferir (≈ 20 min)

Na placa, depois do fim dos ataques:

```bash
cd /home/projetos/SYSOP-AI
sudo systemctl start sysopai-agent.service          # (ou: sudo -u sysop venv/bin/python sysopai/cli.py run-once --max 10)
journalctl -u sysopai-agent.service -n 20 --no-pager # cada incidente leva ~1 min de LLM; repita até analisar todos
venv/bin/python sysopai/cli.py pending              # lista os bans propostos (lê pelo usuário sysop)
venv/bin/python sysopai/cli.py approve <ID>         # aprove SÓ o ban do IP A (confira o IP na tela antes do "s")
sudo systemctl start sysopai-agent.service          # executa o que foi aprovado e verifica (Reflect)
sudo fail2ban-client get sshd banip                 # o IP A tem de estar na lista
```

Na máquina atacante:

```bash
nc -zv -s 192.168.0.201 -w 3 192.168.0.4 22     # pelo IP A: deve FALHAR (banido)
nc -zv -w 3 192.168.0.4 22                       # pelo IP principal: deve conectar
```

Se quiser um segundo exemplo, aprove também o ban do IP B. Não aprove nenhum outro IP.

Desfazer, só como administrador:

```bash
sudo fail2ban-client set sshd unbanip 192.168.0.201    # e o B, se aprovou
```

## 7. Coleta e envio

Copie o gabarito da máquina atacante para a placa e rode a coleta:

```bash
scp lab-*/gabarito.csv lab-*/relogio.txt lab-*/ataque.log opad@192.168.0.4:/tmp/lab/   # na atacante
bash lab/coleta.sh /tmp/lab/gabarito.csv                                              # na placa
```

O pacote `lab-coleta-AAAAMMDD-HHMM.tar.gz` traz:
- o journal da janela;
- cópias do `sysop.db` e do `approvals.db`, feitas em modo leitura;
- o log e o estado do fail2ban;
- o ambiente (sshd, UFW, redes protegidas, RSS do coletor e do agente);
- o gabarito.

Envie o pacote e o `.sha256` para o grupo.

## 8. Restauração (obrigatória)

```bash
sudo rm /etc/fail2ban/jail.d/zz-sysopai-lab.local && sudo fail2ban-client reload
sudo fail2ban-client get sshd maxretry     # tem de voltar ao valor anotado no passo 2
sudo fail2ban-client get sshd banip        # sem IPs do laboratório
```

- **Na máquina atacante:** o script já removeu os IPs extras. Confira com `ip -o addr`.
- **Agente em produção:** se o grupo quiser o agente rodando, use `sudo systemctl enable --now sysopai-agent.timer`. Senão, deixe-o parado. O coletor pode continuar ativo.
- **Banco de produção:** os incidentes e as ações do laboratório ficam no banco, e é assim que deve ser. Não apague nada: são evidência e fazem parte da auditoria (append-only).

## 9. Análise (no PC, por quem recebe o pacote)

```bash
tar xzf lab-coleta-*.tar.gz && cd lab-coleta-*/ && sha256sum -c SHA256SUMS
python -m eval_deteccao.metricas --gabarito gabarito.csv --journal journal.json --sysop-db sysop.db \
    --f2b-log fail2ban.log --out deteccao.md --csv-dir csv      # sem --f2b-log se o fail2ban loga no journal
python -m eval_deteccao.cadeia --sysop-db sysop.db --approvals-db approvals.db --out cadeia.md
```

Se o `relogio.txt` mostrar diferença entre a placa e a atacante, passe-a em `--skew` (em segundos: placa menos atacante).

## Problemas comuns

| Sintoma | Causa provável e o que fazer |
|---|---|
| Nenhum `ssh_invalid_user` no teste do passo 3 | coletor parado ou sshd com outro identificador (`sshd-session`): avise o grupo |
| `nmap: Failed to open device` / sem resposta | `-e` com a interface errada; rode `ip -o -4 addr` e ajuste `IFACE` |
| Varredura detectada com poucas portas | esperado: o UFW registra no máximo 3 linhas/min (rajada 10). Está nas limitações |
| Ban aprovado não aparece em `banip` | veja `journalctl -u sysopai-agent -n 50`: o Reflect registra `ALERT_CRITICAL` se o ban não pegou |
| O fail2ban baniu a atacante sozinho | o passo 4 não pegou: `sudo fail2ban-client get sshd maxretry` tem de dar 1000 |
