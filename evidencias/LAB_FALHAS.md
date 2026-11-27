# Falhas do laboratório (O3), rodada de 26/11/2026

| # | Falha | Efeito | Ação |
|---|---|---|---|
| F1 | `backend = systemd` do jail-sombra falhou (faltava python3-systemd); o reload derrubou todos os jails por ~1 min | Placa sem fail2ban por instantes; corrigido com `apt install python3-systemd` | Registrar no RUNBOOK_LAB (pré-requisito) |
| F2 | Coletor iniciado antes do checkout u3-avaliacao: rodou com triage.py sem consolidação SSH | Incidentes fragmentados no banco ao vivo (.7 em 5 incidentes) | Análise limpa vem do replay do journal |
| F3 | `sudo nmap` esperou senha: início de L5 e L7 gravado antes do nmap | Tempo até detectar inflado; início corrigido pelo cabeçalho do nmap | Rodar `sudo -v` antes do ataque.sh |
| F4 | L4 sem login por chave | Episódio benigno sem `Accepted` | Nota do gabarito não vale |
| F5 | Ban sob a unidade systemd falhou (`no new privileges`), ações #3 e #9; drop-in `NoNewPrivileges=no` não resolveu | Execução só funcionou fora do systemd (#12, verificada) | Corrigir deploy/systemd/sysopai-agent.service |
| F6 | Placa reiniciou durante a rodada: journal anterior perdido; coletor sem eventos após 20:37 | L7, L8, L9 não avaliáveis; L6 parcial (7 portas) | Repetir L7 a L9 e coletar logo após |
| F7 | `journal: 0 linhas` no coleta.sh | Sem replay nem fail2ban simulado desta rodada | Journal persistente e coletar antes de qualquer reboot |
# Falhas do laboratório (O3), rodada de 26/11/2026

| # | Falha | Efeito | Ação |
|---|---|---|---|
| F1 | `backend = systemd` do jail-sombra falhou (faltava python3-systemd); o reload derrubou todos os jails por ~1 min | Placa sem fail2ban por instantes; corrigido com `apt install python3-systemd` | Registrar no RUNBOOK_LAB (pré-requisito) |
| F2 | Coletor iniciado antes do checkout u3-avaliacao: rodou com triage.py sem consolidação SSH | Incidentes fragmentados no banco ao vivo (.7 em 5 incidentes) | Análise limpa vem do replay do journal |
| F3 | `sudo nmap` esperou senha: início de L5 e L7 gravado antes do nmap | Tempo até detectar inflado; início corrigido pelo cabeçalho do nmap | Rodar `sudo -v` antes do ataque.sh |
| F4 | L4 sem login por chave | Episódio benigno sem `Accepted` | Nota do gabarito não vale |
| F5 | Ban sob a unidade systemd falhou (`no new privileges`), ações #3 e #9; drop-in `NoNewPrivileges=no` não resolveu | Execução só funcionou fora do systemd (#12, verificada) | Corrigir deploy/systemd/sysopai-agent.service |
| F6 | Placa reiniciou durante a rodada: journal anterior perdido; coletor sem eventos após 20:37 | L7, L8, L9 não avaliáveis; L6 parcial (7 portas) | Repetir L7 a L9 e coletar logo após |
| F7 | `journal: 0 linhas` no coleta.sh | Sem replay nem fail2ban simulado desta rodada | Journal persistente e coletar antes de qualquer reboot |
