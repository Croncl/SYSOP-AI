# Detecção (O3) em cenários SINTÉTICOS de fronteira: SYSOP-AI e fail2ban contra o gabarito

> Gerado por `eval_deteccao/cenarios.py`: não é medição de ataque real. Mostra onde os limiares fixos acertam e onde falham por projeto. O log do UFW passa por um limitador global igual ao da placa (3/min, rajada 10).

59 episódios: ssh_bruteforce=11, port_scan=5, benigno=43

## Métricas por detector e tipo

| detector | tipo | episódios | VP | FN | FP | precisão | recall | F1 | tempo até detectar, mediana (s) | máx (s) | duplicatas |
|---|---|---|---|---|---|---|---|---|---|---|---|
| SYSOP-AI | ssh_bruteforce | 11 | 3 | 8 | 0 | 100% (IC 44–100) | 27% (IC 10–57) | 0.43 | 18 | 27 | 0 |
| SYSOP-AI | port_scan | 5 | 3 | 2 | 0 | 100% (IC 44–100) | 60% (IC 23–88) | 0.75 | 2 | 27 | 0 |
| fail2ban (simulado) | ssh_bruteforce | 11 | 6 | 5 | 1 | 86% (IC 49–97) | 55% (IC 28–79) | 0.67 | 10 | 360 | 1 |
| fail2ban (simulado) | port_scan | 5 | 0 | 5 | 0 | – | 0% (IC 0–43) | – | – | – | 0 |

## Episódios

| episódio | tipo | IP | duração (s) | esperado | falhas SSH (máx/10 min) | portas (máx/10 min) | SYSOP-AI | fail2ban (simulado) |
|---|---|---|---|---|---|---|---|---|
| S1-rapida | ssh_bruteforce | 203.0.113.21 | 120 | detectar | 60 (60) | 0 (0) | detectou | detectou |
| S2-no-limiar | ssh_bruteforce | 203.0.113.22 | 30 | detectar | 10 (10) | 0 (0) | detectou | detectou |
| S3-abaixo-do-limiar | ssh_bruteforce | 203.0.113.23 | 27 | nao_detectar | 9 (9) | 0 (0) | FN | detectou |
| S4-lenta-90s | ssh_bruteforce | 203.0.113.24 | 1710 | nao_detectar | 20 (7) | 0 (0) | FN | detectou |
| S5-lenta-150s | ssh_bruteforce | 203.0.113.25 | 2850 | nao_detectar | 20 (4) | 0 (0) | FN | FN |
| S6-distribuida-1 | ssh_bruteforce | 198.51.100.101 | 30 | nao_detectar | 4 (4) | 0 (0) | FN | FN |
| S6-distribuida-2 | ssh_bruteforce | 198.51.100.102 | 30 | nao_detectar | 4 (4) | 0 (0) | FN | FN |
| S6-distribuida-3 | ssh_bruteforce | 198.51.100.103 | 30 | nao_detectar | 4 (4) | 0 (0) | FN | FN |
| S6-distribuida-4 | ssh_bruteforce | 198.51.100.104 | 30 | nao_detectar | 4 (4) | 0 (0) | FN | FN |
| S7-ipv6 | ssh_bruteforce | 2001:db8::21 | 60 | nao_detectar | 0 (0) | 0 (0) | FN | detectou |
| S8-invalid-user | ssh_bruteforce | 203.0.113.28 | 60 | detectar | 30 (30) | 0 (0) | detectou | detectou |
| B1-admin-erra-2x | benigno | 198.51.100.50 | 9 | nao_detectar | 2 (2) | 0 (0) | — | — |
| B2-admin-erra-6x | benigno | 198.51.100.51 | 60 | nao_detectar | 6 (6) | 0 (0) | — | — |
| B3-logins-chave-1 | benigno | 192.0.2.10 | 300 | nao_detectar | 0 (0) | 0 (0) | — | — |
| B3-logins-chave-2 | benigno | 192.0.2.11 | 300 | nao_detectar | 0 (0) | 0 (0) | — | — |
| B3-logins-chave-3 | benigno | 192.0.2.12 | 300 | nao_detectar | 0 (0) | 0 (0) | — | — |
| B3-logins-chave-4 | benigno | 192.0.2.13 | 300 | nao_detectar | 0 (0) | 0 (0) | — | — |
| B3-logins-chave-5 | benigno | 192.0.2.14 | 300 | nao_detectar | 0 (0) | 0 (0) | — | — |
| B3-logins-chave-6 | benigno | 192.0.2.15 | 300 | nao_detectar | 0 (0) | 0 (0) | — | — |
| B3-logins-chave-7 | benigno | 192.0.2.16 | 300 | nao_detectar | 0 (0) | 0 (0) | — | — |
| B3-logins-chave-8 | benigno | 192.0.2.17 | 300 | nao_detectar | 0 (0) | 0 (0) | — | — |
| B3-logins-chave-9 | benigno | 192.0.2.18 | 300 | nao_detectar | 0 (0) | 0 (0) | — | — |
| B3-logins-chave-10 | benigno | 192.0.2.19 | 300 | nao_detectar | 0 (0) | 0 (0) | — | — |
| P1-rapida-100 | port_scan | 203.0.113.31 | 30 | detectar | 0 (0) | 11 (11) | detectou | FN |
| P2-rapida-1000 | port_scan | 203.0.113.32 | 300 | detectar | 0 (0) | 24 (24) | detectou | FN |
| P3-9-portas | port_scan | 203.0.113.33 | 27 | nao_detectar | 0 (0) | 9 (9) | FN | FN |
| P4-lenta | port_scan | 203.0.113.34 | 2280 | nao_detectar | 0 (0) | 16 (5) | FN | FN |
| P5-mesma-porta | benigno | 203.0.113.35 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-1 | benigno | 192.0.2.100 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-2 | benigno | 192.0.2.101 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-3 | benigno | 192.0.2.102 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-4 | benigno | 192.0.2.103 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-5 | benigno | 192.0.2.104 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-6 | benigno | 192.0.2.105 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-7 | benigno | 192.0.2.106 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-8 | benigno | 192.0.2.107 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-9 | benigno | 192.0.2.108 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-10 | benigno | 192.0.2.109 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-11 | benigno | 192.0.2.110 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-12 | benigno | 192.0.2.111 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-13 | benigno | 192.0.2.112 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-14 | benigno | 192.0.2.113 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-15 | benigno | 192.0.2.114 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-16 | benigno | 192.0.2.115 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-17 | benigno | 192.0.2.116 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-18 | benigno | 192.0.2.117 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-19 | benigno | 192.0.2.118 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-20 | benigno | 192.0.2.119 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-21 | benigno | 192.0.2.120 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-22 | benigno | 192.0.2.121 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-23 | benigno | 192.0.2.122 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-24 | benigno | 192.0.2.123 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-25 | benigno | 192.0.2.124 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-26 | benigno | 192.0.2.125 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-27 | benigno | 192.0.2.126 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-28 | benigno | 192.0.2.127 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-29 | benigno | 192.0.2.128 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P6-ruido-30 | benigno | 192.0.2.129 | 600 | nao_detectar | 0 (0) | 1 (1) | — | — |
| P7-ipv6-15 | port_scan | 2001:db8::31 | 45 | detectar | 0 (0) | 12 (12) | detectou | FN |

## Falsos negativos e falsos positivos, com o motivo provável

| detector | tipo | episódio/IP | resultado | motivo provável | esperado no gabarito |
|---|---|---|---|---|---|
| SYSOP-AI | ssh_bruteforce | S3-abaixo-do-limiar | FN | abaixo do limiar: no máximo 9 falhas em 10 min (limiar 10) | nao_detectar |
| SYSOP-AI | ssh_bruteforce | S4-lenta-90s | FN | abaixo do limiar: no máximo 7 falhas em 10 min (limiar 10) | nao_detectar |
| SYSOP-AI | ssh_bruteforce | S5-lenta-150s | FN | abaixo do limiar: no máximo 4 falhas em 10 min (limiar 10) | nao_detectar |
| SYSOP-AI | ssh_bruteforce | S6-distribuida-1 | FN | abaixo do limiar: no máximo 4 falhas em 10 min (limiar 10) | nao_detectar |
| SYSOP-AI | ssh_bruteforce | S6-distribuida-2 | FN | abaixo do limiar: no máximo 4 falhas em 10 min (limiar 10) | nao_detectar |
| SYSOP-AI | ssh_bruteforce | S6-distribuida-3 | FN | abaixo do limiar: no máximo 4 falhas em 10 min (limiar 10) | nao_detectar |
| SYSOP-AI | ssh_bruteforce | S6-distribuida-4 | FN | abaixo do limiar: no máximo 4 falhas em 10 min (limiar 10) | nao_detectar |
| SYSOP-AI | ssh_bruteforce | S7-ipv6 | FN | IPv6 no SSH: 30 falhas no log, mas as regras da triagem só reconhecem IPv4 | nao_detectar |
| SYSOP-AI | port_scan | P3-9-portas | FN | abaixo do limiar: no máximo 9 portas distintas registradas em 10 min (limiar 10; o log do UFW tem limite de 3/min, rajada 10) | nao_detectar |
| SYSOP-AI | port_scan | P4-lenta | FN | abaixo do limiar: no máximo 5 portas distintas registradas em 10 min (limiar 10; o log do UFW tem limite de 3/min, rajada 10) | nao_detectar |
| fail2ban (simulado) | ssh_bruteforce | S5-lenta-150s | FN | no máximo 4 falhas contáveis em 10 min (maxretry do jail) | nao_detectar |
| fail2ban (simulado) | ssh_bruteforce | S6-distribuida-1 | FN | no máximo 4 falhas contáveis em 10 min (maxretry do jail) | nao_detectar |
| fail2ban (simulado) | ssh_bruteforce | S6-distribuida-2 | FN | no máximo 4 falhas contáveis em 10 min (maxretry do jail) | nao_detectar |
| fail2ban (simulado) | ssh_bruteforce | S6-distribuida-3 | FN | no máximo 4 falhas contáveis em 10 min (maxretry do jail) | nao_detectar |
| fail2ban (simulado) | ssh_bruteforce | S6-distribuida-4 | FN | no máximo 4 falhas contáveis em 10 min (maxretry do jail) | nao_detectar |
| fail2ban (simulado) | ssh_bruteforce | B2-admin-erra-6x | FP | episódio benigno B2-admin-erra-6x gerou 5 eventos contáveis na janela |  |
| fail2ban (simulado) | port_scan | P1-rapida-100 | FN | a jail sshd não lê o UFW: o fail2ban da placa não tem jail de varredura | detectar |
| fail2ban (simulado) | port_scan | P2-rapida-1000 | FN | a jail sshd não lê o UFW: o fail2ban da placa não tem jail de varredura | detectar |
| fail2ban (simulado) | port_scan | P3-9-portas | FN | a jail sshd não lê o UFW: o fail2ban da placa não tem jail de varredura | nao_detectar |
| fail2ban (simulado) | port_scan | P4-lenta | FN | a jail sshd não lê o UFW: o fail2ban da placa não tem jail de varredura | nao_detectar |
| fail2ban (simulado) | port_scan | P7-ipv6-15 | FN | a jail sshd não lê o UFW: o fail2ban da placa não tem jail de varredura | detectar |

