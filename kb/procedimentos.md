# Base de conhecimento do SYSOP-AI
Texto curado por humanos. Nunca colar logs brutos aqui.

## Brute force SSH: o que fazer
O fail2ban já bane IPs com falhas repetidas no jail sshd. O agente só propõe banimento manual com 10 ou mais falhas contadas pelo SQL, IP presente na evidência, confiança de 0,80 ou mais e fora das redes protegidas. Em caso de dúvida, apenas notificar.

## Redes que nunca devem ser banidas
A LAN do cluster 10.10.0.0/24, a LAN local 192.168.0.0/24, o roteador, o loopback e a tailnet 100.64.0.0/10. O master é o gateway da LAN: banir essas redes derruba o acesso ao cluster e ao administrador.

## Como desfazer um banimento
Desfazer é ato humano: sudo fail2ban-client set sshd unbanip IP. O usuário sysop não tem essa permissão, de propósito.

## Falhas de login vindas da rede protegida
Várias falhas de um IP da rede protegida costumam ser o próprio administrador errando a senha. Não propor banimento; apenas registrar.
