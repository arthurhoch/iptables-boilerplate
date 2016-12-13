#!/bin/bash

####################################
############ Variaveis #############
####################################

IPT=/sbin/iptables

####################################
IF_WAN=eth0
IF_LAN=eth1
####################################

####################################

#IP_WAN=""
IP_LAN="192.168.2.1/24"
IP_GW="1.1.1.254"

####################################
####### rede e seus ranges #########
####################################

REDE_INTERNA="192.168.2.0/24"

RANGE_CPD="192.168.2.41-192.168.2.50"
RANGE_DIRETORIA="192.168.2.51-192.168.2.60"
RANGE_PUBLICIDADE="192.168.2.61-192.168.2.70"

####################################
############## Portas ##############
####################################

HTTP=80
HTTPS=443
SSH=22
DNS=53
POP3=110
SMTP=587

function IniciaFirewall(){

    #####################################
    #### politica padrao - NEGA TUDO ####
    #####################################

    echo "politica por omissao - negar TUDO"

    $IPT -P INPUT DROP
    $IPT -P OUTPUT DROP
    $IPT -P FORWARD DROP

    #####################################
    ##### configurando interfaces #######
    #####################################

    ifconfig $IF_LAN $IP_LAN

    route del default
    route add default gw $IP_GW

    #####################################

    echo "apaga as regras ja existentes"
    $IPT -F
    $IPT -X
    $IPT -Z
    $IPT -t nat -F
    $IPT -t nat -X
    $IPT -t nat -Z
    $IPT -F POSTROUTING -t nat
    $IPT -F PREROUTING -t nat
    $IPT -F OUTPUT -t nat

    ######################################
    ############ stateless ###############
    ######################################

    echo "permite loopbak"
    $IPT -A INPUT -i lo -j ACCEPT
    $IPT -A OUTPUT -o lo -j ACCEPT

    ######################################
    ########### statefull ################
    ######################################

    echo "descarta pacotes invalidos"
    $IPT -A INPUT -m state --state INVALID -j DROP

    echo "Libera tudo para rede do CPD [ok]"
    $IPT -A OUTPUT -p tcp --sport 1204:65535 -m iprange --src-range $RANGE_CPD -m state --state NEW -j ACCEPT
    $IPT -A FORWARD -m iprange --src-range $RANGE_CPD -i $IF_LAN -o $IF_WAN -j ACCEPT

    echo "Libera tudo para rede do DIRETORIA [ok]"
    $IPT -A OUTPUT -p tcp --sport 1204:65535 -m iprange --src-range $RANGE_DIRETORIA -m state --state NEW -j ACCEPT
    $IPT -A FORWARD -m iprange --src-range $RANGE_DIRETORIA -i $IF_LAN -o $IF_WAN -j ACCEPT

    echo "Libera tudo para rede do PUBLICIDADE [ok]"
    $IPT -A FORWARD -p tcp -i $IF_LAN -o $IF_WAN --dport $HTTPS -m iprange --src-range $RANGE_PUBLICIDADE -m string --algo bm --string "facebook.com" -j ACCEPT
    $IPT -A FORWARD -p tcp -i $IF_LAN -o $IF_WAN --dport $HTTPS -m iprange --src-range $RANGE_PUBLICIDADE -m string --algo bm --string "youtube.com" -j ACCEPT
    $IPT -A FORWARD -p tcp -i $IF_LAN -o $IF_WAN --dport $HTTPS -m iprange --src-range $RANGE_PUBLICIDADE -m string --algo bm --string "twitter.com" -j ACCEPT

    echo "Restante da rede segue as regras de bloqueios por horaio 1.1.1.100-1.1.1.240 (Facebook e YouTube)"

    echo "bloqueia facebook mas libera na hora do almoco [ok]"
    $IPT -A FORWARD -p tcp -i $IF_LAN -o $IF_WAN --dport $HTTPS -m string --algo bm --string "facebook.com" -m time --timestart 13:30 --timestop 12:00 --kerneltz -j DROP

    echo "bloqueia youtube mas libera na hora do almoco [ok]"
    $IPT -A FORWARD -s $REDE_INTERNA -m string --algo bm --string 'youtube.com' -m time --timestart 13:30 --timestop 12:00 --kerneltz -j DROP
    $IPT -A OUTPUT -s $REDE_INTERNA -m string --algo bm --string 'youtube.com' -m time --timestart 13:30 --timestop 12:00 --kerneltz -j DROP

    echo "bloqueia twitter mas libera na hora do almoco [ok]"
    $IPT -A FORWARD -s $REDE_INTERNA -m string --algo bm --string 'twitter.com' -m time --timestart 13:30 --timestop 12:00 --kerneltz -j DROP
    $IPT -A OUTPUT -s $REDE_INTERNA -m string --algo bm --string 'twitter.com' -m time --timestart 13:30 --timestop 12:00 --kerneltz -j DROP

    echo "regras STATEFULL genericas"
    $IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    $IPT -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
    $IPT -A FORWARD -i $IF_LAN -m state --state ESTABLISHED,RELATED -j ACCEPT
    $IPT -A FORWARD -i $IF_WAN -m state --state ESTABLISHED,RELATED -j ACCEPT

    echo "permitir DNS [ok]"
    $IPT -A OUTPUT -p udp --sport 1024:65535 --dport $DNS -m state --state NEW -j ACCEPT
    $IPT -A FORWARD -p udp -i $IF_LAN -o $IF_WAN --dport $DNS -j ACCEPT

    echo "permite HTTP [ok]"
    #$IPT -A OUTPUT -p tcp --sport 1024:65535 --dport $HTTP -m state --state NEW -j ACCEPT
    $IPT -A FORWARD -p tcp -i $IF_LAN -o $IF_WAN --dport $HTTP -j ACCEPT

    echo "permite HTTPS [ok]"
    #$IPT -A OUTPUT -p tcp --sport 1024:65535 --dport $HTTPS -m state --state NEW -j ACCEPT
    $IPT -A FORWARD -p tcp -i $IF_LAN -o $IF_WAN --dport $HTTPS -j ACCEPT

    echo "libera portas para e-mail ngegrafica [ok]"
    $IPT -A FORWARD -p tcp -i $IF_LAN -o $IF_WAN --dport $POP3 -j ACCEPT
    $IPT -A FORWARD -p tcp -i $IF_LAN -o $IF_WAN --dport $SMTP -j ACCEPT

    echo "libera SSH [ok]"
    $IPT -A INPUT -p tcp --dport $SSH -j LOG --log-level 4 --log-prefix 'SSH_WAN > '
    $IPT -A INPUT -p tcp -i $IF_WAN --dport $SSH -j ACCEPT

    echo "libera servico smb na porta WAN" #Uso para fins bem especificos (recomendo nao usar se não souber exatamente o que vai fazer)
    $IPT -A INPUT -p udp -i $IF_WAN --dport 137 -j ACCEPT
    $IPT -A INPUT -p udp -i $IF_WAN --dport 138 -j ACCEPT
    $IPT -A INPUT -p tcp -i $IF_WAN --dport 139 -j ACCEPT
    $IPT -A INPUT -p tcp -i $IF_WAN --dport 445 -j ACCEPT

    #Postas para fluxo smb vindo da internet
    #137/udp: Usada pelo Daemon nmbd, responsável pela navegação nos compartilhamentos de rede.
    #138/udp: Também usada pelo nmbd, dessa vez para a resolução dos nomes das máquinas da rede.
    #139/tcp: Usada pelo daemon smbd, o componente principal do Samba, responsável pelo compartilhamento de arquivos e impressoras.
    #445/tcp: Esta porta é usada pelos clientes Windows 2000, XP e Vista para navegação na rede. Eles utilizam o protocolo CIFS, no lugar do antigo protocolo NetBIOS.

    ###########################################
    ########## seguranca da rede ##############
    ###########################################

    echo "Impedindo ataque Ping of Death e ping flood no Firewall vindo da rede interna"
    #A regra abaixo limita em 1 vez por segundo (--limit 1/s) a passagem de pings (echo requests) para o Firewall
    $IPT -A INPUT -p icmp --icmp-type echo-request -i $IF_LAN -j LOG --log-level 4 --log-prefix 'PING_INERNO > '
    $IPT -A INPUT -p icmp --icmp-type echo-request -i $IF_LAN -m limit --limit 1/s -j ACCEPT

    echo "Descarte de pacotes nao identificados ICMP"
    $IPT -A OUTPUT -m state -p icmp --state INVALID -j DROP
    $IPT -A INPUT -m state -p icmp --state INVALID -j DROP
    $IPT -A FORWARD -m state -p icmp --state INVALID -j DROP

    #http://www.ibm.com/developerworks/br/library/os-iptables/
    #Limite de DNS
    #A execução de um servidor Linux como gateway causará certos problemas com o DNS.
    #O kernel é projetado para manter uma tabela de mapeamentos DNS,
    #mas ele vem com um nível máximo de entradas que não é adequado para tráfego pesado.
    #Quando esse nível for atingido, nenhuma consulta DNS pode voltar ao host que a fez.
    #Apesar de esse limite ser raramente atingido com poucos clientes,
    #mais de trinta clientes passando por esse firewall causará problemas.
    #
    #Fique atento a mensagens semelhantes àquela naListagem 16,
    #que fornecerão um aviso se for necessário aumentar os números recém-fornecidos.
    #Listagem 16. Avisos de estouro de DNS de log do sistema
    #
    #Nov  22 11:36:16 firewall kernel: [92374.325689] Neighbour table overflow.
    #Nov  22 11:36:20 firewall kernel: [92379.089870] printk: 37 messages suppressed.
    #Nov  22 11:36:20 firewall kernel: [92379.089876] Neighbour table overflow.
    #Nov  22 11:36:26 firewall kernel: [92384.333161] printk: 51 messages suppressed.
    #Nov  22 11:36:26 firewall kernel: [92384.333166] Neighbour table overflow.
    #Nov  22 11:36:30 firewall kernel: [92389.084373] printk: 200 messages suppressed.

    echo 1024 > /proc/sys/net/ipv4/neigh/default/gc_thresh1
    echo 2048 > /proc/sys/net/ipv4/neigh/default/gc_thresh2
    echo 4096 > /proc/sys/net/ipv4/neigh/default/gc_thresh3

    #Configuração desejada é desativar o suporte a ping broadcasts,
    #um recurso que tem poucos usos legítimos e pode ser usado para fazer
    #com que servidores participem involuntariamente de ataques DoS,
    #enviando grandes quantidades de pings a outros servidores dentro da
    #mesma faixa de endereços. Ele já vem desativado em quase todas as distribuições atuais,
    #mas não custa verificar:

    echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

    #Mais uma opção que é importante manter desativada é o suporte ao source routing.
    #Este é um recurso usado para testes de roteadores, que permite ao emissor especificar
    #qual o caminho que o pacote tomará até o destino e também o caminho de volta.
    #Ele é perigoso, pois permite falsear pacotes, fazendo com que eles pareçam vir de
    #outro endereço e, ao mesmo tempo, fazer com que as respostas realmente sejam recebidas,
    #permitindo abrir a conexão e transferir dados. Em outras palavras, se você incluiu
    #regras que permitem o acesso de terminados endereços e esqueceu o suporte ao source
    #routing ativo, um atacante que soubesse quais são os endereços autorizados poderia
    #abrir conexões com o seu servidor se fazendo passar por um deles, um risco que você
    #com certeza gostaria de evitar. Como o recurso não possui outros usos legítimos,
    #é fortemente recomendável que você o mantenha desativado:

    echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route

    #No Linux, isso pode ser evitado de forma bastante simples, ativando o uso de SYN Cookies,
    #um recurso oferecido diretamente pelo Kernel, o que é feito com o comando abaixo, que pode
    #ser incluído no seu script de firewall:

    echo 1 > /proc/sys/net/ipv4/tcp_syncookies

    ###########################################
    ############ compartilha link #############
    ###########################################

    echo "compartilha link de internet [ok]"
    $IPT -t nat -A POSTROUTING -o $IF_WAN -j MASQUERADE

    echo "habilitando encaminhamento de pacotes [ok]"
    echo 1 > /proc/sys/net/ipv4/ip_forward

    ###########################################################
    ############# testes que devem ser apagados depois ######## #Nesse campo usei apenas para testes temporarios no meu FW
    ###########################################################

    echo "libera HTTP na WAN [ok]"
    $IPT -A INPUT -p tcp --dport 80 -j LOG --log-level 4 --log-prefix 'HTTP_WAN > '
    $IPT -A INPUT -p tcp -i $IF_WAN --dport 80 -j ACCEPT
}

function LiberaFirewall(){

    echo "politica Libera TUDO"

    $IPT -P INPUT ACCEPT
    $IPT -P OUTPUT ACCEPT
    $IPT -P FORWARD ACCEPT

    #########################################
    # configurando interfaces
    #########################################

    ifconfig $IF_LAN $IP_LAN
    route del default
    route add default gw $IP_GW

    #########################################

    echo "apaga as regras ja existentes"
    $IPT -F
    $IPT -X
    $IPT -Z
    $IPT -t nat -F
    $IPT -t nat -X
    $IPT -t nat -Z

    ########## compartilha link ###############
    echo "compartilha link de internet [ok]"
    $IPT -t nat -A POSTROUTING -o $IF_WAN -j MASQUERADE

    echo "habilitando encaminhamento de pacotes [ok]"
    echo 1 > /proc/sys/net/ipv4/ip_forward
}

case $1 in
    start)
        IniciaFirewall
        exit 0
    ;;
    stop)
        LiberaFirewall
        exit 1
    ;;
    restart)
        LiberaFirewall;IniciaFirewall
        exit 2
    ;;
    *)
        echo
        echo "Use ||start|| para iniciar as regras desse Firewall, ||restart|| para reiniciar e ||stop|| para descartar todas as politicas de seguranca, NAO FACA ISSO!"
        echo
        exit 3
    ;;
esac

# FIM: tudo que não for explicitamente permitido será negado!
