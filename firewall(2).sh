#!/bin/bash
 iniciar(){

 #Configuraç do Firewall atravédo iptables
 #Autoria do Script
 #"::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
 #"| Script de Firewall - IPTABLES"
 #"| Criado por: Guilherme Ribeiro"
 #"| Analista de Redes"
 #"| gustavo.ti@hotmail.com.br"
 #"| Uso: firewall start|stop|restart"
 #"::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"

 #mensagem de inicializaçao
 echo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
 echo "| Script de Firewall - IPTABLES"
 echo "| Criado por: Guilherme Ribeiro"
 echo "| Analista de Redes"
 echo "| gustavo.ti@hotmail.com.br"
 echo "| Uso: firewall start|stop|restart"
 echo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
 echo
 echo "=========================================================|"
 echo "|:INICIANDO A CONFIGURA� DO FIREWALL NETFILTER ATRAV�|"
 echo "|:                    DO IPTABLES                       :|"
 echo "=========================================================|"

#iniciar(){

 # Móos #
 modprobe ip_tables
 modprobe ip_conntrack
 modprobe iptable_filter
 modprobe iptable_mangle
 modprobe iptable_nat
 modprobe ipt_LOG
 modprobe ipt_limit
 modprobe ipt_state
 modprobe ipt_REDIRECT
 modprobe ipt_owner
 modprobe ipt_REJECT
 modprobe ipt_MASQUERADE
 modprobe ip_conntrack_ftp
 modprobe ip_nat_ftp
#Limpa as regras #
 iptables -X
 iptables -Z
 iptables -F INPUT
 iptables -F OUTPUT
 iptables -F FORWARD
 iptables -F -t nat
 iptables -F -t mangle

# Politicas padrao #
iptables -t filter -P INPUT DROP
iptables -t filter -P OUTPUT ACCEPT
iptables -t filter -P FORWARD DROP
iptables -t nat -P PREROUTING ACCEPT
iptables -t nat -P OUTPUT ACCEPT
iptables -t nat -P POSTROUTING ACCEPT
iptables -t mangle -P PREROUTING ACCEPT
iptables -t mangle -P OUTPUT ACCEPT

#Compartilhar conexãecho
echo 1 > /proc/sys/net/ipv4/ip_forward
echo ".ativando o redirecionamento no arquivo ip_forward."
echo ".ON .........................................................................................[OK]."

# Manter conexoes jah estabelecidas 
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Aceita todo o trafego vindo do loopback e indo pro loopback
iptables -t filter -A INPUT -i lo -j ACCEPT
#####################
### LOG DO FIREWALL ###
#######################

iptables -A INPUT -d 192.168.1.1 -p tcp --dport 227 -j LOG --log-level 6 --log-prefix "FIREWALL: SSH EXT 22"
iptables -A INPUT -d 192.168.1.1 -p tcp --dport 21 -j LOG --log-level 6 --log-prefix "FIREWALL: FTP EXT 21"
iptables -A INPUT -d 192.168.1.0/24 -p tcp --dport 227 -j LOG --log-level 6 --log-prefix "FIREWALL: SSH INT 22"
iptables -A INPUT -d 192.168.1.0/24 -p tcp --dport 21 -j LOG --log-level 6 --log-prefix "FIREWALL: FTP INT 21"


 # Redireconamento de portas
 # sql Para algum micro (192.168.0.102 = nome da pessoa)
 iptables -t nat -A PREROUTING -d 187.115.x.x -p tcp --dport 1433 -j DNAT --to 192.168.1.102:1433
 iptables -t nat -A PREROUTING -d 187.115.x.x -p tcp --dport 1434 -j DNAT --to 192.168.1.102:1434
 iptables -t nat -A PREROUTING -d 187.115.x.x -p udp --dport 1433 -j DNAT --to 192.168.1.102:1433
 iptables -t nat -A PREROUTING -d 187.115.x.x -p udp --dport 1434 -j DNAT --to 192.168.1.102:1434
 iptables -t nat -A PREROUTING -d 187.115.x.x -p tcp --dport 3080 -j DNAT --to 192.168.1.100:3080
 iptables -t nat -A PREROUTING -d 187.115.x.x -p tcp --dport 3389 -j DNAT --to 192.168.1.102:3389
 iptables -t nat -A PREROUTING -d 187.115.x.x -p udp --dport 3389 -j DNAT --to 192.168.1.102:3389
 iptables -t nat -A PREROUTING -d 187.115.x.x -p tcp --dport 80 -j DNAT --to 192.168.1.100:80
 echo .Redirecionamento Ativado
 echo .ON .........................................................................................[OK].

 ###############################
 #       TABELA Input          #
 ###############################
 ### Destino Externo ###

 # Liberando Porta 227 (SSH)
 iptables -A INPUT  -p tcp --dport 227 -j LOG --log-level 6 --log-prefix "FIREWALL: SSH EXT 227"
 iptables -A INPUT  -p tcp --dport 227 -j ACCEPT


iptables -A INPUT -s 192.168.0.1/24 -j ACCEPT
 # Liberando Porta 21 (ftp)
 iptables -A INPUT  -p tcp --dport 21 -j LOG --log-level 6 --log-prefix "FIREWALL: FTP EXT 21"
 iptables -A INPUT  -p tcp --dport 21 -j ACCEPT

 ### Destino Interno ###

 # Liberando Porta 227 (SSH)
 iptables -A INPUT  -p tcp --dport 227 -j LOG --log-level 6 --log-prefix "FIREWALL: SSH INT 227"
 iptables -A INPUT  -p tcp --dport 227 -j ACCEPT

 # Liberando porta 3128 (Squid)
 iptables -A INPUT  -p tcp --dport 3128 -j ACCEPT
# Liberando Porta 80 (http)
 iptables -A INPUT  -p tcp --dport 80 -j LOG --log-level 6 --log-prefix "FIREWALL: HTTP INT 80"
 iptables -A INPUT  -p tcp --dport 80 -j ACCEPT

 # Liberando Porta 21 (ftp)
 iptables -A INPUT  -p tcp --dport 21 -j LOG --log-level 6 --log-prefix "FIREWALL: FTP INT 21"
 iptables -A INPUT  -p tcp --dport 21 -j ACCEPT

 # Liberando porta 3000 (NTOP)
 iptables -A INPUT  -p tcp --dport 3000 -j ACCEPT

 ###############################
 #       TABELA Forward        #
 ###############################
 ## MSN ###
 # Libera msn para o IP #
 # nome
 #iptables -A FORWARD -s 192.168.0.11 -p tcp --dport 1863 -j ACCEPT

 # Bloqueio de MSN #
# iptables -A FORWARD -s 192.168.1.0/24 -p tcp --dport 5190 -j REJECT
# iptables -A FORWARD -s 192.168.0.0/24 -p tcp --dport 1863 -j REJECT
# iptables -A FORWARD -s 192.168.0.0/24 -d loginnet.passport.com -j REJECT
# iptables -A FORWARD -s 198.168.0.0/24 -d loginnet.passport.com -j REJECT
# iptables -A FORWARD -s 198.168.0.0/24 -d messenger.hotmail.com -j REJECT
# iptables -A FORWARD -s 198.168.0.0/24 -d webmessenger.msn.com -j REJECT
# iptables -A FORWARD -p tcp --dport 1080 -j REJECT
 #iptables -A FORWARD -s 198.168.0.0/24 -p tcp --dport 1080 -j REJECT
 #iptables -A FORWARD -p tcp --dport 1863 -j REJECT
# iptables -A FORWARD -d 64.4.13.0/24 -j REJECT

 # Liberando Porta 227 (SSH)
 iptables -A FORWARD -s 192.168.1.0/24 -p tcp --dport 227 -j ACCEPT

 # Liberando Porta 22 (SSH)
 iptables -A FORWARD -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT
 # Liberando Porta 110 (pop-3)
 iptables -A FORWARD -s 192.168.1.0/24 -p tcp --dport 110 -j ACCEPT
 # Liberando Porta 995 (spop-3)
 iptables -A FORWARD -s 192.168.1.0/24 -p tcp --dport 995 -j ACCEPT

 # Liberando Porta 25 (smtp)
 iptables -A FORWARD -s 192.168.1.0/24 -p tcp --dport 25 -j ACCEPT
 #Liberando Porta 465 (smtp-s)
 iptables -A FORWARD -s 192.168.1.0/24 -p tcp --dport 465 -j ACCEPT

 # Liberando Porta 21 (ftp)
 iptables -A FORWARD -s 192.168.1.0/24 -p udp --dport 21 -j ACCEPT
 iptables -A FORWARD -s 192.168.1.0 -p udp --dport 20 -j ACCEPT

 # Liberando porta 53 (DNS)
 iptables -A FORWARD -s 192.168.1.0/24 -p tcp --dport 53 -j ACCEPT
 iptables -A FORWARD -s 192.168.1.0/24 -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -s 192.168.1.0/24 -p tcp --dport 3128 -j ACCEPT

 # Regras forward para o funcionamento de redirecionamento de portas (NAT)
 iptables -A FORWARD -p tcp --dport 1433:1434 -j ACCEPT
 iptables -A FORWARD -p udp --dport 1433:1434 -j ACCEPT
 iptables -A FORWARD -p tcp --dport 3080 -j ACCEPT
 iptables -A FORWARD -p tcp --dport 3389 -j ACCEPT
 iptables -A FORWARD -p udp --dport 3389 -j ACCEPT
 iptables -A FORWARD -p tcp --dport 80 -j ACCEPT
 ### regras de segurançfirewall ####

 iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
 echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
 echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter
 iptables -A INPUT -m state --state INVALID -j DROP
 ### Impedindo ataque Ping of Death no Firewall ####
 iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

 ### Descarte de pacotes nao identificados ICMP ####
 iptables -A OUTPUT -m state -p icmp --state INVALID -j DROP
 iptables -A INPUT -m state -p icmp --state INVALID -j DROP
 iptables -A FORWARD -m state -p icmp --state INVALID -j DROP

 ### Impedindo ataque de Denial Of Service Dos na rede e servidor ####
 iptables -I FORWARD -p tcp -m limit --limit 1/s -j ACCEPT
 iptables -A INPUT -p tcp -m limit --limit 1/s -j ACCEPT
## Impedindo ataque Port Scanners na rede e no Firewall ####
 iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
 iptables -I INPUT -p udp --dport 33435:33525 -j LOG --log-level info --log-prefix 'SCANNERS DROPADO>'
 iptables -A INPUT -p udp --dport 33435:33525 -j DROP
 iptables -I FORWARD -p udp --dport 33435:33525 -j LOG --log-level info --log-prefix 'SCANNERS DROPADO NA REDE>'
 iptables -A FORWARD -p udp --dport 33435:33525 -j DROP

 ### Bloquear Back Orifice na rede ####
 iptables -I INPUT -p tcp --dport 31337 -j LOG --log-level info --log-prefix 'ORIFICE DROPADO>'
 iptables -A INPUT -p tcp --dport 31337 -j DROP
 iptables -I INPUT -p udp --dport 31337 -j LOG --log-level info --log-prefix 'ORIFICE UDP>'
 iptables -A INPUT -p udp --dport 31337 -j DROP
 iptables -I FORWARD -p tcp --dport 31337 -j LOG --log-level info --log-prefix 'ORIFICE NA REDE>'
 iptables -A FORWARD -p tcp --dport 31337 -j DROP
 iptables -I FORWARD -p udp --dport 31337 -j LOG --log-level info --log-prefix 'ORIFICE NA REDE UDP>'
 iptables -A FORWARD -p udp --dport 31337 -j DROP

 ### Bloquear NetBus na rede ####
 iptables -I INPUT -p tcp --dport 12345 -j LOG --log-level info --log-prefix 'NETBUS >'
 iptables -A INPUT -p tcp --dport 12345 -j DROP
 iptables -I INPUT -p udp --dport 12345 -j LOG --log-level info --log-prefix 'NETBUS UDP>'
 iptables -A INPUT -p udp --dport 12345 -j DROP
 iptables -I FORWARD -p tcp --dport 12345 -j LOG --log-level info --log-prefix 'NETBUS NA REDE>'
 iptables -A FORWARD -p tcp --dport 12345 -j DROP
 iptables -I FORWARD -p udp --dport 12345 -j LOG --log-level info --log-prefix 'NETBUS UDP>'
 iptables -A FORWARD -p udp --dport 12345 -j DROP

###Desabilita resposta para pingecho 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all

 ### Desabilita port scan ####
 echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

 ### Desabilita redirecionamento de ICMP ####
 for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do
 echo 0 >$f
 done

 ### Protecao contra synflood ####
 echo "1" > /proc/sys/net/ipv4/tcp_syncookies

 ### Ativando protecao contra responses bogus ####
 echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
### Protecao contra worms ####
 iptables -I FORWARD -p tcp --dport 135 -j LOG --log-level info --log-prefix 'WORMS REDE>'
 iptables -A FORWARD -p tcp --dport 135 -j DROP
 iptables -I INPUT -p tcp --dport 135 -j LOG --log-level info --log-prefix 'WORMS >'
 iptables -A INPUT -p tcp --dport 135 -j DROP

 ### Bloqueando tracertroute ####
 iptables -A INPUT -p udp -s 0/0 -i eth0 --dport 33435:33525 -j REJECT

 ### Permite o redirecionamento seguro dos pacotes ####
 echo "1" > /proc/sys/net/ipv4/conf/all/secure_redirects

 ### IMPEDINDO O REDIRECIONAMENTO E UMA ROTA ####
 echo "0" > /proc/sys/net/ipv4/conf/all/accept_redirects
 echo Seguranca Carregada e logs gerados ..... [ok]

 # Aceita Pacotes Estabilizados ####

 echo Estabilizando Pacotes
 iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
 iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
 iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
 echo Pacotes Estabilizado ..... [ok]

#echo "1" > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp -i eth0 --dport 80 -j REDIRECT --to 3128
iptables -t nat -A POSTROUTING -o ppp0 -j MASQUERADE


 # Mascaramento de rede para acesso externo #
# iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

 #Bloqueia todo o resto
 #iptables -A INPUT -p tcp -j LOG --log-level 6 --log-prefix "FIREWALL: GERAL "
 iptables -A INPUT -p tcp --syn -j DROP
 iptables -A INPUT -p tcp -j DROP
 iptables -A INPUT -p udp -j DROP
 echo "Regras de firewall e compartilhamento desativados"

}

 parar(){
 iptables -F
 iptables -t nat -F
 iptables -P INPUT ACCEPT
 iptables -P OUTPUT ACCEPT
 iptables -P FORWARD ACCEPT
 echo 0 > /proc/sys/net/ipv4/ip_forward
 echo "Regras de firewall e compartilhamento desativados"
 }
 case "$1" in
 "start") iniciar ;;
 "stop") parar ;;
 "restart") parar; iniciar ;;
 *) echo "Use os parâtros start ou stop"
 esac
