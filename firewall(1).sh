#!/bin/bash
/etc/init.d/bind9 restart
/etc/init.d/squid restart

# carrega modulos
/sbin/modprobe iptable_nat
/sbin/modprobe ip_conntrack
/sbin/modprobe ip_conntrack_ftp
/sbin/modprobe ip_nat_ftp
/sbin/modprobe ipt_LOG
/sbin/modprobe ipt_REJECT
/sbin/modprobe ipt_MASQUERADE

# habilita roteamento no kernel
echo 1 >/proc/sys/net/ipv4/ip_forward

# protecao contra spoofing
echo "1" > /proc/sys/net/ipv4/conf/all/rp_filter

# protecao contra spoofing 2
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

# limpa as tabelas existentes
iptables -F
iptables -t mangle -F
iptables -t nat -F
iptables -X

# politica padrao
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

# conexoes preestabelecidas
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT

# libera interface loopback
iptables -A INPUT -i lo -j ACCEPT

# Registro de logs
iptables -A INPUT -p tcp --dport 333 --syn -j LOG --log-prefix="[TENTATIVA ACESSO FWLOGWATCH]"
iptables -A INPUT -p tcp --dport 23 --syn -j LOG --log-prefix="[TENTATIVA ACESSO TELNET]"
iptables -A INPUT -p tcp --dport 10000 --syn -j LOG --log-prefix="[TENTATIVA ACESSO WEBMIN]"
iptables -A FORWARD -m multiport -p tcp --dport 5800,5900,6000 -j LOG --log-prefix="[ACESSO VNC]"
iptables -A INPUT -p tcp --dport 22 --syn -j LOG --log-prefix="[TENTATIVA ACESSO SSH]"
iptables -A INPUT -p tcp --dport 2222 --syn -j LOG --log-prefix="[TENTATIVA ACESSO SSH]"
iptables -A INPUT -p tcp --dport 21 --syn -j LOG --log-prefix="[TENTATIVA ACESSO FTP]"

################################################################################ REGRAS DE SEGURANÇA
#
###############################################################################

# Protege contra port scanners
iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 5/s -j ACCEPT

# proteção contra traceroute
iptables -A INPUT -p udp -s 0/0 -i eth3 --dport 33435:33525 -j REJECT

# Protecoes contra pacotes invalidos
iptables -A INPUT -m state --state INVALID -j REJECT

###############################################################################
# REGRAS PARA INPUT
#
###############################################################################
# liberando Servidor DNS
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT

# libera proxy squid pelo navegador
iptables -A INPUT -s 192.168.0.0/24 -p tcp --dport 3128 -j ACCEPT
iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 3128 -j ACCEPT
iptables -A INPUT -s 192.168.2.0/24 -p tcp --dport 3128 -j ACCEPT
iptables -A INPUT -s 192.168.3.0/24 -p tcp --dport 3128 -j ACCEPT
iptables -A INPUT -s 192.168.4.0/24 -p tcp --dport 3128 -j ACCEPT

# libera ping para rede do piso 1 
iptables -A INPUT -s 192.168.1.0/24 -p icmp --icmp-type 8 -j ACCEPT

# libera ssh para piso 1 e bloqueia todo o resto
#iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT

# libera ssh externamente
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# libera acesso ao WEBMIN para o piso 1
iptables -A INPUT -p tcp --dport 10000 -j ACCEPT

# libera acesso ao fwlogwatch para o piso 1
iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 333 -j ACCEPT

# bloqueia todo o resto
iptables -A INPUT -p tcp --syn -j DROP
iptables -A INPUT -p tcp -j DROP

################################################################################ REGRAS VLANS e DMZ (FORWARD)
#
###############################################################################

# libera portas ctvoicer
iptables -A FORWARD -d 192.168.0.8/24 -p tcp -m multiport --dport 3050,10014,10010 -j ACCEPT

#liberado ping para rede piso 1 (qualquer destino)
iptables -A FORWARD -s 192.168.1.0/24 -p icmp --icmp-type echo-request -j ACCEPT
iptables -A FORWARD -s 192.168.1.0/24 -p icmp --icmp-type echo-reply -j ACCEPT

# libera portas rede piso 1
iptables -A FORWARD -i eth0.10 -p tcp -m multiport --dport 53,137,138,139,110,25,22,2222,995,465,5800,5900,6000 -j ACCEPT
iptables -A FORWARD -i eth0.10 -p udp -m multiport --dport 53,137,138,139,110,25,22,995,465 -j ACCEPT

# regras para o webserver
iptables -A FORWARD -d 192.168.0.253/24 -p tcp -m multiport --dport 80,8080 -j ACCEPT
iptables -A FORWARD -d 192.168.0.253/24 -p udp -m multiport --dport 80,8080 -j ACCEPT
iptables -A FORWARD -s 192.168.1.0/24 -d 192.168.1.0/24 -p tcp -m multiport --dport 137,138,139 -j ACCEPT
iptables -A FORWARD -s 192.168.1.0/24 -d 192.168.1.0/24 -p udp -m multiport --dport 137,138,139 -j ACCEPT

# regras para servidor de email
iptables -A FORWARD -d 192.168.0.254/24 -p tcp -m multiport --dport 995,465,110,25,143 -j ACCEPT
iptables -A FORWARD -d 192.168.0.254/24 -p udp -m multiport --dport 995,465,110,25,143 -j ACCEPT

# regras para o asterisk
iptables -A FORWARD -d 192.168.0.250/24 -p tcp --dport 5060 -j ACCEPT
iptables -A FORWARD -d 192.168.0.250/24 -p udp --dport 5060 -j ACCEPT
iptables -A FORWARD -d 192.168.0.250/24 -p udp --dport 10000:20000 -j ACCEPT

# regras para servidor samba
iptables -A FORWARD -i eth0 -d 192.168.0.127/24 -p tcp -m multiport --dport 137,138,139 -j ACCEPT
iptables -A FORWARD -i eth0 -d 192.168.0.127/24 -p udp -m multiport --dport 137,138,139 -j ACCEPT

# regras para serv-adm2
iptables -A FORWARD -d 192.168.0.252/24 -p tcp --dport 3389 -j ACCEPT
iptables -A FORWARD -d 192.168.0.252/24 -p udp --dport 3389 -j ACCEPT

# regras de forward para vnc piso 1
iptables -A FORWARD -s 192.168.1.0/24 -p tcp -m multiport --dport 5800,5900,6000 -j ACCEPT

###############################################################################
# REGRAS PARA NAT
#
###############################################################################

# redirecionando acesso ao servidor VOIP
iptables -t nat -A PREROUTING -d 200.195.YYY.YYY -j DNAT --to 192.168.0.250

# redirecionado pop e smtp
iptables -t nat -A PREROUTING -d 200.195.ZZZ.ZZZ -p tcp -m tcp --dport 110 -j DNAT --to-destination 192.168.0.254:110
iptables -t nat -A PREROUTING -d 200.195.ZZZ.ZZZ -p tcp -m tcp --dport 25 -j DNAT --to-destination 192.168.0.254:25

# redirecionando acesso ao servidor web via rede local e internet
iptables -t nat -A PREROUTING -s 200.195.KKK.KKK -p tcp --dport 80 -j DNAT --to 192.168.0.253

# redireciona acesso terminal service para serv-adm
iptables -t nat -A PREROUTING -d 200.195.ZZZ.ZZZ -p tcp --dport 3389 -j DNAT --to 192.168.0.252

# redireciona acesso vnc
iptables -t nat -A PREROUTING -d 200.139.XXX.XXX -p tcp --dport 5900 -j DNAT --to 192.168.0.8

# acesso vnc gabriel
iptables -t nat -A PREROUTING -d 200.139.XXX.XXX -p tcp --dport 6000 -j DNAT --to 192.168.1.2

# acesso vnc gerson
iptables -t nat -A PREROUTING -d 200.139.XXX.XXX -p tcp --dport 6001 -j DNAT --to 192.168.1.3

# ativando proxy transparente
#iptables -t nat -A PREROUTING -p tcp -s 192.168.0.0/24 --dport 80 -j REDIRECT --to-ports 3128

# ativando masquerade
iptables -t nat -A POSTROUTING -p all -s 192.168.1.2 -o eth3 -j SNAT --to-source 200.139.XXX.XXX

# ativando SNAT
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -m multiport -p tcp --dport 53,110,25,22,2222,995,465,5800,5900,6000 -o eth3 -j SNAT --to-source 200.139.XXX.XXX
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -m multiport -p udp --dport 53,110,25,22,995,465 -j SNAT --to-source 200.139.XXX.XXX
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -p icmp -o eth3 -j SNAT --to-source 200.139.XXX.XXX

###############################################################################

# priorizando pacotes da rede
iptables -t mangle -A PREROUTING -p tcp --dport 5060 -j TOS --set-tos 16
iptables -t mangle -A PREROUTING -p udp --dport 1000:20000 -j TOS --set-tos 8
iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TOS --set-tos 8
iptables -t mangle -A PREROUTING -p udp --dport 80 -j TOS --set-tos 8
iptables -t mangle -A OUTPUT -o eth3 -p tcp --dport 5060 -j TOS --set-tos 16
iptables -t mangle -A OUTPUT -o eth3 -p udp --dport 10000:20000 -j TOS --set-tos 8
iptables -t mangle -A OUTPUT -o eth3 -p tcp --dport 80 -j TOS --set-tos 8
iptables -t mangle -A OUTPUT -o eth3 -p udp --dport 80 -j TOS --set-tos 8

# balanceamento dos links gvt e copel realizado por serviços
#link1 copel 8mb
#link2 gvt 2mb

#echo 10 link1 >>/etc/iproute2/rt_tables
#echo 20 link2 >>/etc/iproute2/rt_tables

#iptables -t mangle -A PREROUTING -p tcp --dport 443 -j MARK --set-mark 3
#iptables -t mangle -A PREROUTING -p tcp --dport 80 -j MARK --set-mark 3
#iptables -t mangle -A PREROUTING -p tcp --dport 5060 -j MARK --set-mark 3
#iptables -t mangle -A PREROUTING -p tcp --dport 21 -j MARK --set-mark 4
#iptables -t mangle -A PREROUTING -p tcp --dport 25 -j MARK --set-mark 4
#iptables -t mangle -A PREROUTING -p tcp --dport 110 -j MARK --set-mark 4
#iptables -t mangle -A PREROUTING -p tcp --dport 5800:6000 -j MARK --set-mark 4
#iptables -t mangle -A PREROUTING -p tcp --dport 3306 -j MARK --set-mark 4
#ip rule add fwmark 3 table link1
#ip rule add fwmark 4 table link2
#ip route add default via 200.195.XXX.XXX table link1
#ip route add default via 200.139.XXX.XXX table link2
