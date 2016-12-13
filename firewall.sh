#!/bin/bash                                                                                                               
#############################################
#      Autor:Douglas Q. dos Santos                                                                          
#      Data:24/07/2009                 
#      E-mail: douglashx@gmail.com                                                                          
#      Scripts para configuração de firewall                                                                                          
#############################################
#############################################
#Servicos utilizados neste servidor	                                                                    
#############################################
#############################################
#Serviços TCP	
#############################################
#DNS,HTTP,SMTP,POP,IMAP,IMAPS,POP3S
SRV_TCP="53,80,25,110,143,995,993"
#############################################
#Serviço UDP
#############################################
SRV_UDP="53"
#############################################
#Configuração do RANGE da LAN
#############################################
LAN=192.168.0.0/24
#############################################
#Caminho do comando iptables
#############################################
IPT=/sbin/iptables

case $1 in

	start)
	echo -e "[         Iniciando Firewall         ]"
	#####################################
	#Ativa o Modulo o iptables	                                                       
	#####################################
	modprobe iptable_nat
	#####################################
	#Ativa o ip_forward                                                                       
	#####################################
	echo 1 > /proc/sys/net/ipv4/ip_forward
	#####################################
	#Desativa o suporte icmp redirects                                               
	#####################################
	echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
	#####################################
	#Ativa o ping broadcast                                                                  
	#####################################
	echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
	#####################################
	#Desativa source routing                                                                
	#####################################
	echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
	#####################################
	#Desativa SYN cookies                                                                   
	#####################################
	echo 1 > /proc/sys/net/ipv4/tcp_syncookies
	#####################################
	#Ativa rp_filter resp mesma interface                                          
	#####################################
	echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter
	#####################################
	#Define politicas default	                                                       
	#####################################
	$IPT -P INPUT DROP 
	$IPT -P OUTPUT ACCEPT
	$IPT -P FORWARD DROP
	#####################################
	#Limpa todas as regras		                                                       
	#####################################
	$IPT -t filter -F
	$IPT -t nat -F
	$IPT -t mangle -F
	$IPT -t raw -F
	#####################################
	#Liberar pacotes pertencentes a	                                           
	#conexões permitidas		                                                      
	#####################################
	$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	$IPT -A INPUT -i lo -j ACCEPT
	#####################################
	#Libera a internet para acessar os seguintes serviços                
	#####################################
	$IPT -A INPUT -p tcp -m multiport --dports $SRV_TCP -j ACCEPT
	$IPT -A INPUT -p udp --dport $SRV_UDP -j ACCEPT
	$IPT -A INPUT -p tcp -s $LAN --dport 22 -j ACCEPT
	#####################################
	#Hosts com acesso irrestrito. controlando por mac e ip               
	#####################################
	$IPT -A FORWARD -m mac --mac-source 00:00:00:00:00:00 -s 192.168.0.179 -j ACCEPT 
	$IPT -A INPUT -m mac --mac-source 00:00:00:00:00:00 -s 192.168.0.179 -j ACCEPT	
	####################################
	#Libera pings			                                                    
	####################################
	$IPT -A INPUT -p icmp --icmp-type 0 -m length --length :84 -m limit --limit 2/sec -j ACCEPT
	$IPT -A INPUT -p icmp --icmp-type 8 -m length --length :84 -m limit --limit 2/sec -j ACCEPT
	$IPT -A INPUT -m limit --limit 2/sec -p icmp --icmp-type 3 -j ACCEPT
	$IPT -A INPUT -m limit --limit 2/sec -p icmp --icmp-type 5 -j ACCEPT
	$IPT -A INPUT -m limit --limit 2/sec -p icmp --icmp-type 11 -j ACCEPT
	$IPT -A INPUT -m limit --limit 2/sec -p icmp --icmp-type 12 -j ACCEPT
	echo -e "[         Firewall Iniciado        ]"
	;;
	stop)
	echo -e "[       Parando Firewall ...      ]";
	####################################
	#Define políticas default.         
	####################################
	$IPT -P INPUT ACCEPT
	$IPT -P OUTPUT ACCEPT
	$IPT -P FORWARD ACCEPT
	####################################
	#Limpando todas as regras         
	####################################
	$IPT -t filter -F
	$IPT -t nat -F
	$IPT -t mangle -F
	$IPT -t raw -F
	####################################
	echo -e " [       Firewall Parado          ] ";
	;;

	status)
	echo -e "########################################################################################";
	echo -e "*******************************************Table Filter*********************************************";
	$IPT -t filter -L -n
	echo -e "########################################################################################";
	echo -e "*******************************************Table Nat***********************************************";
	$IPT -t nat -L -n
	echo -e "########################################################################################";
	echo -e "*******************************************Table Mangle********************************************";
	$IPT -t mangle -L -n
	echo -e "########################################################################################";
	echo -e "*******************************************Table Raw***********************************************";
	$IPT -t raw -L -n

	;;

	restart)
	  $0 stop
	  $0 start
	;;

	*)
	echo "Opcoes Validas:(start|stop|restart|status)"
	;;

esac
