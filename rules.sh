#!/bin/sh
d=$(date +%Y-%m-%d)

# Clear rules
iptables -t filter -F
iptables -t filter -X

# Deny all
iptables -t filter -P INPUT DROP
iptables -t filter -P FORWARD DROP
iptables -t filter -P OUTPUT DROP

# READY ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# loop-back local
iptables -t filter -A INPUT -i lo -j ACCEPT
iptables -t filter -A OUTPUT -o lo -j ACCEPT

# Stop ping
#iptables -t filter -A INPUT -p icmp -j ACCEPT
iptables -t filter -A OUTPUT -p icmp -j ACCEPT

echo 1 > /proc/sys/net/ipv4/ip_forward

# Ssh 
iptables -t filter -A INPUT -p tcp --dport 8600 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 8600 -j ACCEPT

# Http
#iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
#iptables -t filter -A OUTPUT -p tcp --dport 80 -j ACCEPT

#Https
iptables -t filter -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 443 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 443 -j ACCEPT

#Mailing 
iptables -t filter -A INPUT -p tcp --dport 25 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 25 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 25 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 25 -j ACCEPT

iptables -t filter -A INPUT -p tcp --dport 26 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 26 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 26 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 26 -j ACCEPT

iptables -t filter -A INPUT -p tcp --dport 110 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 110 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 110 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 110 -j ACCEPT

iptables -t filter -A INPUT -p tcp --dport 143 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 143 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 143 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 143 -j ACCEPT

iptables -t filter -A INPUT -p tcp --dport 587 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 587 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 465 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 465 -j ACCEPT

# Dns
iptables -t filter -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 53 -j ACCEPT

# Ntp
iptables -t filter -A OUTPUT -p udp --dport 123 -j ACCEPT

# Forward
iptables -A FORWARD -p tcp --syn -m limit --limit 1/second -j ACCEPT
iptables -A FORWARD -p udp -m limit --limit 1/second -j ACCEPT
iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# Reject spoofed packets
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP

iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP


# Drop all unknow packets
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP

# Drop smurf attacks
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# Stop scan
iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

# Stop portscan listing
iptables -A INPUT   -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove

# Rules scanner
iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

# Drop all invalid packets
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP

# Set limit packets
iptables -A INPUT -p tcp --syn -m limit --limit 2/s --limit-burst 30 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags ALL NONE -m limit --limit 1/h -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags ALL ALL -m limit --limit 1/h -j ACCEPT


# Mysql
iptables -t filter -A INPUT -p tcp --dport 3306 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 3306 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 3306 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 3306 -j ACCEPT


# Range port's 
#iptables -t filter -A OUTPUT -p udp --dport 9986:10288 -j ACCEPT
#iptables -t filter -A INPUT -p udp --dport 9986:10288 -j ACCEPT

# Http Flooding x)
iptables -N http-flood
iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 1 -j http-flood
iptables -A INPUT -p tcp --syn --dport 443 -m connlimit --connlimit-above 1 -j http-flood
iptables -A http-flood -m limit --limit 10/s --limit-burst 10 -j RETURN
iptables -A http-flood -m limit --limit 1/s --limit-burst 10 -j LOG --log-prefix "HTTP-FLOODINGGGGGGGGGGGGGG"
iptables -A http-flood -j DROP

iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 20 -j DROP
iptables -A INPUT -p tcp --syn --dport 443 -m connlimit --connlimit-above 20 -j DROP
iptables -A INPUT -p tcp --dport 80 -i eth0 -m state --state NEW -m recent --set
iptables -I INPUT -p tcp --dport 80 -m state --state NEW -m recent --update --seconds 10 --hitcount 20 -j DROP
iptables -A INPUT -p tcp --dport 443 -i eth0 -m state --state NEW -m recent --set
iptables -I INPUT -p tcp --dport 443 -m state --state NEW -m recent --update --seconds 10 --hitcount 20 -j DROP
iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 13 -j DROP
iptables -N flood
iptables -A flood -j LOG --log-prefix "FLOOD"
iptables -A flood -j DROP

iptables -t filter -N syn-flood
iptables -t filter -A INPUT -i eth0 -p tcp --syn -j syn-flood
iptables -t filter -A syn-flood -m limit --limit 1/sec --limit-burst 4 -j RETURN
iptables -t filter -A syn-flood -j LOG \
--log-prefix "IPTABLES SYN-FLOOD:"
iptables -t filter -A syn-flood -j DROP

iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -t mangle -A PREROUTING -p icmp -j DROP
iptables -A INPUT -p tcp -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP
iptables -t mangle -A PREROUTING -f -j DROP
iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP
iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP

#Ftp
iptables -t filter -A OUTPUT -p udp --dport 30110:30210 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 30110:30210 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 30110:30210 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 30110:30210 -j ACCEPT
iptables -A INPUT -p tcp --match multiport --dports 30110:30210 -j ACCEPT
iptables -A INPUT -p udp --match multiport --dports 30110:30210 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 21 -j ACCEPT
iptables -t filter -A INPUT -p udp --dport 21 -j ACCEPT

iptables -t filter -A INPUT -p udp --dport 21 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 21 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 21 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 21 -j ACCEPT

# Web panel
iptables -A INPUT -p tcp -m tcp --dport 8112 -j ACCEPT

iptables -t filter -A INPUT -p udp --dport 8112 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 8112 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 8112 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 8112 -j ACCEPT

iptables -t filter -A INPUT -p udp --dport 58846 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 58846 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 58846 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 58846 -j ACCEPT

iptables -t filter -A INPUT -p udp --dport 44729 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 44729 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 44729 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 44729 -j ACCEPT

iptables -t filter -A INPUT -p udp --dport 58391 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 58391 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 58391 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 58391 -j ACCEPT

iptables -t filter -A INPUT -p udp --dport 58846 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 58846 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 58846 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 58846 -j ACCEPT


iptables -t filter -A INPUT -p udp --dport 6969 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 6969 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 6969 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 6969 -j ACCEPT

# OpenVPN

iptables -t filter -A INPUT -p udp --dport 1194 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 1194 -j ACCEPT

iptables -t filter -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 443 -j ACCEPT

# TCP Port number:

iptables -t filter -A INPUT -p udp --dport 7841 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 7841 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 7841 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 7841 -j ACCEPT

# UDP Port number:
iptables -t filter -A INPUT -p udp --dport 7842 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 7842 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 7842 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 7842 -j ACCEPT

# OpenVPN

iptables -t filter -A INPUT -p udp --dport 9988 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 9988 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 9988 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 9988 -j ACCEPT


iptables -t filter -A INPUT -p udp --dport 9981 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 9981 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 9981 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 9981 -j ACCEPT

iptables -t filter -A INPUT -p udp --dport 9982 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 9982 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 9982 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 9982 -j ACCEPT

iptables -t filter -A INPUT -p udp --dport 9983 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 9983 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 9983 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 9983 -j ACCEPT

iptables -t filter -A INPUT -p udp --dport 50375 -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 50375 -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 50375 -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport 50375 -j ACCEPT


echo "[OK] Rules Successfully Updated"
echo

echo 

########################### IPTABLES MANUEL ###########################################

echo "[TCP/UDP] rule n°1 :"
read PORT1

iptables -t filter -A INPUT -p udp --dport "$PORT1" -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport "$PORT1" -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport "$PORT1" -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --dport "$PORT1" -j ACCEPT
echo
echo "Port Successfully Add"
echo