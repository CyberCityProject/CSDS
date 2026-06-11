#!/bin/bash

IP=$1

if grep -q "$IP" /opt/cybercity/firewall/whitelist.txt
then
    logger "CyberCity WHITELIST BYPASS $IP"
    exit
fi

if grep -q "$IP" /opt/cybercity/firewall/blocked_ips.txt
then
    exit
fi

iptables -w 5 -A INPUT -s $IP -j DROP

echo "$(date) BLOCKED $IP" >> \
/opt/cybercity/firewall/blocked_ips.txt

logger "CyberCity BLOCKED IP $IP"
