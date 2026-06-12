#!/bin/bash

LOG="/opt/cybercity/zeek/logs/system_alerts.log"

#
# CPU LOAD
#

CPU=$(uptime | awk -F'load average:' '{ print $2 }' \
| cut -d',' -f1 | tr -d ' ')

CPU_INT=${CPU%.*}

if [ "$CPU_INT" -ge 4 ]
then

    echo "$(date) HIGH CPU LOAD: $CPU" >> $LOG

fi

#
# MEMORY
#

MEM=$(free | awk '/Mem:/ {printf("%.0f"), $3/$2 * 100.0}')

if [ "$MEM" -ge 80 ]
then

    echo "$(date) HIGH MEMORY USAGE: ${MEM}%" >> $LOG

fi

#
# DISK
#

DISK=$(df / | awk 'END{print $5}' | tr -d '%')

if [ "$DISK" -ge 80 ]
then

    echo "$(date) HIGH DISK USAGE: ${DISK}%" >> $LOG

fi

#
# ZEEK
#

if ! pgrep -x zeek >/dev/null
then

    echo "$(date) ZEEK DOWN" >> $LOG

fi

#
# WEBSOCKET
#

if ! pgrep -f server.js >/dev/null
then

    echo "$(date) WEBSOCKET DOWN" >> $LOG

fi
