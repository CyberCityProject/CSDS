#!/bin/bash

LOG="/var/log/cybercity_watchdog.log"

echo "[$(date)] Watchdog check" >> $LOG

#
# ZEEK
#

if ! pgrep -x zeek >/dev/null
then

    echo "[$(date)] Zeek DOWN - restarting" >> $LOG

    nohup /opt/cybercity/zeek/start_zeek.sh \
    >/dev/null 2>&1 &

fi

#
# WEBSOCKET
#

if ! pgrep -f server.js >/dev/null
then

    echo "[$(date)] WebSocket DOWN - restarting" >> $LOG

    nohup node /opt/cybercity/ws/server.js \
    >/dev/null 2>&1 &

fi

#
# APACHE
#

if ! pgrep httpd >/dev/null
then

    echo "[$(date)] Apache DOWN - restarting" >> $LOG

    /etc/rc.d/rc.httpd start

fi

#
# SQLite Importer
#

if ! pgrep -f alert_importer.py >/dev/null
then

    echo "[WATCHDOG] Restarting SQLite Importer"

    nohup python3 \
    /opt/cybercity/scripts/alert_importer.py \
    >/dev/null 2>&1 &

fi
