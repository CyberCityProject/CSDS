#!/bin/bash

#
# CSDS Cleanup
#

DB="/opt/cybercity/db/cybercity.db"

LOG_DIR="/opt/cybercity/zeek/logs"

echo "[*] CSDS Cleanup Started"

#
# Delete alerts older than 30 days
#

sqlite3 $DB "

DELETE FROM alerts

WHERE timestamp < datetime(
    'now',
    '-30 days'
);
"

#
# Compress old logs
#

find $LOG_DIR \
-name "*.log" \
-size +10M \
-exec gzip {} \;

#
# Delete compressed logs older than 30 days
#

find $LOG_DIR \
-name "*.gz" \
-mtime +30 \
-delete

echo "[+] Cleanup Finished"
