#!/bin/bash

ZEEK=$(which zeek)

cd /opt/cybercity/zeek/logs

$ZEEK \
-C \
-i eth0 \
/opt/cybercity/zeek/config/local.zeek \
/opt/cybercity/zeek/scripts/scan_detect.zeek \
/opt/cybercity/zeek/scripts/beacon_detect.zeek
