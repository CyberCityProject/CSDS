@load /opt/cybercity/zeek/scripts/cybercity_whitelist.zeek
@load /opt/cybercity/zeek/scripts/correlation_globals.zeek
@load /opt/cybercity/zeek/scripts/ad_attack_chain.zeek
@load policy/tuning/json-logs.zeek
@load /opt/cybercity/zeek/scripts/beacon_detect.zeek
@load /opt/cybercity/zeek/scripts/ssh_watch.zeek
@load /opt/cybercity/zeek/scripts/scan_detect.zeek
@load /opt/cybercity/zeek/scripts/bruteforce_detect.zeek
@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/slow_scan_detect.zeek
@load /opt/cybercity/zeek/scripts/web_enum_detect.zeek
@load /opt/cybercity/zeek/scripts/smb_enum_detect.zeek
#@load /opt/cybercity/zeek/scripts/smb_debug.zeek
@load /opt/cybercity/zeek/scripts/winrm_enum_detect.zeek
@load /opt/cybercity/zeek/scripts/winrm_http_detect.zeek
@load /opt/cybercity/zeek/scripts/ldap_enum_detect.zeek
#@load /opt/cybercity/zeek/scripts/ldap_test.zeek
#@load /opt/cybercity/zeek/scripts/krb_debug.zeek
@load /opt/cybercity/zeek/scripts/kerberos_detect.zeek
#@load /opt/cybercity/zeek/scripts/rdp_debug.zeek
@load /opt/cybercity/zeek/scripts/rdp_detect.zeek
@load /opt/cybercity/zeek/scripts/dns_enum_detect.zeek
#@load /opt/cybercity/zeek/scripts/rpc_debug.zeek
@load /opt/cybercity/zeek/scripts/rpc_enum_detect.zeek
#@load /opt/cybercity/zeek/scripts/rpc_dcsync_debug.zeek
@load /opt/cybercity/zeek/scripts/dcsync_detect.zeek
@load /opt/cybercity/zeek/scripts/ntlm_relay_detect.zeek
@load /opt/cybercity/zeek/scripts/pth_detect.zeek
@load /opt/cybercity/zeek/scripts/ftp_bruteforce_detect.zeek
redef LogAscii::use_json = T;

redef ignore_checksums = T;