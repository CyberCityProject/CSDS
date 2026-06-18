module CyberCity;

export {

    #
    # Discovery
    #

    global ad_dns_seen: table[addr] of bool
        &default=F;

    global ad_ldap_seen: table[addr] of bool
        &default=F;

    #
    # Enumeration
    #

    global ad_smb_seen: table[addr] of bool
        &default=F;

    global ad_rpc_seen: table[addr] of bool
        &default=F;

    #
    # Credential Access
    #

    global ad_kerberos_seen: table[addr] of bool
        &default=F;

    global ad_asreproast_seen: table[addr] of bool
        &default=F;

    global ad_kerberoast_seen: table[addr] of bool
        &default=F;

    #
    # Domain Dominance
    #

    global ad_dcsync_seen: table[addr] of bool
        &default=F;

    #
    # Lateral Movement
    #

    global ad_winrm_seen: table[addr] of bool
        &default=F;

    global ad_rdp_seen: table[addr] of bool
        &default=F;

    #
    # AD Attack Chain Stages
    #

    global ad_stage1_seen: table[addr] of bool
        &default=F;

    global ad_stage2_seen: table[addr] of bool
        &default=F;

    global ad_stage3_seen: table[addr] of bool
        &default=F;

    global ad_campaign_seen: table[addr] of bool
        &default=F;

    #
    # NTLM Relay
    #
    global ad_ntlm_relay_seen: table[addr] of bool &default=F;

    #
    # pass th hash
    #
    global ad_pth_seen: table[addr] of bool &default=F;

}