@load base/frameworks/notice

module CyberCity;

export {

    redef enum Notice::Type += {

        #
        # Scan Detection
        #

        Scan_Detected,
        Slow_Scan_Detected,

        #
        # SSH Detection
        #

        SSH_Auth_Failed,
        SSH_Bruteforce,

        #
        # Beacon Detection
        #

        Beacon_Detected,

        #
        # Web Enumeration
        #

        Web_Enumeration,

        #
        # SMB Enumeration
        #

        SMB_Enumeration,

        #
        # winRM Enumeration
        #

        WinRM_Enumeration,

        #
        # WinRM_Client_Detect
        #

        WinRM_Client_Detected,

        #
        # LDAP
        #

        LDAP_Enumeration,
        LDAP_User_Discovery,
        LDAP_Group_Discovery,
        LDAP_Computer_Discovery,
        LDAP_Privilege_Enumeration,
        LDAP_Kerberoast_Recon,
        BloodHound_Collection,

        #
        # Kerberos
        #
        Kerberos_User_Enumeration,
        Kerberos_Password_Spray,
        Kerberoast_Recon,
        AD_Attack_Chain,

        #
        # RDP Detection
        #
        RDP_Enumeration,
        RDP_Bruteforce,

        #
        # DNS Enumeration
        #

        DNS_Enumeration,

        #
        # RPC Detect
        #

        RPC_Enumeration,
        RPC_LSARPC,
        RPC_SAMR,
        AD_RPC_Enumeration,

        #
        # NTLM Relay detect
        #

        NTLM_Relay_Detected,
        NTLM_Multi_Target_Relay,
        NTLM_HTTP_SMB_Relay,
        NTLM_LDAP_Relay,
        NTLM_Relay_Listener,
        NTLM_Relay_Outbound,

        #
        # pass the hash detect
        #

        PtH_Detected,
        PtH_Exec,
        PtH_Lateral_Movement,
 };

}