@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice
@load /opt/cybercity/zeek/scripts/correlation_globals.zeek
module CyberCity;

event zeek_init()
{
    print "KERBEROS DETECT V1.3 LOADED";
}

#
# Counters
#

global asreq_count: table[addr] of count
    &default=0;

global tgsreq_count: table[addr] of count
    &default=0;

global krb_error_count: table[addr] of count
    &default=0;

global krb_first_seen: table[addr] of time;

#
# Correlation Flags
#

global kerberos_enum_detected: table[addr] of bool
    &default=F;

global kerberos_roast_detected: table[addr] of bool
    &default=F;

#
# Multi-Protocol AD Correlation
#



#
# Anti-Spam Flags
#

global kerberos_enum_alerted: table[addr] of bool
    &default=F;

global kerberos_spray_alerted: table[addr] of bool
    &default=F;

#
# AS-REQ Monitoring
#

event krb_as_request(
    c: connection,
    msg: KRB::KDC_Request
)
{
    local src: addr = c$id$orig_h;

    if ( src !in krb_first_seen )
        krb_first_seen[src] = network_time();

    local delta =
        network_time() -
        krb_first_seen[src];

    #
    # Re-arm after 10 minutes
    #

    if ( delta > 600secs )
    {
        asreq_count[src] = 0;
        tgsreq_count[src] = 0;
        krb_error_count[src] = 0;

        kerberos_enum_detected[src] = F;
        kerberos_roast_detected[src] = F;

        kerberos_enum_alerted[src] = F;
        kerberos_spray_alerted[src] = F;

        krb_first_seen[src] = network_time();

        delta = 0secs;
    }

    asreq_count[src] += 1;

    local user = "";

    if ( msg?$client_name )
        user = msg$client_name;

    print fmt(
        "KRB ASREQ: %s user=%s count=%d",
        src,
        user,
        asreq_count[src]
    );

    #
    # Kerberos User Enumeration
    #

    if (
        asreq_count[src] >= 2
        &&
        delta <= 60secs
        &&
        ! kerberos_enum_alerted[src]
    )
    {
        ad_kerberos_seen[src] = T;

        print fmt(
            "KERBEROS ENUM DETECT: %s",
            src
        );

        add_threat(
            src,
            30,
            "Kerberos User Enumeration"
        );

        kerberos_enum_detected[src] = T;
        kerberos_enum_alerted[src] = T;

        NOTICE([
            $note=CyberCity::Kerberos_User_Enumeration,
            $msg=fmt(
                "KERBEROS USER ENUMERATION: %s",
                src
            ),
            $conn=c
        ]);

        if ( kerberos_roast_detected[src] )
        {
            ad_kerberos_seen[src] = T;

            add_threat(
                src,
                80,
                "Active Directory Attack Chain"
            );

            print fmt(
                "AD ATTACK CHAIN: %s",
                src
            );

            NOTICE([
                $note=CyberCity::AD_Attack_Chain,
                $msg=fmt(
                    "ACTIVE DIRECTORY ATTACK CHAIN: %s",
                    src
                ),
                $conn=c
            ]);

            kerberos_enum_detected[src] = F;
            kerberos_roast_detected[src] = F;
        }
    }
}

#
# TGS Requests
#

event krb_tgs_request(
    c: connection,
    msg: KRB::KDC_Request
)
{
    local src: addr = c$id$orig_h;

    tgsreq_count[src] += 1;

    local service = "";

    if ( msg?$service_name )
        service = msg$service_name;

    print fmt(
        "KRB TGSREQ: %s service=%s",
        src,
        service
    );

    ad_kerberos_seen[src] = T;

    add_threat(
        src,
        50,
        "Kerberoast Recon"
    );

    kerberos_roast_detected[src] = T;

    NOTICE([
        $note=CyberCity::Kerberoast_Recon,
        $msg=fmt(
            "KERBEROAST RECON: %s service=%s",
            src,
            service
        ),
        $conn=c
    ]);

    if ( kerberos_enum_detected[src] )
    {
        ad_kerberos_seen[src] = T;

        add_threat(
            src,
            80,
            "Active Directory Attack Chain"
        );

        print fmt(
            "AD ATTACK CHAIN: %s",
            src
        );

        NOTICE([
            $note=CyberCity::AD_Attack_Chain,
            $msg=fmt(
                "ACTIVE DIRECTORY ATTACK CHAIN: %s",
                src
            ),
            $conn=c
        ]);

        kerberos_enum_detected[src] = F;
        kerberos_roast_detected[src] = F;
    }
}

#
# Kerberos Errors
#

event krb_error(
    c: connection,
    msg: KRB::Error_Msg
)
{
    local src: addr = c$id$orig_h;

    if ( kerberos_spray_alerted[src] )
        return;

    krb_error_count[src] += 1;

    print fmt(
        "KRB ERROR: %s count=%d",
        src,
        krb_error_count[src]
    );

    if ( krb_error_count[src] >= 2 )
    {
        ad_kerberos_seen[src] = T;

        add_threat(
            src,
            40,
            "Kerberos Password Spray"
        );

        kerberos_spray_alerted[src] = T;

        NOTICE([
            $note=CyberCity::Kerberos_Password_Spray,
            $msg=fmt(
                "KERBEROS PASSWORD SPRAY: %s",
                src
            ),
            $conn=c
        ]);

        krb_error_count[src] = 0;
    }
}
