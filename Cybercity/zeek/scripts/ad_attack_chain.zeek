@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice
@load /opt/cybercity/zeek/scripts/correlation_globals.zeek

module CyberCity;

event zeek_init()
{
    print "AD ATTACK CHAIN V1.2 LOADED";
}

#
# Alert Control
#

global ad_stage1_alerted: table[addr] of bool
    &default=F;

global ad_stage2_alerted: table[addr] of bool
    &default=F;

global ad_stage3_alerted: table[addr] of bool
    &default=F;

global ad_stage4_alerted: table[addr] of bool
    &default=F;

global ad_campaign_alerted: table[addr] of bool
    &default=F;

#
# Correlation Engine
#

event new_connection(c: connection)
{
    local src: addr = c$id$orig_h;

    #
    # Stage 1
    # DNS + LDAP
    #

    if (
        ad_dns_seen[src]
        &&
        ad_ldap_seen[src]
        &&
        ! ad_stage1_alerted[src]
    )
    {
        ad_stage1_alerted[src] = T;

        add_threat(
            src,
            50,
            "AD Recon Stage 1"
        );

        print fmt(
            "AD RECON STAGE 1: %s",
            src
        );
    }

    #
    # Stage 2
    # DNS + LDAP + SMB/RPC
    #

    if (
        ad_dns_seen[src]
        &&
        ad_ldap_seen[src]
        &&
        (
            ad_smb_seen[src]
            ||
            ad_rpc_seen[src]
        )
        &&
        ! ad_stage2_alerted[src]
    )
    {
        ad_stage2_alerted[src] = T;

        add_threat(
            src,
            75,
            "AD Recon Stage 2"
        );

        print fmt(
            "AD RECON STAGE 2: %s",
            src
        );
    }

    #
    # Stage 3
    # Recon + Kerberos
    #

    if (
        ad_stage2_alerted[src]
        &&
        ad_kerberos_seen[src]
        &&
        ! ad_stage3_alerted[src]
    )
    {
        ad_stage3_alerted[src] = T;

        add_threat(
            src,
            100,
            "AD Credential Access"
        );

        print fmt(
            "AD CREDENTIAL ACCESS: %s",
            src
        );
    }

    #
    # Stage 4
    # Kerberoast / ASREPRoast
    #

    if (
        ad_stage3_alerted[src]
        &&
        (
            ad_kerberoast_seen[src]
            ||
            ad_asreproast_seen[src]
        )
        &&
        ! ad_stage4_alerted[src]
    )
    {
        ad_stage4_alerted[src] = T;

        add_threat(
            src,
            150,
            "AD Credential Theft"
        );

        print fmt(
            "AD CREDENTIAL THEFT: %s",
            src
        );
    }

#
# DCsync
#

if (
    ad_campaign_alerted[src]
    &&
    ad_dcsync_seen[src]
)
{
    add_threat(
        src,
        300,
        "Domain Compromise"
    );

    print fmt(
        "DOMAIN COMPROMISE: %s",
        src
    );
}

    #
    # Full Campaign
    #

    if (
        ad_stage1_alerted[src]
        &&
        ad_stage2_alerted[src]
        &&
        ad_stage3_alerted[src]
        &&
        ! ad_campaign_alerted[src]
    )
    {
        ad_campaign_alerted[src] = T;

        add_threat(
            src,
            200,
            "Active Directory Attack Campaign"
        );

        print fmt(
            "AD ATTACK CAMPAIGN: %s",
            src
        );

        NOTICE([
            $note=CyberCity::AD_Attack_Chain,
            $msg=fmt(
                "ACTIVE DIRECTORY ATTACK CAMPAIGN: %s",
                src
            )
        ]);
    }

    #
    # Domain Dominance
    #

    if (
        ad_dcsync_seen[src]
        &&
        ad_campaign_alerted[src]
    )
    {
        add_threat(
            src,
            300,
            "Domain Compromise"
        );

        print fmt(
            "DOMAIN COMPROMISE: %s",
            src
        );

        NOTICE([
            $note=CyberCity::AD_Attack_Chain,
            $msg=fmt(
                "DOMAIN COMPROMISE DETECTED: %s",
                src
            )
        ]);
    }
}
