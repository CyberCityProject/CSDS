@load base/protocols/ldap
@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice
@load /opt/cybercity/zeek/scripts/correlation_globals.zeek
module CyberCity;

event zeek_init()
{
    print "LDAP ENUM V3.1 LOADED";
}

#
# LDAP Enumeration Counters
#

global ldap_search_count: table[addr] of count
    &default=0;

global ldap_first_seen: table[addr] of time;

#
# BloodHound Recon Counters
#

global ldap_bloodhound_count: table[addr] of count
    &default=0;

#
# AD Correlation
#



#
# LDAP Search Monitoring
#

event LDAP::log_ldap_search(rec: LDAP::SearchInfo)
{
    local src: addr = rec$id$orig_h;

    local filter: string = "";

    if ( rec?$filter )
        filter = rec$filter;

    #
    # Init
    #

    if ( src !in ldap_first_seen )
        ldap_first_seen[src] = network_time();

    ldap_search_count[src] += 1;

    #
    # Debug
    #

    print fmt(
        "LDAP SEARCH: %s filter=%s count=%d",
        src,
        filter,
        ldap_search_count[src]
    );

    local delta =
        network_time() -
        ldap_first_seen[src];

    #
    # Generic LDAP Enumeration
    #

    if (
        ldap_search_count[src] >= 3
        &&
        delta <= 60secs
    )
    {
        ad_ldap_seen[src] = T;

        print fmt(
            "LDAP ENUM DETECT: %s searches=%d",
            src,
            ldap_search_count[src]
        );

        add_threat(
            src,
            30,
            "LDAP Enumeration"
        );

        delete ldap_search_count[src];
        delete ldap_first_seen[src];
    }

    #
    # User Discovery
    #

    if ( /objectClass=user/i in filter )
    {
        ad_ldap_seen[src] = T;

        add_threat(
            src,
            20,
            "AD User Discovery"
        );

        ldap_bloodhound_count[src] += 1;

        print fmt(
            "LDAP USER ENUM: %s",
            src
        );
    }

    #
    # Group Discovery
    #

    if ( /objectClass=group/i in filter )
    {
        ad_ldap_seen[src] = T;

        add_threat(
            src,
            20,
            "AD Group Discovery"
        );

        ldap_bloodhound_count[src] += 1;

        print fmt(
            "LDAP GROUP ENUM: %s",
            src
        );
    }

    #
    # Computer Discovery
    #

    if ( /objectClass=computer/i in filter )
    {
        ad_ldap_seen[src] = T;

        add_threat(
            src,
            20,
            "AD Computer Discovery"
        );

        ldap_bloodhound_count[src] += 1;

        print fmt(
            "LDAP COMPUTER ENUM: %s",
            src
        );
    }

    #
    # Privilege Enumeration
    #

    if ( /memberOf/i in filter )
    {
        ad_ldap_seen[src] = T;

        add_threat(
            src,
            40,
            "AD Privilege Enumeration"
        );

        ldap_bloodhound_count[src] += 2;

        print fmt(
            "LDAP PRIVILEGE ENUM: %s",
            src
        );
    }

    #
    # Kerberoast Recon
    #

    if ( /servicePrincipalName/i in filter )
    {
        ad_ldap_seen[src] = T;

        add_threat(
            src,
            50,
            "Kerberoast Recon"
        );

        ldap_bloodhound_count[src] += 3;

        print fmt(
            "LDAP SPN ENUM: %s",
            src
        );
    }

    #
    # BloodHound-like activity
    #

    if ( ldap_bloodhound_count[src] >= 5 )
    {
        ad_ldap_seen[src] = T;

        print fmt(
            "BLOODHOUND DETECT: %s score=%d",
            src,
            ldap_bloodhound_count[src]
        );

        add_threat(
            src,
            80,
            "BloodHound Collection"
        );

        ldap_bloodhound_count[src] = 0;
    }

    #
    # Window Expired
    #

    if (
        src in ldap_first_seen
        &&
        delta > 60secs
    )
    {
        ldap_search_count[src] = 1;
        ldap_first_seen[src] = network_time();
        ldap_bloodhound_count[src] = 0;
    }
}
