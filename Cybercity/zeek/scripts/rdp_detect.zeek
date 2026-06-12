@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek

module CyberCity;

event zeek_init()
{
    print "RDP DETECT V1.1 LOADED";
}

#
# Counters
#

global rdp_conn_count: table[addr] of count
    &default=0;

global rdp_failure_count: table[addr] of count
    &default=0;

global rdp_proto_count: table[addr] of count
    &default=0;

global rdp_first_seen: table[addr] of time;

#
# Alert state
#

global rdp_enum_alerted: table[addr] of bool
    &default=F;

global rdp_bruteforce_alerted: table[addr] of bool
    &default=F;

global rdp_nmap_alerted: table[addr] of bool
    &default=F;

global rdp_flood_alerted: table[addr] of bool
    &default=F;

#
# RDP Connection
#

event rdp_connect_request(
    c: connection,
    cookie: string
)
{
    local src: addr = c$id$orig_h;

    if ( src !in rdp_first_seen )
        rdp_first_seen[src] = network_time();

    local delta =
        network_time() -
        rdp_first_seen[src];

    #
    # Reset after 10 minutes
    #

    if ( delta > 600secs )
    {
        rdp_conn_count[src] = 0;
        rdp_failure_count[src] = 0;
        rdp_proto_count[src] = 0;

        rdp_enum_alerted[src] = F;
        rdp_bruteforce_alerted[src] = F;
        rdp_nmap_alerted[src] = F;
        rdp_flood_alerted[src] = F;

        rdp_first_seen[src] = network_time();
    }

    rdp_conn_count[src] += 1;

    print fmt(
        "RDP CONNECT DETECT: %s cookie=%s count=%d",
        src,
        cookie,
        rdp_conn_count[src]
    );

    #
    # Nmap Detection
    #

    if (
        cookie == "nmap"
        &&
        ! rdp_nmap_alerted[src]
    )
    {
        add_threat(
            src,
            20,
            "RDP Enumeration"
        );

        rdp_nmap_alerted[src] = T;

        print fmt(
            "RDP NMAP ENUM: %s",
            src
        );
    }

    #
    # Connection Flood
    #

    if (
        rdp_conn_count[src] >= 10
        &&
        ! rdp_flood_alerted[src]
    )
    {
        add_threat(
            src,
            30,
            "RDP Connection Flood"
        );

        rdp_flood_alerted[src] = T;

        print fmt(
            "RDP FLOOD DETECT: %s",
            src
        );
    }
}

#
# Protocol Enumeration
#

event rdp_negotiation_response(
    c: connection,
    security_protocol: count
)
{
    local src: addr = c$id$orig_h;

    rdp_proto_count[src] += 1;

    print fmt(
        "RDP PROTOCOL: %s proto=%d count=%d",
        src,
        security_protocol,
        rdp_proto_count[src]
    );

    if (
        rdp_proto_count[src] >= 3
        &&
        ! rdp_enum_alerted[src]
    )
    {
        add_threat(
            src,
            30,
            "RDP Security Enumeration"
        );

        rdp_enum_alerted[src] = T;

        print fmt(
            "RDP SECURITY ENUM: %s",
            src
        );
    }
}

#
# Failed Negotiation
#

event rdp_negotiation_failure(
    c: connection,
    failure_code: count
)
{
    local src: addr = c$id$orig_h;

    rdp_failure_count[src] += 1;

    print fmt(
        "RDP FAILURE: %s code=%d count=%d",
        src,
        failure_code,
        rdp_failure_count[src]
    );

    if (
        rdp_failure_count[src] >= 5
        &&
        ! rdp_bruteforce_alerted[src]
    )
    {
        add_threat(
            src,
            40,
            "RDP Bruteforce"
        );

        rdp_bruteforce_alerted[src] = T;

        print fmt(
            "RDP BRUTEFORCE DETECT: %s",
            src
        );

        rdp_failure_count[src] = 0;
    }
}

#
# Encryption Started
#

event rdp_begin_encryption(
    c: connection,
    security_protocol: count
)
{
    local src: addr = c$id$orig_h;

    print fmt(
        "RDP ENCRYPTION DETECT: %s protocol=%d",
        src,
        security_protocol
    );
}
