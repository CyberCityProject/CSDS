@load base/protocols/dce-rpc
@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice
@load /opt/cybercity/zeek/scripts/correlation_globals.zeek
module CyberCity;

event zeek_init()
{
    print "RPC ENUM V1.3 LOADED";
}

#
# RPC Counters
#

global rpc_request_count: table[addr] of count
    &default=0;

global rpc_first_seen: table[addr] of time;

#
# RPC Service Detection
#

global rpc_lsa_seen: table[addr] of bool
    &default=F;

global rpc_samr_seen: table[addr] of bool
    &default=F;

#
# AD Correlation
#



#
# Alert Control
#

global rpc_enum_alerted: table[addr] of bool
    &default=F;

global rpc_chain_alerted: table[addr] of bool
    &default=F;

global rpc_windows_enum_alerted: table[addr] of bool
    &default=F;

#
# RPC Requests
#

event dce_rpc_request(
    c: connection,
    fid: count,
    ctx_id: count,
    opnum: count,
    stub_len: count
)
{
    local src: addr = c$id$orig_h;

    #
    # Init
    #

    if ( src !in rpc_first_seen )
        rpc_first_seen[src] = network_time();

    local delta =
        network_time() -
        rpc_first_seen[src];

    #
    # Reset Window
    #

    if ( delta > 60secs )
    {
        rpc_request_count[src] = 0;

        rpc_lsa_seen[src] = F;
        rpc_samr_seen[src] = F;

        rpc_enum_alerted[src] = F;
        rpc_chain_alerted[src] = F;
        rpc_windows_enum_alerted[src] = F;

        rpc_first_seen[src] = network_time();
    }

    rpc_request_count[src] += 1;

    #
    # Debug
    #

    print fmt(
        "RPC REQUEST: %s opnum=%d count=%d",
        src,
        opnum,
        rpc_request_count[src]
    );

    #
    # LSA Enumeration
    #

    if (
        (
            opnum == 0
            ||
            opnum == 6
            ||
            opnum == 7
        )
        &&
        ! rpc_lsa_seen[src]
    )
    {
        rpc_lsa_seen[src] = T;
        ad_rpc_seen[src] = T;

        add_threat(
            src,
            20,
            "RPC LSA Enumeration"
        );

        print fmt(
            "RPC LSA ENUM: %s",
            src
        );
    }

    #
    # SAMR Enumeration
    #

    if (
        (
            opnum == 57
            ||
            opnum == 62
            ||
            opnum == 64
        )
        &&
        ! rpc_samr_seen[src]
    )
    {
        rpc_samr_seen[src] = T;
        ad_rpc_seen[src] = T;

        add_threat(
            src,
            20,
            "RPC SAMR Enumeration"
        );

        print fmt(
            "RPC SAMR ENUM: %s",
            src
        );
    }

    #
    # AD RPC Enumeration
    #

    if (
        rpc_lsa_seen[src]
        &&
        rpc_samr_seen[src]
        &&
        ! rpc_chain_alerted[src]
    )
    {
        rpc_chain_alerted[src] = T;
        ad_rpc_seen[src] = T;

        add_threat(
            src,
            40,
            "AD RPC Enumeration"
        );

        print fmt(
            "AD RPC ENUMERATION: %s",
            src
        );
    }

    #
    # Generic RPC Enumeration
    #

    if (
        rpc_request_count[src] >= 10
        &&
        ! rpc_enum_alerted[src]
    )
    {
        rpc_enum_alerted[src] = T;
        ad_rpc_seen[src] = T;

        add_threat(
            src,
            30,
            "RPC Enumeration"
        );

        print fmt(
            "RPC ENUMERATION: %s requests=%d",
            src,
            rpc_request_count[src]
        );
    }

    #
    # Windows Account Enumeration
    #

    if (
        rpc_chain_alerted[src]
        &&
        rpc_enum_alerted[src]
        &&
        ! rpc_windows_enum_alerted[src]
    )
    {
        rpc_windows_enum_alerted[src] = T;
        ad_rpc_seen[src] = T;

        add_threat(
            src,
            50,
            "Windows Account Enumeration"
        );

        print fmt(
            "WINDOWS ACCOUNT ENUMERATION: %s",
            src
        );
    }
}
