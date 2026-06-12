@load base/protocols/dce-rpc
@load base/frameworks/notice

@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load /opt/cybercity/zeek/scripts/correlation_globals.zeek

module CyberCity;

event zeek_init()
{
    print "DCSYNC DETECT V1.0 LOADED";
}

#
# DRSUAPI Tracking
#

global drsuapi_seen: table[addr] of bool
    &default=F;

global dcsync_alerted: table[addr] of bool
    &default=F;

#
# DRSUAPI Bind Detection
#
# UUID:
# e3514235-4b06-11d1-ab04-00c04fc2dcd2
#

event dce_rpc_bind(
    c: connection,
    fid: count,
    ctx_id: count,
    uuid: string,
    ver_major: count,
    ver_minor: count
)
{
    local src: addr = c$id$orig_h;

    #
    # DRSUAPI v4.0
    #

    if ( ver_major == 4 )
    {
        drsuapi_seen[src] = T;

        print fmt(
            "DRSUAPI BIND: %s -> %s",
            src,
            c$id$resp_h
        );
    }
}

#
# DCSync Detection
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
    # Must have seen DRSUAPI first
    #

    if ( ! drsuapi_seen[src] )
        return;

    #
    # DRSGetNCChanges
    #
    # opnum = 3
    #

    if (
        opnum == 3
        &&
        ! dcsync_alerted[src]
    )
    {
        dcsync_alerted[src] = T;

        ad_dcsync_seen[src] = T;

        add_threat(
            src,
            300,
            "DCSync Attempt"
        );

        print fmt(
            "DCSYNC DETECTED: %s",
            src
        );

        NOTICE([
            $note=CyberCity::AD_Attack_Chain,
            $msg=fmt(
                "DCSYNC ATTEMPT DETECTED: %s",
                src
            ),
            $conn=c
        ]);
    }
}
