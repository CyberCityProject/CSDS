@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice

module CyberCity;

#
# Remember scanned ports
#

global scanned_ports:
table[addr, port] of bool
&default=F;

event new_connection(c: connection)
{

    local src =
    c$id$orig_h;

    local dst_port =
    c$id$resp_p;

    #
    # Ignore IPv6 link-local noise
    #

    if ( /^fe80:/ in fmt("%s", src) )
        return;

    #
    # Ignore normal web traffic
    #

    if (
        dst_port == 80/tcp
        ||
        dst_port == 443/tcp
    )
    {
        return;
    }

    #
    # Sensitive ports only
    #

    if (
        dst_port != 21/tcp
        &&
        dst_port != 22/tcp
        &&
        dst_port != 23/tcp
        &&
        dst_port != 445/tcp
        &&
        dst_port != 3389/tcp
    )
    {
        return;
    }

    #
    # Already seen ?
    #

    if ( scanned_ports[src, dst_port] )
    {
        return;
    }

    #
    # First time this IP touches this port
    #

    scanned_ports[src, dst_port] = T;

    add_threat(
        src,
        10,
        "Port Scan"
    );

    NOTICE([

        $note=CyberCity::Scan_Detected,

        $msg=fmt(
            "SCAN DETECTED: %s -> %s:%s",
            c$id$orig_h,
            c$id$resp_h,
            c$id$resp_p
        ),

        $conn=c

    ]);

}
