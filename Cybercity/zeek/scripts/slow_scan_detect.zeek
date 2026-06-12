@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice

module CyberCity;

global scanned_port:
table[addr, port] of bool
&default=F;

global scanned_count:
table[addr] of count
&default=0;

global first_seen:
table[addr] of time;

event new_connection(c: connection)
{

    local src =
    c$id$orig_h;

    local dst_port =
    c$id$resp_p;

    #
    # Ignore IPv6 link-local traffic
    #

    if ( /^fe80:/ in fmt("%s", src) )
    {
        return;
    }

    #
    # Initialize timer
    #

    if ( src !in first_seen )
    {

        first_seen[src] =
        network_time();

    }

    #
    # Count unique ports
    #

    if ( ! scanned_port[src, dst_port] )
    {

        scanned_port[src, dst_port] = T;

        scanned_count[src] += 1;

    }

    local delta =
    network_time() -
    first_seen[src];

    #
    # Slow Scan Detection
    #

    if (
        scanned_count[src] >= 5
        &&
        delta >= 60secs
    )
    {

        add_threat(
            src,
            20,
            "Slow Scan"
        );

        NOTICE([

            $note=CyberCity::Slow_Scan_Detected,

            $msg=fmt(
                "SLOW SCAN DETECTED: %s touched %d unique ports in %.0f seconds",
                src,
                scanned_count[src],
                delta / 1sec
            ),

            $conn=c

        ]);

        #
        # Reset counters
        #

        delete scanned_count[src];
        delete first_seen[src];

    }

}
