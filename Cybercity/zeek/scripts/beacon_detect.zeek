@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice

module CyberCity;

#
# Store last timestamps
#

global beacon_last_seen:
table[addr, addr, port] of time;

#
# Store hit counters
#

global beacon_hits:
table[addr, addr, port] of count
&default=0;

event zeek_init()
{

    print "CyberCity Beacon Detection Loaded";

}

event connection_state_remove(c: connection)
{

    local orig =
    c$id$orig_h;

    local resp =
    c$id$resp_h;

    local p =
    c$id$resp_p;

    #
    # Ignore IPv6 link-local noise
    #

if ( /^fe80:/ in fmt("%s", orig) )
{
    return;
}

    #
    # Monitor HTTP/HTTPS only
    #

    if (
        p != 80/tcp
        &&
        p != 443/tcp
    )
    {
        return;
    }

    local now =
    network_time();

    #
    # Previous communication exists
    #

    if ( [orig, resp, p] in beacon_last_seen )
    {

        local last =
        beacon_last_seen[orig, resp, p];

        local delta =
        now - last;

        #
        # Beacon interval
        #
        # Example:
        # every 20-40 sec
        #

        if (
            delta > 20secs
            &&
            delta < 40secs
        )
        {

            beacon_hits[orig, resp, p] += 1;

        }
        else
        {

            beacon_hits[orig, resp, p] = 0;

        }

        #
        # Detection threshold
        #

        if (
            beacon_hits[orig, resp, p] >= 4
        )
        {

            add_threat(
                orig,
                50,
                "Beacon Activity"
            );

            NOTICE([

                $note=CyberCity::Beacon_Detected,

                $msg=fmt(
                    "BEACON DETECTED: %s -> %s:%s (interval %.1f sec)",
                    orig,
                    resp,
                    p,
                    delta / 1sec
                ),

                $conn=c

            ]);

            #
            # Reset counter
            #

            beacon_hits[orig, resp, p] = 0;

        }

    }

    #
    # Update timestamp
    #

    beacon_last_seen[
        orig,
        resp,
        p
    ] = now;

}
