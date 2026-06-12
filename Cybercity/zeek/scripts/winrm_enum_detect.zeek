@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice

module CyberCity;

event zeek_init()
{
    print "WINRM ENUM V1 LOADED";
}

#
# Counters
#

global winrm_count:
table[addr] of count
&default=0;

global winrm_first_seen:
table[addr] of time;

#
# Detection
#

event new_connection(c: connection)
{
    local src = c$id$orig_h;

    #
    # WinRM ports
    #

    if (
        c$id$resp_p != 5985/tcp
        &&
        c$id$resp_p != 5986/tcp
    )
    {
        return;
    }

    if ( src !in winrm_first_seen )
    {
        winrm_first_seen[src] =
        network_time();
    }

    winrm_count[src] += 1;

    local delta =
        network_time() -
        winrm_first_seen[src];

    print fmt(
        "WINRM DEBUG: %s count=%d elapsed=%.0f",
        src,
        winrm_count[src],
        delta / 1sec
    );

    #
    # Enumeration
    #

    if (
        winrm_count[src] >= 2
        &&
        delta <= 60secs
    )
    {
        add_threat(
            src,
            25,
            "WinRM Enumeration"
        );

        NOTICE([

            $note=CyberCity::WinRM_Enumeration,

            $msg=fmt(
                "WINRM ENUMERATION DETECTED: %s (%d connections)",
                src,
                winrm_count[src]
            ),

            $conn=c

        ]);

        delete winrm_count[src];
        delete winrm_first_seen[src];
    }

    #
    # Reset window
    #

    if ( delta > 60secs )
    {
        winrm_count[src] = 1;

        winrm_first_seen[src] =
        network_time();
    }
}
