@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice

module CyberCity;

#
# SSH Tracking
#

global ssh_conn_count:
table[addr] of count
&default=0;

global ssh_first_seen:
table[addr] of time;

event new_connection(c: connection)
{

    #
    # SSH only
    #

    if ( c$id$resp_p != 22/tcp )
        return;

    local src =
    c$id$orig_h;

    #
    # Ignore IPv6 noise
    #

    if ( /^fe80:/ in fmt("%s", src) )
        return;

    #
    # First connection
    #

    if ( src !in ssh_first_seen )
    {

        ssh_first_seen[src] =
        network_time();

    }

    ssh_conn_count[src] += 1;

    local delta =
    network_time() -
    ssh_first_seen[src];

    

    #
    # Detection
    #
    # 10 SSH connections
    # in less than 60 sec
    #

    if (
        ssh_conn_count[src] >= 10
        &&
        delta <= 60secs
    )
    {

        add_threat(
            src,
            30,
            "SSH Bruteforce"
        );

        NOTICE([

            $note=CyberCity::SSH_Bruteforce,

            $msg=fmt(
                "SSH BRUTEFORCE SUSPECTED: %s (%d SSH connections in %.0f seconds)",
                src,
                ssh_conn_count[src],
                delta / 1sec
            ),

            $conn=c

        ]);

        delete ssh_conn_count[src];
        delete ssh_first_seen[src];

    }

    #
    # Expired window
    #

    if ( delta > 60secs )
    {

        ssh_conn_count[src] = 1;

        ssh_first_seen[src] =
        network_time();

    }

}
