@load base/protocols/smb
@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice
@load /opt/cybercity/zeek/scripts/correlation_globals.zeek
module CyberCity;

event zeek_init()
{
    print "SMB ENUM V6.1 LOADED";
}

#
# SMB Counters
#

global smb_session_count:
table[addr] of count
&default=0;

global smb_tree_count:
table[addr] of count
&default=0;

global smb_first_seen:
table[addr] of time;

#
# AD Correlation
#



#
# Generic SMB Enumeration
#

function check_smb_enum(
    src: addr,
    c: connection,
    path: string
)
{
    if ( src !in smb_first_seen )
        return;

    local delta =
        network_time() -
        smb_first_seen[src];

    if (
        smb_session_count[src] >= 3
        &&
        smb_tree_count[src] >= 1
        &&
        delta <= 60secs
    )
    {
        ad_smb_seen[src] = T;

        print fmt(
            "SMB ENUM DETECT: %s sessions=%d trees=%d path=%s",
            src,
            smb_session_count[src],
            smb_tree_count[src],
            path
        );

        add_threat(
            src,
            20,
            "SMB Enumeration"
        );

        NOTICE([
            $note=CyberCity::SMB_Enumeration,

            $msg=fmt(
                "SMB ENUMERATION DETECTED: %s (%d sessions, %d tree connects)",
                src,
                smb_session_count[src],
                smb_tree_count[src]
            ),

            $conn=c
        ]);

        delete smb_session_count[src];
        delete smb_tree_count[src];
        delete smb_first_seen[src];
    }

    if ( delta > 60secs )
    {
        smb_session_count[src] = 0;
        smb_tree_count[src] = 0;
        smb_first_seen[src] = network_time();
    }
}

#
# SMB2 Session Setup
#

event smb2_session_setup_request(
    c: connection,
    hdr: SMB2::Header,
    request: SMB2::SessionSetupRequest
)
{
    local src = c$id$orig_h;

    print fmt(
        "ENUM SESSION: %s",
        src
    );

    if ( src !in smb_first_seen )
        smb_first_seen[src] = network_time();

    smb_session_count[src] += 1;
}

#
# SMB2 Tree Connect
#

event smb2_tree_connect_request(
    c: connection,
    hdr: SMB2::Header,
    path: string
)
{
    local src = c$id$orig_h;

    print fmt(
        "ENUM TREE: %s -> %s",
        src,
        path
    );

    #
    # ADMIN$
    #

    if ( /ADMIN\$/ in path )
    {
        ad_smb_seen[src] = T;

        add_threat(
            src,
            40,
            "SMB Admin Share Access"
        );

        NOTICE([
            $note=CyberCity::SMB_Enumeration,

            $msg=fmt(
                "SMB ADMIN SHARE ACCESS: %s -> %s",
                src,
                path
            ),

            $conn=c
        ]);
    }

    #
    # C$
    #

    if ( /\\C\$/ in path )
    {
        ad_smb_seen[src] = T;

        add_threat(
            src,
            50,
            "SMB Lateral Movement"
        );

        NOTICE([
            $note=CyberCity::SMB_Enumeration,

            $msg=fmt(
                "SMB LATERAL MOVEMENT: %s -> %s",
                src,
                path
            ),

            $conn=c
        ]);
    }

    #
    # NETLOGON
    #

    if ( /NETLOGON/ in path )
    {
        ad_smb_seen[src] = T;

        add_threat(
            src,
            30,
            "SMB NETLOGON Access"
        );

        print fmt(
            "SMB NETLOGON ACCESS: %s",
            src
        );
    }

    #
    # SYSVOL
    #

    if ( /SYSVOL/ in path )
    {
        ad_smb_seen[src] = T;

        add_threat(
            src,
            30,
            "SMB SYSVOL Access"
        );

        print fmt(
            "SMB SYSVOL ACCESS: %s",
            src
        );
    }

    if ( src !in smb_first_seen )
        smb_first_seen[src] = network_time();

    smb_tree_count[src] += 1;

    check_smb_enum(
        src,
        c,
        path
    );
}
