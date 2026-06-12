@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice

module CyberCity;

event zeek_init()
{
    print "WINRM HTTP V2 LOADED";
}

global winrm_http_hits:
table[addr] of count
&default=0;

event http_request(
    c: connection,
    method: string,
    original_URI: string,
    unescaped_URI: string,
    version: string
)
{
    #
    # WinRM utilise POST /wsman
    #

    if ( method != "POST" )
        return;

    if ( /wsman/ !in unescaped_URI )
        return;

    local src =
        c$id$orig_h;

    winrm_http_hits[src] += 1;

    print fmt(
        "WINRM HTTP: %s uri=%s hits=%d",
        src,
        unescaped_URI,
        winrm_http_hits[src]
    );

    #
    # Détection
    #

    if ( winrm_http_hits[src] >= 2 )
    {
        add_threat(
            src,
            35,
            "WinRM Client Activity"
        );

        NOTICE([
            $note=CyberCity::WinRM_Client_Detected,

            $msg=fmt(
                "WINRM CLIENT DETECTED: %s (%d POST /wsman)",
                src,
                winrm_http_hits[src]
            ),

            $conn=c
        ]);

        delete winrm_http_hits[src];
    }
}
