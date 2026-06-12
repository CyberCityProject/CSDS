@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice

module CyberCity;

global web_enum_count:
table[addr] of count
&default=0;

global web_enum_first_seen:
table[addr] of time;

event http_request(
    c: connection,
    method: string,
    original_URI: string,
    unescaped_URI: string,
    version: string
)
{

    local src =
    c$id$orig_h;

    #
    # Ignore IPv6 noise
    #

    if ( /^fe80:/ in fmt("%s", src) )
        return;

    #
    # Interesting paths
    #

    if (
        /admin/ in unescaped_URI ||
        /login/ in unescaped_URI ||
        /wp-admin/ in unescaped_URI ||
        /phpmyadmin/ in unescaped_URI ||
        /.git/ in unescaped_URI ||
        /backup/ in unescaped_URI ||
        /config/ in unescaped_URI
    )
    {

        if ( src !in web_enum_first_seen )
        {

            web_enum_first_seen[src] =
            network_time();

        }

        web_enum_count[src] += 1;

        local delta =
        network_time() -
        web_enum_first_seen[src];

        #
        # 5 suspicious requests
        # in less than 60 sec
        #

        if (
            web_enum_count[src] >= 5
            &&
            delta <= 60secs
        )
        {

            add_threat(
                src,
                25,
                "Web Enumeration"
            );

            NOTICE([

                $note=CyberCity::Web_Enumeration,

                $msg=fmt(
                    "WEB ENUMERATION DETECTED: %s (%d requests)",
                    src,
                    web_enum_count[src]
                ),

                $conn=c

            ]);

            delete web_enum_count[src];
            delete web_enum_first_seen[src];

        }

        #
        # Reset expired window
        #

        if ( delta > 60secs )
        {

            web_enum_count[src] = 1;

            web_enum_first_seen[src] =
            network_time();

        }

    }

}
