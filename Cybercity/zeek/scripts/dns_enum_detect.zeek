@load base/protocols/dns
@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice
@load /opt/cybercity/zeek/scripts/correlation_globals.zeek
module CyberCity;

event zeek_init()
{
print "DNS ENUM V1.2 LOADED";
}

#

# DNS Counters

#

global dns_query_count: table[addr] of count
&default=0;

global dns_first_seen: table[addr] of time;

#

# AD Discovery Flags

#

global ldap_dns_seen: table[addr] of bool
&default=F;

global kerberos_dns_seen: table[addr] of bool
&default=F;

global gc_dns_seen: table[addr] of bool
&default=F;

#

# AD Correlation

#



#

# Alert Control

#

global dns_enum_alerted: table[addr] of bool
&default=F;

global dns_domain_alerted: table[addr] of bool
&default=F;

#

# DNS Monitoring

#

event DNS::log_dns(rec: DNS::Info)
{
local src: addr = rec$id$orig_h;

local query: string = "";

if ( rec?$query )
    query = to_lower(rec$query);

#
# Ignore mDNS
#

if (
    rec$id$resp_p == 5353/udp
    ||
    rec$id$resp_p == 5353/tcp
)
    return;

#
# Init
#

if ( src !in dns_first_seen )
    dns_first_seen[src] = network_time();

local delta =
    network_time() -
    dns_first_seen[src];

#
# Reset Window
#

if ( delta > 120secs )
{
    dns_query_count[src] = 0;

    ldap_dns_seen[src] = F;
    kerberos_dns_seen[src] = F;
    gc_dns_seen[src] = F;

    dns_enum_alerted[src] = F;
    dns_domain_alerted[src] = F;

    dns_first_seen[src] = network_time();
}

dns_query_count[src] += 1;

#
# Debug
#

print fmt(
    "DNS QUERY: %s query=%s count=%d",
    src,
    query,
    dns_query_count[src]
);

#
# AD Domain Discovery
#

if (
    query == "cybercity.local"
    &&
    ! dns_domain_alerted[src]
)
{
    dns_domain_alerted[src] = T;

    add_threat(
        src,
        10,
        "AD Domain Discovery"
    );

    ad_dns_seen[src] = T;

    print fmt(
        "DNS DOMAIN DISCOVERY: %s",
        src
    );
}

#
# LDAP Discovery
#

if ( /_ldap\._tcp/i in query )
{
    ldap_dns_seen[src] = T;
    ad_dns_seen[src] = T;

    add_threat(
        src,
        20,
        "LDAP DNS Discovery"
    );

    print fmt(
        "DNS LDAP DISCOVERY: %s",
        src
    );
}

#
# Kerberos Discovery
#

if ( /_kerberos\._tcp/i in query )
{
    kerberos_dns_seen[src] = T;
    ad_dns_seen[src] = T;

    add_threat(
        src,
        20,
        "Kerberos DNS Discovery"
    );

    print fmt(
        "DNS KERBEROS DISCOVERY: %s",
        src
    );
}

#
# Global Catalog Discovery
#

if ( /_gc\._tcp/i in query )
{
    gc_dns_seen[src] = T;
    ad_dns_seen[src] = T;

    add_threat(
        src,
        30,
        "Global Catalog Discovery"
    );

    print fmt(
        "DNS GC DISCOVERY: %s",
        src
    );
}

#
# Kerberos Password Service Discovery
#

if ( /_kpasswd\._tcp/i in query )
{
    ad_dns_seen[src] = T;

    add_threat(
        src,
        20,
        "Kerberos Password Service Discovery"
    );

    print fmt(
        "DNS KPASSWD DISCOVERY: %s",
        src
    );
}

#
# AD DNS Enumeration Chain
#

if (
    ldap_dns_seen[src]
    &&
    kerberos_dns_seen[src]
    &&
    gc_dns_seen[src]
    &&
    ! dns_enum_alerted[src]
)
{
    dns_enum_alerted[src] = T;

    ad_dns_seen[src] = T;
    
    
    add_threat(
        src,
        40,
        "AD DNS Enumeration"
    );

    print fmt(
        "AD DNS ENUMERATION: %s",
        src
    );

    delete ldap_dns_seen[src];
    delete kerberos_dns_seen[src];
    delete gc_dns_seen[src];
}

}
