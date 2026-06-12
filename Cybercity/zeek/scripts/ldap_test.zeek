@load base/protocols/ldap

event zeek_init()
{
    print "LDAP TEST V2 LOADED";
}

event LDAP::log_ldap_search(rec: LDAP::SearchInfo)
{
    local src: addr = rec$id$orig_h;

    print fmt(
        "LDAP SEARCH: %s scope=%s filter=%s",
        src,
        rec$scope,
        rec$filter
    );
}
