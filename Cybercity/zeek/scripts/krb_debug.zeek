event zeek_init()
{
    print "KERBEROS DEBUG V1 LOADED";
}

event krb_as_request(
    c: connection,
    msg: KRB::KDC_Request
)
{
    local user = "";

    if ( msg?$client_name )
        user = msg$client_name;

    print fmt(
        "AS-REQ: %s user=%s",
        c$id$orig_h,
        user
    );
}

event krb_tgs_request(
    c: connection,
    msg: KRB::KDC_Request
)
{
    local user = "";
    local service = "";

    if ( msg?$client_name )
        user = msg$client_name;

    if ( msg?$service_name )
        service = msg$service_name;

    print fmt(
        "TGS-REQ: %s user=%s service=%s",
        c$id$orig_h,
        user,
        service
    );
}

event krb_error(
    c: connection,
    msg: KRB::Error_Msg
)
{
    print fmt(
        "KRB ERROR: %s",
        c$id$orig_h
    );
}
