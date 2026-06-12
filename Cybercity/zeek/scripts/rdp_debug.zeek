module CyberCity;

event zeek_init()
{
    print "RDP DEBUG V2 LOADED";
}

#
# Client Hello
#

event rdp_connect_request(
    c: connection,
    cookie: string
)
{
    print fmt(
        "RDP CONNECT: %s -> %s cookie=%s",
        c$id$orig_h,
        c$id$resp_h,
        cookie
    );
}

#
# Negotiation
#

event rdp_negotiation_response(
    c: connection,
    security_protocol: count
)
{
    print fmt(
        "RDP NEGOTIATION: %s protocol=%d",
        c$id$orig_h,
        security_protocol
    );
}

#
# Negotiation Failure
#

event rdp_negotiation_failure(
    c: connection,
    failure_code: count
)
{
    print fmt(
        "RDP FAILURE: %s code=%d",
        c$id$orig_h,
        failure_code
    );
}

#
# Encryption
#

event rdp_begin_encryption(
    c: connection,
    security_protocol: count
)
{
    print fmt(
        "RDP ENCRYPTION: %s protocol=%d",
        c$id$orig_h,
        security_protocol
    );
}

#
# Server Security
#

event rdp_server_security(
    c: connection,
    encryption_method: count,
    encryption_level: count
)
{
    print fmt(
        "RDP SECURITY: %s method=%d level=%d",
        c$id$orig_h,
        encryption_method,
        encryption_level
    );
}

#
# Certificate
#

event rdp_server_certificate(
    c: connection,
    cert_type: count,
    permanently_issued: bool
)
{
    print fmt(
        "RDP CERT: %s cert=%d permanent=%s",
        c$id$orig_h,
        cert_type,
        permanently_issued
    );
}
