event zeek_init()
{
    print "SMB DEBUG LOADED";
}

event smb1_session_setup_andx_request(
    c: connection,
    hdr: SMB1::Header,
    request: SMB1::SessionSetupAndXRequest
)
{
    print fmt(
        "SMB1 SESSION SETUP: %s",
        c$id$orig_h
    );
}

event smb2_session_setup_request(
    c: connection,
    hdr: SMB2::Header,
    request: SMB2::SessionSetupRequest
)
{
    print fmt(
        "SMB2 SESSION SETUP: %s",
        c$id$orig_h
    );
}

event smb1_tree_connect_andx_request(
    c: connection,
    hdr: SMB1::Header,
    path: string,
    service: string
)
{
    print fmt(
        "SMB1 TREE CONNECT: %s -> %s",
        c$id$orig_h,
        path
    );
}

event smb2_tree_connect_request(
    c: connection,
    hdr: SMB2::Header,
    path: string
)
{
    print fmt(
        "SMB2 TREE CONNECT: %s -> %s",
        c$id$orig_h,
        path
    );
}
