@load base/protocols/dce-rpc

event zeek_init()
{
    print "RPC DEBUG V1 LOADED";
}

event dce_rpc_bind(
    c: connection,
    fid: count,
    ctx_id: count,
    uuid: string,
    ver_major: count,
    ver_minor: count
)
{
    print fmt(
        "RPC BIND: %s -> %s uuid=%s v=%d.%d",
        c$id$orig_h,
        c$id$resp_h,
        uuid,
        ver_major,
        ver_minor
    );
}

event dce_rpc_request(
    c: connection,
    fid: count,
    ctx_id: count,
    opnum: count,
    stub_len: count
)
{
    print fmt(
        "RPC REQ: %s opnum=%d stub=%d",
        c$id$orig_h,
        opnum,
        stub_len
    );
}
