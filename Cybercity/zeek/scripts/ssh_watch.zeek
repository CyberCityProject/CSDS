event ssh_auth_failed(c: connection)
{
    print fmt("SSH FAILED: %s -> %s",
        c$id$orig_h,
        c$id$resp_h);
}
