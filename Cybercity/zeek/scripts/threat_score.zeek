global threat_score: table[addr] of count &default=0;

function add_threat(ip: addr, score: count, reason: string)
{
    threat_score[ip] += score;

    local now = strftime("%Y-%m-%d %H:%M:%S", network_time());

    print fmt("[%s] THREAT SCORE: %s => %d (%s)",
        now,
        ip,
        threat_score[ip],
        reason);

    if ( threat_score[ip] >= 50 )
    {
        print fmt("[%s] HIGH THREAT DETECTED: %s",
            now,
            ip);
    
      system(fmt("/opt/cybercity/firewall/block_ip.sh %s", ip));
     }
}
