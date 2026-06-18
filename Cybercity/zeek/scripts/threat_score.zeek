@load /opt/cybercity/zeek/scripts/cybercity_whitelist.zeek

global threat_score: table[addr] of count &default=0;

function add_threat(ip: addr, score: count, reason: string)
{
	if ( CyberCity::should_ignore_ip(ip) )
		return;

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
