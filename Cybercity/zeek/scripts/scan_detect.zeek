@load /opt/cybercity/zeek/scripts/cybercity_whitelist.zeek
@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice

module CyberCity;

#
# Scan Detection V2.0
#
# A single connection to one sensitive port is NOT a scan (e.g. a legit
# `net use \\host\ipc$` or an NTLM relay return path). A real scan touches
# many ports (vertical) or many hosts (horizontal sweep). We only score once
# the source crosses a threshold.
#

const SCAN_VERTICAL_THRESHOLD = 3;      # distinct sensitive ports from one src
const SCAN_HORIZONTAL_THRESHOLD = 4;    # same port across distinct hosts

event zeek_init()
{
	print "SCAN DETECT V2.0 LOADED";
}

#
# Dedup: distinct (src, port) and (src, port, dst) pairs already counted
#

global scan_port_seen: table[addr, port] of bool &default=F;
global scan_host_seen: table[addr, port, addr] of bool &default=F;

#
# Counters (avoid nested sets — |set| is unreliable with &default in Zeek)
#

global scan_port_count: table[addr] of count &default=0;
global scan_host_count: table[addr, port] of count &default=0;

#
# Alert dedup
#

global scan_vertical_alerted: table[addr] of bool &default=F;
global scan_horizontal_alerted: table[addr, port] of bool &default=F;

function is_sensitive_port(p: port): bool
{
	return p == 21/tcp
		|| p == 22/tcp
		|| p == 23/tcp
		|| p == 445/tcp
		|| p == 3389/tcp;
}

event new_connection(c: connection)
{
	local src = c$id$orig_h;
	local dst = c$id$resp_h;
	local dst_port = c$id$resp_p;

	if ( should_ignore_ip(src) )
		return;

	if ( /^fe80:/ in fmt("%s", src) )
		return;

	if ( ! is_sensitive_port(dst_port) )
		return;

	#
	# Vertical scan: count distinct sensitive ports for this source
	#

	if ( ! scan_port_seen[src, dst_port] )
	{
		scan_port_seen[src, dst_port] = T;
		scan_port_count[src] += 1;
	}

	#
	# Horizontal sweep: count distinct hosts for this (src, port)
	#

	if ( ! scan_host_seen[src, dst_port, dst] )
	{
		scan_host_seen[src, dst_port, dst] = T;
		scan_host_count[src, dst_port] += 1;
	}

	#
	# Vertical scan alert
	#

	if ( scan_port_count[src] >= SCAN_VERTICAL_THRESHOLD &&
	     ! scan_vertical_alerted[src] )
	{
		scan_vertical_alerted[src] = T;

		add_threat(
			src,
			15,
			"Port Scan"
		);

		print fmt(
			"PORT SCAN: %s (%d sensitive ports)",
			src,
			scan_port_count[src]
		);

		NOTICE([
			$note=CyberCity::Scan_Detected,
			$msg=fmt(
				"PORT SCAN: %s hit %d sensitive ports",
				src,
				scan_port_count[src]
			),
			$conn=c
		]);
	}

	#
	# Horizontal sweep alert
	#

	if ( scan_host_count[src, dst_port] >= SCAN_HORIZONTAL_THRESHOLD &&
	     ! scan_horizontal_alerted[src, dst_port] )
	{
		scan_horizontal_alerted[src, dst_port] = T;

		add_threat(
			src,
			20,
			"Port Sweep"
		);

		print fmt(
			"PORT SWEEP: %s -> :%s on %d hosts",
			src,
			dst_port,
			scan_host_count[src, dst_port]
		);

		NOTICE([
			$note=CyberCity::Scan_Detected,
			$msg=fmt(
				"PORT SWEEP: %s targeted %d hosts on port %s",
				src,
				scan_host_count[src, dst_port],
				dst_port
			),
			$conn=c
		]);
	}
}
