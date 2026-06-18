@load base/protocols/smb
@load base/protocols/ntlm
@load /opt/cybercity/zeek/scripts/cybercity_whitelist.zeek
@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load /opt/cybercity/zeek/scripts/correlation_globals.zeek
@load base/frameworks/notice

module CyberCity;

#
# Pass-the-Hash / NTLM Lateral Movement Detection V2.1
#
# Lab topology:
#   Kali .47    = attacker (score + block)
#   Win  .91    = AD target (DC)
#   CSDS .39 / Host .98 = trusted
#
# IMPORTANT — SMB3 encryption:
#   Modern Windows (Server 2022 here) encrypts SMB after session setup. A
#   passive sensor (Zeek) can read the NEGOTIATE + SESSION_SETUP (NTLM auth is
#   cleartext) but NOT tree connect / create / named-pipe DCE-RPC. So detecting
#   psexec/atexec by "ADMIN$ + svcctl" on the wire is impossible once SMB is
#   encrypted.
#
# This engine therefore uses encryption-resilient signals:
#   1. NTLM lateral movement: one source NTLM-authenticating to >= N hosts.
#   2. Privileged NTLM auth: NTLM (not Kerberos) with an admin account to SMB.
#   3. Clear-text bonus: if SMB is NOT encrypted, also catch ADMIN$ + svcctl/
#      atsvc => full PASS-THE-HASH EXEC.
#
# NOTE: under SMB3 encryption a single-target PtH can only be flagged as
# SUSPECTED from the network. Confirming remote code execution requires host
# telemetry (Sysmon/EDR on the target).
#

const PTH_WINDOW = 300secs;
const PTH_LATERAL_THRESHOLD = 2;   # distinct hosts NTLM-auth'd by one source

event zeek_init()
{
	print "PTH DETECT V2.1 LOADED";
}

#
# NTLM auth context per source (cleartext, survives SMB3 encryption)
#

global pth_ntlm_user: table[addr] of string &default="?";
global pth_ntlm_ws: table[addr] of string &default="?";
global pth_ntlm_target_seen: table[addr, addr] of bool &default=F;
global pth_ntlm_target_count: table[addr] of count &default=0;
global pth_last: table[addr] of time &create_expire=PTH_WINDOW;

#
# Clear-text SMB indicators (only when encryption is OFF)
#

global pth_ip_connect: set[addr];
global pth_admin_share: set[addr];
global pth_exec_pipe: set[addr];

#
# Alert dedup
#

global pth_admin_auth_alerted: table[addr] of bool &default=F;
global pth_lateral_alerted: table[addr] of bool &default=F;
global pth_exec_alerted: table[addr] of bool &default=F;

function is_privileged_user(u: string): bool
{
	local lu = to_lower(u);

	return /administrator/ in lu
		|| /administrateur/ in lu
		|| lu == "admin"
		|| /krbtgt/ in lu
		|| /domain admin/ in lu;
}

function raise_pth(
	src: addr,
	c: connection,
	reason: string,
	score: count,
	note: Notice::Type,
	label: string
)
{
	if ( should_ignore_ip(src) )
		return;

	ad_pth_seen[src] = T;
	add_threat(src, score, label);

	print fmt("%s: %s (user=%s ws=%s) %s",
		label,
		src,
		pth_ntlm_user[src],
		pth_ntlm_ws[src],
		reason);

	NOTICE([
		$note=note,
		$msg=fmt("%s: %s (user=%s) - %s",
			label,
			src,
			pth_ntlm_user[src],
			reason),
		$conn=c
	]);
}

#
# Behavioral NTLM detection (encryption-resilient)
#

function check_ntlm_behavior(src: addr, dst: addr, c: connection)
{
	if ( should_ignore_ip(src) )
		return;

	#
	# Lateral movement: NTLM auth to multiple distinct hosts
	#

	if ( pth_ntlm_target_count[src] >= PTH_LATERAL_THRESHOLD &&
	     ! pth_lateral_alerted[src] )
	{
		pth_lateral_alerted[src] = T;

		raise_pth(
			src,
			c,
			fmt("NTLM auth to %d hosts (lateral movement)",
				pth_ntlm_target_count[src]),
			60,
			CyberCity::PtH_Lateral_Movement,
			"NTLM LATERAL MOVEMENT"
		);

		return;
	}

	#
	# Privileged account over NTLM (admins should use Kerberos)
	#

	if ( is_privileged_user(pth_ntlm_user[src]) &&
	     ! pth_admin_auth_alerted[src] )
	{
		pth_admin_auth_alerted[src] = T;

		raise_pth(
			src,
			c,
			fmt("privileged NTLM auth to %s (Kerberos expected)", dst),
			45,
			CyberCity::PtH_Detected,
			"SUSPICIOUS NTLM ADMIN AUTH"
		);
	}
}

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
{
	local src = c$id$orig_h;
	local dst = c$id$resp_h;

	if ( should_ignore_ip(src) )
		return;

	pth_last[src] = network_time();

	#
	# Only update the stored identity when this auth actually carries a
	# username — an anonymous/empty NTLM message must not overwrite a good
	# captured user (e.g. CYBERCITY\Administrateur).
	#

	if ( request?$user_name && request$user_name != "" )
	{
		local domain = "";

		if ( request?$domain_name && request$domain_name != "" )
			domain = fmt("%s\\", request$domain_name);

		pth_ntlm_user[src] = fmt("%s%s", domain, request$user_name);
	}

	if ( request?$workstation && request$workstation != "" )
		pth_ntlm_ws[src] = request$workstation;

	if ( ! pth_ntlm_target_seen[src, dst] )
	{
		pth_ntlm_target_seen[src, dst] = T;
		pth_ntlm_target_count[src] += 1;
	}

	print fmt("PTH NTLM AUTH: %s -> %s user=%s ws=%s",
		src,
		dst,
		pth_ntlm_user[src],
		pth_ntlm_ws[src]);

	check_ntlm_behavior(src, dst, c);
}

#
# Clear-text SMB path — only fires when SMB is NOT encrypted.
# Catches the full psexec/atexec signature (ADMIN$ + svcctl/atsvc => RCE).
#

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
{
	local src = c$id$orig_h;
	local dst = c$id$resp_h;

	if ( should_ignore_ip(src) )
		return;

	local upath = to_upper(path);

	if ( /\\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\/ in path )
	{
		add pth_ip_connect[src];
		pth_last[src] = network_time();
	}

	if ( /ADMIN\$/ in upath || /\\C\$/ in upath )
	{
		add pth_admin_share[src];
		pth_last[src] = network_time();

		print fmt("PTH ADMIN SHARE: %s -> %s (%s)", src, dst, path);
	}
}

event smb2_create_request(c: connection, hdr: SMB2::Header,
	request: SMB2::CreateRequest)
{
	local src = c$id$orig_h;
	local dst = c$id$resp_h;

	if ( should_ignore_ip(src) )
		return;

	local pipe = to_lower(request$filename);

	if ( /svcctl/ !in pipe && /atsvc/ !in pipe )
		return;

	add pth_exec_pipe[src];
	pth_last[src] = network_time();

	print fmt("PTH EXEC PIPE: %s -> %s (\\%s)", src, dst, request$filename);

	#
	# Full clear-text PtH exec: admin share + service/task pipe
	#

	if ( src in pth_admin_share && ! pth_exec_alerted[src] )
	{
		pth_exec_alerted[src] = T;

		raise_pth(
			src,
			c,
			fmt("admin share + service/task pipe -> RCE on %s", dst),
			70,
			CyberCity::PtH_Exec,
			"PASS-THE-HASH EXEC"
		);
	}
}
