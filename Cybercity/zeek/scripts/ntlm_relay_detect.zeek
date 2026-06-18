@load base/protocols/smb
@load base/protocols/http
@load /opt/cybercity/zeek/scripts/cybercity_whitelist.zeek
@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load /opt/cybercity/zeek/scripts/correlation_globals.zeek
@load base/frameworks/notice

module CyberCity;

#
# NTLM Relay Detection V1.8
#
# Lab topology:
#   Kali .47    = relay attacker (score + block)
#   Win  .91    = victim / target (observe only, no score)
#   CSDS .39    = trusted sensor
#   Host .98    = trusted
#
# V1.7: explicit ntlm_relay_hosts set (Zeek |table[key]| unreliable with &default=set)
#       skip listener tracking when client is already relay actor (outbound path)
# V1.8: reliable ntlm_listener_count for display; fixed victim_label scope
# V1.9: listener alert is informational only (no score). Fixes false positive
#       where a legit SMB server (DC during secretsdump/psexec) was scored +45
#       as a relay listener. Scoring now only on full inbound+outbound relay.
#

const NTLM_RELAY_WINDOW = 120secs;
const NTLM_RELAY_PAIR_WINDOW = 60secs;
const NTLM_MULTI_TARGET_THRESHOLD = 2;
const NTLM_OUTBOUND_SESSION_THRESHOLD = 1;

event zeek_init()
{
	print "NTLM RELAY DETECT V1.9 LOADED";
}

global ntlm_inbound_victims: table[addr] of set[addr] &default=set();
global ntlm_inbound_last: table[addr] of time &create_expire=NTLM_RELAY_WINDOW;

global ntlm_listener_clients: table[addr] of set[addr] &default=set();
global ntlm_listener_last: table[addr] of time &create_expire=NTLM_RELAY_WINDOW;

global ntlm_outbound_targets: table[addr] of set[addr] &default=set();
global ntlm_outbound_last: table[addr] of time &create_expire=NTLM_RELAY_WINDOW;

global ntlm_smb_targets: table[addr] of set[addr] &default=set();
global ntlm_smb_session_count: table[addr, addr] of count &default=0;
global ntlm_smb_first_seen: table[addr] of time &create_expire=NTLM_RELAY_WINDOW;

global ntlm_http_auth_seen: table[addr] of bool &default=F;
global ntlm_http_auth_count: table[addr] of count &default=0;

global ntlm_ldap_relay_seen: table[addr] of bool &default=F;

global ntlm_victim_ips: set[addr];
global ntlm_relay_hosts: set[addr];
global ntlm_has_outbound: set[addr];
global ntlm_listener_count: table[addr] of count &default=0;

global ntlm_relay_alerted: table[addr] of bool &default=F;
global ntlm_listener_alerted: table[addr] of bool &default=F;
global ntlm_outbound_alerted: table[addr] of bool &default=F;
global ntlm_multi_target_alerted: table[addr] of bool &default=F;
global ntlm_http_smb_chain_alerted: table[addr] of bool &default=F;
global ntlm_ldap_chain_alerted: table[addr] of bool &default=F;

function is_pure_victim(ip: addr): bool
{
	return ip in ntlm_victim_ips &&
	       ip !in ntlm_relay_hosts &&
	       ! ntlm_http_auth_seen[ip];
}

function is_relay_actor(ip: addr): bool
{
	if ( should_ignore_ip(ip) )
		return F;

	return ip in ntlm_relay_hosts || ntlm_http_auth_seen[ip];
}

function is_confirmed_relay_host(ip: addr): bool
{
	if ( should_ignore_ip(ip) || ! is_relay_actor(ip) )
		return F;

	if ( ip !in ntlm_has_outbound )
		return F;

	return T;
}

function track_inbound_ntlm(relay: addr, victim: addr)
{
	if ( should_ignore_ip(relay) || should_ignore_ip(victim) )
		return;

	if ( relay == victim )
		return;

	add ntlm_inbound_victims[relay][victim];
	ntlm_inbound_last[relay] = network_time();

	print fmt(
		"NTLM INBOUND: victim=%s relay=%s",
		victim,
		relay
	);
}

function track_outbound_ntlm(relay: addr, target: addr)
{
	if ( should_ignore_ip(relay) || should_ignore_ip(target) )
		return;

	if ( relay == target )
		return;

	add ntlm_outbound_targets[relay][target];
	add ntlm_has_outbound[relay];
	ntlm_outbound_last[relay] = network_time();

	print fmt(
		"NTLM OUTBOUND: relay=%s target=%s",
		relay,
		target
	);
}

function raise_ntlm_notice(
	relay: addr,
	c: connection,
	reason: string,
	score: count,
	note: Notice::Type,
	label: string
)
{
	if ( should_ignore_ip(relay) )
		return;

	if ( ! is_confirmed_relay_host(relay) )
		return;

	ad_ntlm_relay_seen[relay] = T;
	add_threat(relay, score, label);

	print fmt(
		"%s: %s (%s)",
		label,
		relay,
		reason
	);

	NOTICE([
		$note=note,
		$msg=fmt(
			"%s: %s - %s",
			label,
			relay,
			reason
		),
		$conn=c
	]);
}

function check_listener_alert(relay: addr, c: connection)
{
	if ( ntlm_listener_alerted[relay] )
		return;

	if ( relay !in ntlm_relay_hosts && ! ntlm_http_auth_seen[relay] )
		return;

	ntlm_listener_alerted[relay] = T;

	#
	# V1.9: informational only — receiving inbound NTLM does NOT prove a
	# relay (every SMB server does). Scoring happens only on the full
	# inbound+outbound correlation (NTLM RELAY DETECTED). This avoids
	# false-positiving legit SMB servers (e.g. the DC during secretsdump
	# or psexec) as relay listeners.
	#

	print fmt(
		"NTLM POTENTIAL LISTENER: %s (inbound NTLM from %d client(s)) - awaiting outbound correlation",
		relay,
		ntlm_listener_count[relay]
	);
}

function correlate_relay_hit(relay: addr, target: addr, c: connection)
{
	if ( should_ignore_ip(relay) || ntlm_relay_alerted[relay] )
		return;

	if ( relay !in ntlm_relay_hosts && ! ntlm_http_auth_seen[relay] )
		return;

	if ( relay !in ntlm_has_outbound )
		return;

	if ( relay !in ntlm_outbound_last )
		return;

	local outbound_age = network_time() - ntlm_outbound_last[relay];

	if ( outbound_age > NTLM_RELAY_PAIR_WINDOW )
		return;

	local victim_label = fmt("%s", target);

	for ( client in ntlm_listener_clients[relay] )
	{
		victim_label = fmt("%s", client);
		break;
	}

	ntlm_relay_alerted[relay] = T;

	raise_ntlm_notice(
		relay,
		c,
		fmt("victim %s relayed to target %s", victim_label, target),
		80,
		CyberCity::NTLM_Relay_Detected,
		"NTLM RELAY DETECTED"
	);
}

function check_inbound_outbound_pair(relay: addr, c: connection)
{
	if ( should_ignore_ip(relay) || ntlm_relay_alerted[relay] )
		return;

	if ( ! is_confirmed_relay_host(relay) )
		return;

	local has_inbound = relay in ntlm_inbound_last;
	local has_listener = relay in ntlm_relay_hosts;
	local has_http = ntlm_http_auth_seen[relay];

	if ( relay !in ntlm_outbound_last )
		return;

	local outbound_age = network_time() - ntlm_outbound_last[relay];

	if ( outbound_age > NTLM_RELAY_PAIR_WINDOW )
		return;

	if ( has_inbound && relay in ntlm_inbound_last )
	{
		local inbound_age = network_time() - ntlm_inbound_last[relay];

		if ( inbound_age > NTLM_RELAY_PAIR_WINDOW )
			has_inbound = F;
	}

	if ( has_listener && relay in ntlm_listener_last )
	{
		local listener_age = network_time() - ntlm_listener_last[relay];

		if ( listener_age > NTLM_RELAY_PAIR_WINDOW )
			has_listener = F;
	}

	local victim_label = "";

	for ( target in ntlm_outbound_targets[relay] )
	{
		if ( has_listener )
		{
			victim_label = fmt("%s", target);

			for ( client in ntlm_listener_clients[relay] )
			{
				victim_label = fmt("%s", client);
				break;
			}

			ntlm_relay_alerted[relay] = T;

			raise_ntlm_notice(
				relay,
				c,
				fmt("victim %s relayed to target %s", victim_label, target),
				80,
				CyberCity::NTLM_Relay_Detected,
				"NTLM RELAY DETECTED"
			);

			return;
		}

		if ( has_inbound )
		{
			victim_label = fmt("%s", target);

			for ( victim in ntlm_inbound_victims[relay] )
			{
				victim_label = fmt("%s", victim);
				break;
			}

			ntlm_relay_alerted[relay] = T;

			raise_ntlm_notice(
				relay,
				c,
				fmt("victim %s relayed to target %s", victim_label, target),
				80,
				CyberCity::NTLM_Relay_Detected,
				"NTLM RELAY DETECTED"
			);

			return;
		}

		if ( has_http )
		{
			ntlm_relay_alerted[relay] = T;

			raise_ntlm_notice(
				relay,
				c,
				fmt("HTTP NTLM listener relayed to target %s", target),
				80,
				CyberCity::NTLM_Relay_Detected,
				"NTLM RELAY DETECTED"
			);

			return;
		}
	}
}

function check_outbound_relay(relay: addr, target: addr, c: connection)
{
	if ( ntlm_outbound_alerted[relay] || ntlm_relay_alerted[relay] )
		return;

	if ( should_ignore_ip(relay) || ! is_relay_actor(relay) )
		return;

	if ( c$id$resp_p != 445/tcp )
		return;

	local sessions = ntlm_smb_session_count[relay, target];

	if ( sessions < NTLM_OUTBOUND_SESSION_THRESHOLD )
		return;

	check_inbound_outbound_pair(relay, c);

	if ( ntlm_relay_alerted[relay] )
		return;

	if ( ! is_confirmed_relay_host(relay) )
		return;

	ntlm_outbound_alerted[relay] = T;

	raise_ntlm_notice(
		relay,
		c,
		fmt("SMB NTLM session setup to %s (sessions=%d)", target, sessions),
		55,
		CyberCity::NTLM_Relay_Outbound,
		"NTLM RELAY OUTBOUND"
	);
}

function recheck_relay_outbound(relay: addr, c: connection)
{
	if ( should_ignore_ip(relay) || ! is_relay_actor(relay) )
		return;

	for ( target in ntlm_smb_targets[relay] )
		check_outbound_relay(relay, target, c);
}

function check_multi_target_relay(relay: addr, c: connection)
{
	if ( ntlm_multi_target_alerted[relay] || should_ignore_ip(relay) )
		return;

	if ( ! is_confirmed_relay_host(relay) )
		return;

	if ( |ntlm_smb_targets[relay]| < NTLM_MULTI_TARGET_THRESHOLD )
		return;

	ntlm_multi_target_alerted[relay] = T;
	ad_ntlm_relay_seen[relay] = T;

	add_threat(
		relay,
		60,
		"NTLM Multi-Target Relay"
	);

	print fmt(
		"NTLM MULTI-TARGET RELAY: %s targets=%d",
		relay,
		|ntlm_smb_targets[relay]|
	);

	NOTICE([
		$note=CyberCity::NTLM_Multi_Target_Relay,
		$msg=fmt(
			"NTLM MULTI-TARGET RELAY: %s (%d SMB auth targets)",
			relay,
			|ntlm_smb_targets[relay]|
		),
		$conn=c
	]);
}

function check_http_smb_chain(relay: addr, c: connection)
{
	if ( ntlm_http_smb_chain_alerted[relay] || should_ignore_ip(relay) )
		return;

	if ( ! is_confirmed_relay_host(relay) )
		return;

	if ( ! ntlm_http_auth_seen[relay] )
		return;

	if ( relay !in ntlm_has_outbound )
		return;

	ntlm_http_smb_chain_alerted[relay] = T;
	ad_ntlm_relay_seen[relay] = T;

	add_threat(
		relay,
		90,
		"NTLM HTTP-to-SMB Relay"
	);

	print fmt(
		"NTLM HTTP->SMB RELAY: %s",
		relay
	);

	NOTICE([
		$note=CyberCity::NTLM_HTTP_SMB_Relay,
		$msg=fmt(
			"NTLM HTTP-TO-SMB RELAY: %s (HTTP NTLM listener + SMB relay)",
			relay
		),
		$conn=c
	]);
}

function check_ldap_relay_chain(relay: addr, c: connection)
{
	if ( ntlm_ldap_chain_alerted[relay] || should_ignore_ip(relay) )
		return;

	if ( ! is_confirmed_relay_host(relay) )
		return;

	if ( ! ntlm_ldap_relay_seen[relay] )
		return;

	ntlm_ldap_chain_alerted[relay] = T;
	ad_ntlm_relay_seen[relay] = T;

	add_threat(
		relay,
		85,
		"NTLM LDAP Relay"
	);

	print fmt(
		"NTLM LDAP RELAY: %s",
		relay
	);

	NOTICE([
		$note=CyberCity::NTLM_LDAP_Relay,
		$msg=fmt(
			"NTLM LDAP RELAY: %s (inbound NTLM + outbound LDAP auth)",
			relay
		),
		$conn=c
	]);
}

function track_listener_auth(relay: addr, client: addr, c: connection)
{
	if ( should_ignore_ip(relay) || should_ignore_ip(client) )
		return;

	if ( relay == client )
		return;

	#
	# Outbound relay session (Kali -> target) — not victim auth to listener
	#

	if ( is_relay_actor(client) )
		return;

	#
	# Target/victim host receiving relay return traffic — not a listener
	#

	if ( is_pure_victim(relay) )
	{
		print fmt(
			"NTLM SKIP LISTENER: %s is victim not relay",
			relay
		);
		return;
	}

	add ntlm_victim_ips[client];
	add ntlm_listener_clients[relay][client];
	add ntlm_relay_hosts[relay];
	ntlm_listener_count[relay] += 1;
	ntlm_listener_last[relay] = network_time();

	track_inbound_ntlm(relay, client);

	print fmt(
		"NTLM LISTENER HIT: client=%s relay=%s",
		client,
		relay
	);

	check_listener_alert(relay, c);
	recheck_relay_outbound(relay, c);
}

function handle_relay_outbound(client: addr, server: addr, c: connection)
{
	if ( should_ignore_ip(client) || should_ignore_ip(server) )
		return;

	if ( is_pure_victim(client) )
	{
		print fmt(
			"NTLM SKIP OUTBOUND: %s is victim not relay",
			client
		);
		return;
	}

	if ( ! is_relay_actor(client) )
		return;

	track_outbound_ntlm(client, server);
	correlate_relay_hit(client, server, c);
	check_outbound_relay(client, server, c);
	check_inbound_outbound_pair(client, c);
	check_multi_target_relay(client, c);
	check_http_smb_chain(client, c);
}

function handle_ntlm_session_setup(c: connection)
{
	local client = c$id$orig_h;
	local server = c$id$resp_h;

	if ( should_ignore_ip(client) && should_ignore_ip(server) )
		return;

	print fmt(
		"NTLM SMB SESSION: %s -> %s:%s",
		client,
		server,
		c$id$resp_p
	);

	if ( ! should_ignore_ip(client) )
	{
		if ( client !in ntlm_smb_first_seen )
			ntlm_smb_first_seen[client] = network_time();

		add ntlm_smb_targets[client][server];
		ntlm_smb_session_count[client, server] += 1;
	}

	#
	# Relay outbound first (Kali -> target) when client already confirmed relay
	#

	if ( is_relay_actor(client) )
	{
		handle_relay_outbound(client, server, c);
		return;
	}

	#
	# Victim NTLM auth arriving at relay listener (Win -> Kali)
	#

	if ( ! should_ignore_ip(server) && ! should_ignore_ip(client) )
		track_listener_auth(server, client, c);

	#
	# Pure victim SMB client — no outbound relay scoring
	#

	if ( is_pure_victim(client) )
	{
		print fmt(
			"NTLM SKIP OUTBOUND: %s is victim not relay",
			client
		);
	}
}

event smb2_session_setup_request(
	c: connection,
	hdr: SMB2::Header,
	request: SMB2::SessionSetupRequest
)
{
	handle_ntlm_session_setup(c);
}

event smb1_session_setup_andx_request(
	c: connection,
	header: SMB1::Header,
	andx: SMB1::SessionSetupAndXRequest
)
{
	handle_ntlm_session_setup(c);
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	if ( ! is_orig )
		return;

	if ( to_upper(name) != "AUTHORIZATION" )
		return;

	local auth_value = to_upper(value);

	if ( /^NTLM / !in auth_value )
		return;

	local client = c$id$orig_h;
	local server = c$id$resp_h;

	if ( should_ignore_ip(client) && should_ignore_ip(server) )
		return;

	print fmt(
		"NTLM HTTP AUTH: %s -> %s",
		client,
		server
	);

	if ( ! should_ignore_ip(server) && ! should_ignore_ip(client) )
	{
		if ( ! is_pure_victim(server) && ! is_relay_actor(client) )
		{
			add ntlm_victim_ips[client];
			add ntlm_listener_clients[server][client];
			add ntlm_relay_hosts[server];
			ntlm_listener_count[server] += 1;
			ntlm_listener_last[server] = network_time();
			track_inbound_ntlm(server, client);
			ntlm_http_auth_seen[server] = T;
			ntlm_http_auth_count[server] += 1;
			check_listener_alert(server, c);
			recheck_relay_outbound(server, c);
		}
	}
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
	if ( code != 401 )
		return;

	local server = c$id$resp_h;

	if ( should_ignore_ip(server) || is_pure_victim(server) )
		return;

	ntlm_http_auth_seen[server] = T;

	print fmt(
		"NTLM HTTP CHALLENGE: relay listener %s",
		server
	);
}

event new_connection(c: connection)
{
	local src = c$id$orig_h;
	local dst = c$id$resp_h;
	local dst_p = c$id$resp_p;

	if ( dst_p == 445/tcp || dst_p == 80/tcp || dst_p == 389/tcp || dst_p == 636/tcp )
	{
		if ( ! should_ignore_ip(src) || ! should_ignore_ip(dst) )
		{
			print fmt(
				"NTLM WATCH: %s -> %s:%s",
				src,
				dst,
				dst_p
			);
		}
	}

	if ( dst_p != 389/tcp && dst_p != 636/tcp )
		return;

	if ( should_ignore_ip(src) || is_pure_victim(src) )
		return;

	if ( ! is_relay_actor(src) && ! ntlm_http_auth_seen[src] )
		return;

	if ( src !in ntlm_has_outbound && src !in ntlm_smb_first_seen &&
	     ! ntlm_http_auth_seen[src] )
		return;

	ntlm_ldap_relay_seen[src] = T;
	track_outbound_ntlm(src, dst);

	check_ldap_relay_chain(src, c);
	check_inbound_outbound_pair(src, c);
}
