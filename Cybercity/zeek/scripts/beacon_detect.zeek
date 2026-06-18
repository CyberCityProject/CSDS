@load /opt/cybercity/zeek/scripts/cybercity_whitelist.zeek
@load /opt/cybercity/zeek/scripts/cybercity_alerts.zeek
@load /opt/cybercity/zeek/scripts/threat_score.zeek
@load base/frameworks/notice

module CyberCity;

#
# Beacon (C2) Detection V2.0
#
# Detects command-and-control beaconing by measuring the REGULARITY of repeated
# connections from one host to one destination, instead of matching a fixed
# interval window. Real C2 (Cobalt Strike, Sliver, Metasploit) calls back at a
# steady interval with some jitter. We flag low-variance interval patterns.
#
# Method (RITA-style):
#   - collect connection start times per (src, dst, port)
#   - once enough samples exist, compute the inter-arrival intervals
#   - mean interval must be in a plausible C2 range
#   - coefficient of variation (stddev / mean) must be low (= very regular)
#
# This catches any beacon period (5s, 60s, 5min...) as long as it is regular,
# and tolerates jitter up to ~25%.
#

const BEACON_MIN_SAMPLES = 6;          # connections needed before evaluating
const BEACON_MAX_SAMPLES = 12;         # cap stored timestamps per key
const BEACON_MIN_INTERVAL = 5.0;       # seconds — ignore faster app chatter
const BEACON_MAX_INTERVAL = 1800.0;    # seconds — ignore very slow / unrelated
const BEACON_CV_MAX = 0.25;            # max coefficient of variation (jitter)

global beacon_times: table[addr, addr, port] of vector of time;
global beacon_alerted: table[addr, addr, port] of bool &default=F;

event zeek_init()
{
	print "CyberCity Beacon Detection V2.0 Loaded";
}

function evaluate_beacon(orig: addr, resp: addr, p: port, c: connection)
{
	local times = beacon_times[orig, resp, p];
	local n = |times|;

	if ( n < BEACON_MIN_SAMPLES )
		return;

	#
	# Inter-arrival intervals (seconds)
	#

	local sum = 0.0;
	local intervals: vector of double;
	local i = 1;

	while ( i < n )
	{
		local d = interval_to_double(times[i] - times[i - 1]);
		intervals[|intervals|] = d;
		sum += d;
		i += 1;
	}

	local k = |intervals|;

	if ( k == 0 )
		return;

	local mean = sum / k;

	if ( mean < BEACON_MIN_INTERVAL || mean > BEACON_MAX_INTERVAL )
		return;

	#
	# Standard deviation of the intervals
	#

	local var = 0.0;
	local j = 0;

	while ( j < k )
	{
		local diff = intervals[j] - mean;
		var += diff * diff;
		j += 1;
	}

	var = var / k;

	local sd = sqrt(var);
	local cv = sd / mean;

	if ( cv > BEACON_CV_MAX )
		return;

	#
	# Confident beacon: regular interval, low jitter
	#

	if ( beacon_alerted[orig, resp, p] )
		return;

	beacon_alerted[orig, resp, p] = T;

	add_threat(orig, 50, "Beacon Activity");

	print fmt(
		"BEACON DETECTED: %s -> %s:%s (interval ~%.1fs, jitter %.0f%%, %d samples)",
		orig,
		resp,
		p,
		mean,
		cv * 100,
		n
	);

	NOTICE([
		$note=CyberCity::Beacon_Detected,
		$msg=fmt(
			"BEACON DETECTED: %s -> %s:%s (interval ~%.1fs, jitter %.0f%%)",
			orig,
			resp,
			p,
			mean,
			cv * 100
		),
		$conn=c
	]);
}

event connection_state_remove(c: connection)
{
	local orig = c$id$orig_h;
	local resp = c$id$resp_h;
	local p = c$id$resp_p;

	if ( should_ignore_ip(orig) )
		return;

	if ( p != 80/tcp && p != 443/tcp )
		return;

	local start = c$start_time;

	#
	# Append start time, keeping only the last BEACON_MAX_SAMPLES
	#

	local times: vector of time;

	if ( [orig, resp, p] in beacon_times )
		times = beacon_times[orig, resp, p];

	times[|times|] = start;

	if ( |times| > BEACON_MAX_SAMPLES )
	{
		local trimmed: vector of time;
		local drop = |times| - BEACON_MAX_SAMPLES;
		local i = drop;

		while ( i < |times| )
		{
			trimmed[|trimmed|] = times[i];
			i += 1;
		}

		times = trimmed;
	}

	beacon_times[orig, resp, p] = times;

	evaluate_beacon(orig, resp, p, c);
}
