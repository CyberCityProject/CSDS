<?php

$db = new SQLite3('/opt/cybercity/db/cybercity.db');

#
# Threat level
#

$threat_query =
$db->query(

    "SELECT COUNT(*) as total
     FROM alerts"

);

$threat_data =
$threat_query->fetchArray();

$total_alerts =
$threat_data['total'];

$threat_level = "LOW";
$threat_color = "#00ff88";

if($total_alerts > 10){

    $threat_level = "MEDIUM";
    $threat_color = "#ffaa00";

}

if($total_alerts > 30){

    $threat_level = "HIGH";
    $threat_color = "#ff3333";

}

#
# Critical attackers
#

$critical =
$db->query(

    "SELECT
        src_ip,
        COUNT(*) as total

     FROM alerts

     GROUP BY src_ip

     HAVING total >= 10

     ORDER BY total DESC

     LIMIT 1"

);

$critical_data =
$critical->fetchArray();

#
# Latest alerts
#

$latest =
$db->query(

    "SELECT *

     FROM alerts

     ORDER BY id DESC

     LIMIT 10"

);

#
# Live events
#

$live =
$db->query(

    "SELECT *

     FROM alerts

     ORDER BY id DESC

     LIMIT 15"

);

#
# Top attackers
#

$attackers =
$db->query(

    "SELECT src_ip,
            COUNT(*) as total

     FROM alerts

     GROUP BY src_ip

     ORDER BY total DESC

     LIMIT 5"

);

#
# Top ports
#

$ports =
$db->query(

    "SELECT port,
            COUNT(*) as total

     FROM alerts

     GROUP BY port

     ORDER BY total DESC

     LIMIT 5"

);

#
# Timeline attacks
#

$timeline =
$db->query(

    "SELECT
        substr(timestamp,1,16) as minute,
        COUNT(*) as total

     FROM alerts

     GROUP BY minute

     ORDER BY minute ASC

     LIMIT 20"

);

$timeline_labels = [];
$timeline_data   = [];

while($row = $timeline->fetchArray()){

    $timeline_labels[] =
    $row['minute'];

    $timeline_data[] =
    $row['total'];

}

$timeline_labels_json =
json_encode($timeline_labels);

$timeline_data_json =
json_encode($timeline_data);

?>

<!DOCTYPE html>

<html>

<head>

<title>CyberCity SOC</title>

<meta http-equiv="refresh" content="10">

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

body{

    background:#050505;
    color:#00ff88;
    font-family:Arial;
    margin:20px;

}

h1,h2{

    color:#00ffaa;

}

.panel{

    border:1px solid #00ff88;
    padding:20px;
    margin-bottom:30px;
    background:#101010;
    box-shadow:0 0 20px rgba(0,255,136,0.15);

}

table{

    width:100%;
    border-collapse:collapse;

}

th,td{

    border:1px solid #00ff88;
    padding:10px;
    text-align:left;

}

th{

    background:#002b1a;

}

.status{

    font-size:64px;
    font-weight:bold;

}

canvas{

    background:#0a0a0a;
    padding:10px;
    border:1px solid #00ff88;

}

tr:hover{

    background:#002b1a;

}

@keyframes blink{

    0%{

        opacity:1;

    }

    50%{

        opacity:0.4;

    }

    100%{

        opacity:1;

    }

}

.terminal{

    background:#000000;
    border:1px solid #00ff88;
    padding:15px;
    height:300px;
    overflow-y:scroll;
    font-family:monospace;
    box-shadow:0 0 20px rgba(0,255,136,0.2);

}

.line{

    margin-bottom:8px;
    color:#00ff88;

}

</style>

</head>

<body>

<h1>CSDS — Cyber Security Daemon System</h1>

<?php

if($critical_data){

?>

<div class="panel"

style="
border:2px solid #ff3333;
box-shadow:0 0 30px #ff3333;
animation: blink 1s infinite;
">

<h2 style="color:#ff3333;">

CRITICAL THREAT DETECTED

</h2>

<p>

Attacker:
<?php echo $critical_data['src_ip']; ?>

</p>

<p>

Alerts:
<?php echo $critical_data['total']; ?>

</p>

</div>

<?php

}

?>

<div class="panel">

<h2>GLOBAL THREAT LEVEL</h2>

<h1 class="status"

style="
color: <?php echo $threat_color; ?>;
text-shadow:0 0 20px <?php echo $threat_color; ?>;
">

<?php echo $threat_level; ?>

</h1>

<p>

Total Alerts:
<?php echo $total_alerts; ?>

</p>

</div>

<div class="panel">

<h2>Attack Timeline</h2>

<canvas id="timelineChart"></canvas>

</div>

<div class="panel">

<h2>LIVE EVENTS TERMINAL</h2>

<div class="terminal">

<?php

while($row = $live->fetchArray()){

    echo "<div class='line'>";

    echo "[".$row['timestamp']."] ";

    echo $row['note']." ";

    echo $row['src_ip']." -> ";

    echo $row['dst_ip'].":".$row['port'];

    echo "</div>";

}

?>

</div>

</div>

<div class="panel">

<h2>Latest Alerts</h2>

<table>

<tr>

<th>ID</th>
<th>Type</th>
<th>Source</th>
<th>Destination</th>
<th>Port</th>
<th>Severity</th>

</tr>

<?php

while($row = $latest->fetchArray()){

    #
    # Severity
    #

    $severity = "LOW";
    $severity_color = "#00ff88";

    if(
        strpos(
            $row['note'],
            'SSH_Bruteforce'
        ) !== false
    ){

        $severity = "HIGH";
        $severity_color = "#ff3333";

    }

    if(
        strpos(
            $row['note'],
            'Scan_Detected'
        ) !== false
    ){

        $severity = "MEDIUM";
        $severity_color = "#ffaa00";

    }

    echo "<tr>";

    echo "<td>".$row['id']."</td>";

    echo "<td>".$row['note']."</td>";

    echo "<td>".$row['src_ip']."</td>";

    echo "<td>".$row['dst_ip']."</td>";

    echo "<td>".$row['port']."</td>";

    echo "<td style='
    color:$severity_color;
    font-weight:bold;
    '>".$severity."</td>";

    echo "</tr>";

}

?>

</table>

</div>

<div class="panel">

<h2>Top Attackers</h2>

<table>

<tr>

<th>IP</th>
<th>Alerts</th>

</tr>

<?php

while($row = $attackers->fetchArray()){

    echo "<tr>";

    echo "<td>".$row['src_ip']."</td>";

    echo "<td>".$row['total']."</td>";

    echo "</tr>";

}

?>

</table>

</div>

<div class="panel">

<h2>Top Targeted Ports</h2>

<table>

<tr>

<th>Port</th>
<th>Hits</th>

</tr>

<?php

while($row = $ports->fetchArray()){

    echo "<tr>";

    echo "<td>".$row['port']."</td>";

    echo "<td>".$row['total']."</td>";

    echo "</tr>";

}

?>

</table>

</div>

<script>

const ctx =
document.getElementById(
'timelineChart'
);

new Chart(ctx, {

    type: 'line',

    data: {

        labels:
        <?php echo $timeline_labels_json; ?>,

        datasets: [{

            label: 'Alerts',

            data:
            <?php echo $timeline_data_json; ?>,

            borderColor: '#00ff88',

            backgroundColor:
            'rgba(0,255,136,0.15)',

            borderWidth: 2,

            tension: 0.3

        }]

    },

    options: {

        responsive: true,

        plugins: {

            legend: {

                labels: {

                    color: '#00ff88'

                }

            }

        },

        scales: {

            x: {

                ticks: {

                    color: '#00ff88'

                }

            },

            y: {

                ticks: {

                    color: '#00ff88'

                }

            }

        }

    }

});

//
// WebSocket Live Events
//

const socket =
new WebSocket(
'ws://192.168.1.39:8080'
);

socket.onmessage = function(event){

    const terminal =
    document.querySelector(
        '.terminal'
    );

    const lines =
    event.data.split('\n');

    lines.forEach(line => {

        if(line.trim() != ''){

            const div =
            document.createElement(
                'div'
            );

            div.className = 'line';

            try{

                const obj =
                JSON.parse(line);

                div.innerText =
                "[" + obj.ts + "] " +
                obj.note + " " +
                obj.src + " -> " +
                obj.dst + ":" +
                obj.p;

            }
            catch(e){

                div.innerText = line;

            }

            terminal.prepend(div);

        }

    });

};

</script>

</body>

</html>
