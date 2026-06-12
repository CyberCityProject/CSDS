<!DOCTYPE html>
<html lang="fr">

<head>

<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>CyberCity SOC Dashboard</title>

<link rel="stylesheet" href="style.css">

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

</head>

<body>

<h1>CyberCity SOC Dashboard</h1>

<div class="stats">

    <div class="card">
        <h2 id="totalAlerts">0</h2>
        <p>Total Alerts</p>
    </div>

    <div class="card">
        <h2 id="topIP">-</h2>
        <p>Top Attacker</p>
    </div>

    <div class="card">
        <h2 id="blockedIPs">0</h2>
        <p>Blocked IPs</p>
    </div>

    <div class="card">
        <h2 id="topPort">-</h2>
        <p>Top Target Port</p>
    </div>

    <div class="card">
        <h2 id="threatLevel">LOW</h2>
        <p>Threat Level</p>
    </div>

    <div class="card">
        <h2 id="cpuLoad">0</h2>
        <p>CPU Load</p>
    </div>

    <div class="card">
        <h2 id="uptime">-</h2>
        <p>System Uptime</p>
    </div>

</div>

<h2 style="text-align:center; margin-top:40px;">
Live Activity
</h2>

<div class="container" id="timeline"></div>

<h2 style="text-align:center; margin-top:40px;">
Security Alerts
</h2>

<div class="container" id="alerts"></div>

<h2 style="text-align:center; margin-top:40px;">
Historical Top Attackers
</h2>

<div class="container" id="history"></div>

<h2 style="text-align:center; margin-top:40px;">
Attack Activity
</h2>

<div class="container">

<canvas id="activityChart"></canvas>

</div>

<script>

let activityChart = null;

const socket = new WebSocket(
    "ws://192.168.1.39:8080"
);

socket.onopen = () => {

    console.log(
        "CyberCity WS Connected"
    );

};

socket.onmessage = (event) => {

    console.log(
        "Realtime Alert:",
        event.data
    );

    loadAlerts();
    loadTimeline();
    loadStats();
    loadHistory();
    loadChart();

};

socket.onerror = (error) => {

    console.log(
        "WebSocket Error:",
        error
    );

};

socket.onclose = () => {

    console.log(
        "WebSocket Closed"
    );

};

async function loadGeoIPSafe(ip, safeID){

    try{

        let geo =
        document.getElementById(
            "geo-" + safeID
        );

        if(!geo){
            return;
        }

        if(

            ip.startsWith("192.168.") ||

            ip.startsWith("10.") ||

            ip.startsWith("172.16.") ||

            ip.startsWith("172.17.") ||

            ip.startsWith("172.18.") ||

            ip.startsWith("172.19.") ||

            ip.startsWith("172.20.") ||

            ip.startsWith("172.21.") ||

            ip.startsWith("172.22.") ||

            ip.startsWith("172.23.") ||

            ip.startsWith("172.24.") ||

            ip.startsWith("172.25.") ||

            ip.startsWith("172.26.") ||

            ip.startsWith("172.27.") ||

            ip.startsWith("172.28.") ||

            ip.startsWith("172.29.") ||

            ip.startsWith("172.30.") ||

            ip.startsWith("172.31.") ||

            ip === "127.0.0.1"

        ){

            geo.innerHTML =
            "Private / Internal Network";

            return;

        }

        let response =
        await fetch("geoip.php?ip=" + ip);

        let data =
        await response.json();

        if(data.country){

            geo.innerHTML =

            data.country +
            " | " +
            data.isp;

        }
        else{

            geo.innerHTML =
            "Unknown Location";

        }

    }
    catch(error){

        console.log(
            "GeoIP loading error:",
            error
        );

    }

}

async function loadAlerts(){

    try{

        let response =
        await fetch("alerts.php");

        let data =
        await response.json();

        let container =
        document.getElementById("alerts");

        container.innerHTML = "";

        document.getElementById(
            "totalAlerts"
        ).innerText = data.length;

        let attackers = {};

        data.forEach(alert => {

            if(alert.src){

                attackers[alert.src] =

                (attackers[alert.src] || 0)
                + 1;

            }

        });

        let top = "-";
        let max = 0;

        for(let ip in attackers){

            if(attackers[ip] > max){

                max = attackers[ip];
                top = ip;

            }

        }

        document.getElementById(
            "topIP"
        ).innerText = top;

        data.forEach(alert => {

            let div =
            document.createElement("div");

            let level = "low";

            if(

                alert.note &&

                alert.note.includes(
                    "Bruteforce"
                )

            ){

                level = "high";

            }
            else if(

                alert.note &&

                alert.note.includes(
                    "Scan"
                )

            ){

                level = "medium";

            }

            div.className =
            "alert " + level;

            let timestamp =

            parseFloat(alert.ts || 0)
            * 1000;

            let date =
            new Date(timestamp);

            let safeIP =

            (alert.src || "unknown")

            .replace(/\./g, "-");

            div.innerHTML = `

            <div class="time">
            ${date.toLocaleString()}
            </div>

            <div class="note">
            ${alert.note || "UNKNOWN"}
            </div>

            <div class="msg">
            ${alert.msg || ""}
            </div>

            <div class="ip">
            ${alert.src || "?"}
            →
            ${alert.dst || "?"}
            </div>

            <div class="geo"
            id="geo-${safeIP}">
            Loading GEOIP...
            </div>

            `;

            container.appendChild(div);

            if(alert.src){

                loadGeoIPSafe(
                    alert.src,
                    safeIP
                );

            }

        });

    }
    catch(error){

        console.log(
            "Alert loading error:",
            error
        );

    }

}

async function loadFirewall(){

    try{

        let response =
        await fetch("firewall.php");

        let data =
        await response.json();

        document.getElementById(
            "blockedIPs"
        ).innerText = data.length;

    }
    catch(error){

        console.log(
            "Firewall loading error:",
            error
        );

    }

}

async function loadStats(){

    try{

        let response =
        await fetch("stats.php");

        let data =
        await response.json();

        let ports = data.ports;

        let topPort = "-";

        for(let port in ports){

            topPort = port;
            break;

        }

        document.getElementById(
            "topPort"
        ).innerText = topPort;

        let level = "LOW";

        if(data.total >= 20){

            level = "HIGH";

        }
        else if(data.total >= 10){

            level = "MEDIUM";

        }

        document.getElementById(
            "threatLevel"
        ).innerText = level;

    }
    catch(error){

        console.log(
            "Stats loading error:",
            error
        );

    }

}

async function loadTimeline(){

    try{

        let response =
        await fetch("alerts.php");

        let data =
        await response.json();

        let timeline =
        document.getElementById(
            "timeline"
        );

        timeline.innerHTML = "";

        data.slice(0, 10).forEach(alert => {

            let div =
            document.createElement("div");

            div.className =
            "alert medium";

            let timestamp =

            parseFloat(alert.ts || 0)
            * 1000;

            let date =
            new Date(timestamp);

            div.innerHTML = `

            <div class="time">
            ${date.toLocaleTimeString()}
            </div>

            <div class="msg">
            ${alert.msg || ""}
            </div>

            `;

            timeline.appendChild(div);

        });

    }
    catch(error){

        console.log(
            "Timeline loading error:",
            error
        );

    }

}

async function loadHistory(){

    try{

        let response =
        await fetch("history.php");

        let data =
        await response.json();

        let history =
        document.getElementById(
            "history"
        );

        history.innerHTML = "";

        data.forEach(item => {

            let div =
            document.createElement("div");

            div.className =
            "alert low";

            div.innerHTML = `

            <div class="msg">
            ${item.src_ip}
            </div>

            <div class="note">
            ${item.total} alerts
            </div>

            `;

            history.appendChild(div);

        });

    }
    catch(error){

        console.log(
            "History loading error:",
            error
        );

    }

}

async function loadChart(){

    try{

        let response =
        await fetch("alerts.php");

        let data =
        await response.json();

        let labels = [];
        let values = [];

        let grouped = {};

        data.forEach(alert => {

            let timestamp =

            parseFloat(alert.ts || 0)
            * 1000;

            let date =
            new Date(timestamp);

            let key =

            date.getHours() + ":" +

            String(
                date.getMinutes()
            ).padStart(2,'0');

            grouped[key] =

            (grouped[key] || 0) + 1;

        });

        for(let key in grouped){

            labels.push(key);
            values.push(grouped[key]);

        }

        let ctx =
        document.getElementById(
            "activityChart"
        );

        if(activityChart){

            activityChart.destroy();

        }

        activityChart = new Chart(ctx, {

            type: "line",

            data: {

                labels: labels,

                datasets: [{

                    label:
                    "Attack Activity",

                    data: values,

                    borderColor:
                    "#00ff88",

                    backgroundColor:

                    "rgba(0,255,136,0.2)",

                    tension: 0.3

                }]

            },

            options: {

                responsive: true,

                plugins: {

                    legend: {

                        labels: {

                            color:
                            "#00ff88"

                        }

                    }

                },

                scales: {

                    x: {

                        ticks: {

                            color:
                            "#00ff88"

                        }

                    },

                    y: {

                        ticks: {

                            color:
                            "#00ff88"

                        }

                    }

                }

            }

        });

    }
    catch(error){

        console.log(
            "Chart loading error:",
            error
        );

    }

}

async function loadSystem(){

    try{

        let response =
        await fetch("system.php");

        let data =
        await response.json();

        document.getElementById(
            "cpuLoad"
        ).innerText = data.cpu;

        document.getElementById(
            "uptime"
        ).innerText = data.uptime;

    }
    catch(error){

        console.log(
            "System loading error:",
            error
        );

    }

}

loadAlerts();
loadFirewall();
loadStats();
loadTimeline();
loadHistory();
loadChart();
loadSystem();

setInterval(loadAlerts, 5000);
setInterval(loadFirewall, 5000);
setInterval(loadStats, 5000);
setInterval(loadTimeline, 5000);
setInterval(loadHistory, 10000);
setInterval(loadChart, 10000);
setInterval(loadSystem, 10000);

</script>

</body>

</html>
