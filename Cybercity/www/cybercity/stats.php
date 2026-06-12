<?php

header('Content-Type: application/json');

$logfile = "/opt/cybercity/zeek/logs/notice.log";

$result = [

    "total" => 0,
    "scans" => 0,
    "bruteforce" => 0,
    "ports" => []

];

if(file_exists($logfile)){

    $lines = file($logfile,
        FILE_IGNORE_NEW_LINES |
        FILE_SKIP_EMPTY_LINES);

    foreach($lines as $line){

        $json = json_decode($line, true);

        if(!$json){
            continue;
        }

        $result["total"]++;

        if(isset($json["note"])){

            if(strpos($json["note"], "Scan") !== false){

                $result["scans"]++;

            }

            if(strpos($json["note"], "Bruteforce") !== false){

                $result["bruteforce"]++;

            }

        }

        if(isset($json["p"])){

            $port = $json["p"];

            if(!isset($result["ports"][$port])){

                $result["ports"][$port] = 0;

            }

            $result["ports"][$port]++;

        }

    }

}

arsort($result["ports"]);

echo json_encode($result);

?>
