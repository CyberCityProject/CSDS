<?php

header('Content-Type: application/json');

$logfile = "/opt/cybercity/zeek/logs/notice.log";

if (!file_exists($logfile)) {
    echo json_encode([]);
    exit;
}

$lines = file($logfile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

$data = [];

foreach(array_reverse($lines) as $line){

    $json = json_decode($line, true);

    if($json){
        $data[] = $json;
    }

    if(count($data) >= 50){
        break;
    }
}

echo json_encode($data, JSON_PRETTY_PRINT);

?>
