<?php

header('Content-Type: application/json');

$file = "/opt/cybercity/firewall/blocked_ips.txt";

$data = [];

if(file_exists($file)){

    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    foreach($lines as $line){

        $data[] = $line;

    }

}

echo json_encode($data);

?>
