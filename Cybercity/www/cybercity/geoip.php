<?php

header('Content-Type: application/json');

if(!isset($_GET['ip'])){

    echo json_encode([]);
    exit;

}

$ip = $_GET['ip'];

$url =
"http://ip-api.com/json/" . urlencode($ip);

$response = @file_get_contents($url);

if($response){

    echo $response;

}
else{

    echo json_encode([]);

}

?>
