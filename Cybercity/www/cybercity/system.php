<?php

header('Content-Type: application/json');

$load = sys_getloadavg();

$uptime =
shell_exec("uptime -p");

$memory =
shell_exec("free -m");

$disk =
shell_exec("df -h /");

$result = [

    "cpu" => $load[0],
    "uptime" => trim($uptime),
    "memory" => $memory,
    "disk" => $disk

];

echo json_encode($result);

?>
