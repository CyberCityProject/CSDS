<?php

$db = new SQLite3('/opt/cybercity/db/cybercity.db');

$logfile = "/opt/cybercity/zeek/logs/notice.log";

if(!file_exists($logfile)){
    exit;
}

$lines = file($logfile,
    FILE_IGNORE_NEW_LINES |
    FILE_SKIP_EMPTY_LINES);

foreach($lines as $line){

    $json = json_decode($line, true);

    if(!$json){
        continue;
    }

    $timestamp =
    date('Y-m-d H:i:s', $json['ts']);

    $note = $json['note'] ?? '';
    $msg  = $json['msg'] ?? '';
    $src  = $json['src'] ?? '';
    $dst  = $json['dst'] ?? '';
    $port = $json['p'] ?? 0;

    $stmt = $db->prepare('
        INSERT INTO alerts
        (timestamp,note,message,src_ip,dst_ip,port)
        VALUES
        (:timestamp,:note,:message,:src,:dst,:port)
    ');

    $stmt->bindValue(':timestamp', $timestamp);
    $stmt->bindValue(':note', $note);
    $stmt->bindValue(':message', $msg);
    $stmt->bindValue(':src', $src);
    $stmt->bindValue(':dst', $dst);
    $stmt->bindValue(':port', $port);

    $stmt->execute();

}

echo "Import OK\n";

?>
