<?php

header('Content-Type: application/json');

$db = new SQLite3('/opt/cybercity/db/cybercity.db');

$result = [];

$query = "

SELECT
src_ip,
COUNT(*) as total

FROM alerts

GROUP BY src_ip

ORDER BY total DESC

LIMIT 10

";

$res = $db->query($query);

while($row = $res->fetchArray(SQLITE3_ASSOC)){

    $result[] = $row;

}

echo json_encode($result);

?>
