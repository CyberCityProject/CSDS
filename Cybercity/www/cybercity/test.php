<?php

$file = "/opt/cybercity/zeek/logs/notice.log";

echo "<pre>";

if(file_exists($file)){

    echo "FILE EXISTS\n\n";

    $content = file_get_contents($file);

    if($content){
        echo $content;
    }
    else{
        echo "CANNOT READ FILE";
    }

}
else{

    echo "FILE NOT FOUND";

}

echo "</pre>";

?>
