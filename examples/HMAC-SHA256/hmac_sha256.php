<?php
    $s = hash_hmac('sha256', 'Message', 'secret', false);
    //echo base64_encode($s);
    echo $s;
    echo "\n";
?>