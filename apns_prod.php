<?php

    $localhost = $_SERVER['SERVER_ADDR'] == '127.0.0.1';
    $certificate = $localhost ? 'apns_prod.pem' : '../../apns_prod.pem';

    header('Content-Type: application/json');

    function exitSuccess($json, $handle = false) {
        exit(json_encode(array(
            'status' => 'success',
            'data' => $json
        )));

        if ($handle) fclose($handle);
    }

    function exitError($json, $handle = false) {
        exit(json_encode(array(
            'status' => 'error',
            'message' => $json
        )));

        if ($handle) fclose($handle);
    }

    if (isset($_GET['debug']) && $localhost) {
        $_POST['deviceToken'] = 'ce059d008c1ea4977c99c354dd2c9fcffa44d809784b84c1c1064ce6b873db75';
        $_POST['raivoType'] = '1';
        $_POST['raivoToken'] = '123456';
        $_POST['raivoIssuer'] = 'Microsoft';
        $_POST['raivoAccount'] = 'john.doe@outlook.com';
    }

    $deviceToken = isset($_POST['deviceToken']) && strlen($_POST['deviceToken']) == 64 ? $_POST['deviceToken'] : null;
    $raivoType = isset($_POST['raivoType']) && !empty($_POST['raivoType']) ? (int) $_POST['raivoType'] : null;
    $raivoToken = isset($_POST['raivoToken']) && !empty($_POST['raivoToken']) ? $_POST['raivoToken'] : null;
    $raivoIssuer = isset($_POST['raivoIssuer']) && !empty($_POST['raivoIssuer']) ? $_POST['raivoIssuer'] : null;
    $raivoAccount = isset($_POST['raivoAccount']) && !empty($_POST['raivoAccount']) ? $_POST['raivoAccount'] : null;

    if (is_null($deviceToken)) {
        exitError('Incorrect deviceToken');
    }
    
    if (is_null($raivoType) || !in_array($raivoType, [1])) {
        exitError('Incorrect raivoType');
    }
    
    if (is_null($raivoToken) || strlen($raivoToken) < 4 || strlen($raivoToken) > 8) {
        exitError('Incorrect raivoToken');
    }
    
    if (is_null($raivoIssuer)) {
        exitError('Incorrect raivoIssuer');
    }
    
    if (is_null($raivoAccount)) {
        exitError('Incorrect raivoAccount');
    }

    $host = 'ssl://gateway.push.apple.com:2195';
    $options = STREAM_CLIENT_CONNECT|STREAM_CLIENT_PERSISTENT;

    $streamContext = stream_context_create();
    stream_context_set_option($streamContext, 'ssl', 'local_cert', $certificate);
    $handle = stream_socket_client($host, $err, $errstr, 60, $options, $streamContext); 

    if(!$handle) {
        exitError('failed to connect');
    }

    $body = json_encode(array(
        'type' => $raivoType,
        'token' => $raivoToken,
        'issuer' => $raivoIssuer,
        'account' => $raivoAccount
    ));

    $payload = chr(0) . pack('n', 32) . pack('H*', $deviceToken) . pack('n', strlen($body)) . $body;
    $result = fwrite($handle, $payload, strlen($payload));

    if ($result) {
        exitSuccess('notification delivered', $handle);
    } else {
        exitError('notification not delivered', $handle);
    }