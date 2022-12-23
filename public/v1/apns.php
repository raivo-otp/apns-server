<?php

    /* Raivo OTP APNS
     * 
     * Workflow:
     *      1. iPhone: Scans MacOS receiver QR-code (containing MacOS push token & MacOS encryption key)
     *      2. iPhone: Sends MacOS receiver a type 1 (copy to clipboard) notification containing a password, encrypted with the encryption key
     */

    // All output data should be JSON
    header('Content-Type: application/json');

    // Helper function for I/O
    function respondWith(string $message, bool $success = true) {
        exit(json_encode(array(
            'status' => $success ? 'success' : 'error',
            'message' => $message
        )));
    }

    // Read INI configuration
    $ini = parse_ini_file(realpath(dirname(__FILE__) . '/../../apns_config.ini'), true, INI_SCANNER_TYPED);

    if ($ini === false) {
        respondWith('Could not read configuration file.', false);
    }

    // Define settings
    define('APNS_PRODUCTION', $ini['server']['production']);
    define('APNS_DEVELOPMENT', !APNS_PRODUCTION);
    define('APNS_TEAMID', $ini['authentication']['team_id']);
    define('APNS_KEYID', $ini['authentication']['key_id']);
    define('APNS_AUTHKEY', openssl_pkey_get_private(base64_decode($ini['authentication']['key'])));
    define('APNS_BUNDLEID', 'me.tij.Raivo-MacOS');
    define('APNS_URI', APNS_PRODUCTION ? 'https://api.push.apple.com' : 'https://api.sandbox.push.apple.com');

    // Show PHP errors in development runs
    if (APNS_DEVELOPMENT) {
        error_reporting(E_ALL);
        ini_set('display_errors', 1);
    }

    // Helper function to retrieve user input (string)
    function getUserInputString(array $values, string $key): ?string {
        if (isset($values[$key]) && is_string($values[$key])) {
            return $values[$key];
        }

        return null;
    }

    // Helper function to retrieve user input (int)
    function getUserInputInt(array $values, string $key): ?int {
        if (isset($values[$key]) && is_numeric($values[$key])) {
            return $values[$key];
        }

        return null;
    }

    // Helper function to base64 encode replacing +/ with -_ and trimming = signs
    function base64(array $data): string {
        return rtrim(strtr(base64_encode(json_encode($data)), '+/', '-_'), '=');
    }

    // Validate authentication key
    if (APNS_AUTHKEY === false) {
        respondWith('Fatal misconfiguration. Could not find the authentication key on the server.');
    }

    // Validate device tokens
    if (count($_POST) > 10) {
        respondWith('Maximum amount of device tokens reached.', false);
    }

    // Build JWT header & claims
    $header = base64([
        'alg' => 'ES256',
        'kid' => APNS_KEYID
    ]);

    // Keep track of successful push notifications
    $successful = 0;

    // Build CURL handle/request
    $handle = curl_init();

    // Send push notifications
    foreach($_POST as $deviceToken => $values) {

        // Retrieve all user input
        $notificationType = getUserInputInt($values, 'notificationType');
        $notificationToken = getUserInputString($values, 'notificationToken');
        $notificationIssuer = getUserInputString($values, 'notificationIssuer');
        $notificationAccount = getUserInputString($values, 'notificationAccount');

        $claims = base64([
            'iss' => APNS_TEAMID,
            'iat' => time()
        ]);

        // Sign JWT header & claims
        $signature = '';
        openssl_sign($header . '.' . $claims, $signature, APNS_AUTHKEY, 'sha256');
        $jwt = $header . '.' . $claims . '.' . base64_encode($signature);


        curl_setopt_array($handle, [
            CURLOPT_URL => APNS_URI. '/3/device/' . $deviceToken,
            CURLOPT_PORT => 443,
            CURLOPT_HTTPHEADER => [
                'apns-push-type: ' . 'alert',
                'apns-priority: ' . 10,
                'apns-topic: ' . APNS_BUNDLEID,
                'Authorization: Bearer ' . $jwt,
                'User-Agent: Raivo OTP for MacOS APNS server'
            ],
            CURLOPT_POST => TRUE,
            CURLOPT_POSTFIELDS => json_encode([
                'type' => $notificationType,
                'token' => $notificationToken,
                'issuer' => $notificationIssuer,
                'account' => $notificationAccount
            ]),
            CURLOPT_RETURNTRANSFER => TRUE,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_2_0,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_HEADER => 1
        ]);

        $curl_status = curl_exec($handle);

        if ($curl_status === false) {
            respondWith('Stopped sending push notifications as a curl error occurred: ' . curl_error($handle), false);
            break;
        }

        $http_status = curl_getinfo($handle, CURLINFO_HTTP_CODE);

        if ($http_status !== 200) {
            respondWith('Stopped sending push notifications as APS responded with an error: ' . curl_error($handle), false);
            break;
        }

        $successful ++;
    }

    // Close handle
    curl_close($handle);

    // Exit with a success message
    respondWith('Token delivered at ' . $successful . ' device(s).');
