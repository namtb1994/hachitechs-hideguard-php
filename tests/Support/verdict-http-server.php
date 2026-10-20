<?php

declare(strict_types=1);

// One-request HTTPS fixture. It never contacts HideGuard or any external service.
[$script, $pem, $capture, $mode] = $argv;
$context = stream_context_create(['ssl' => ['local_cert' => $pem, 'verify_peer' => false]]);
$server = stream_socket_server(
    'tls://127.0.0.1:0',
    $errno,
    $error,
    STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
    $context
);
if ($server === false) {
    throw new RuntimeException($error, $errno);
}
echo stream_socket_get_name($server, false) . "\n";
flush();
$connection = @stream_socket_accept($server, 10);
if ($connection === false) {
    fclose($server);
    exit(0);
}
stream_set_timeout($connection, 5);
$requestLine = trim((string)fgets($connection));
$headers = [];
while (($line = fgets($connection)) !== false && trim($line) !== '') {
    [$name, $value] = explode(':', $line, 2);
    $headers[strtolower($name)] = trim($value);
}
$body = '';
$length = (int)($headers['content-length'] ?? 0);
while (strlen($body) < $length && !feof($connection)) {
    $body .= fread($connection, $length - strlen($body));
}
file_put_contents($capture, json_encode([$requestLine, $headers, $body], JSON_THROW_ON_ERROR));
if ($mode === 'timeout') {
    sleep(3);
}
$status = $mode === 'redirect' ? '302 Found' : '200 OK';
$payload = gzencode('{"verdict":"allow","reasons":[{"code":"https-fixture"}]}');
fwrite($connection, 'HTTP/1.1 ' . $status . "\r\n"
    . "Content-Type: application/json\r\nContent-Encoding: gzip\r\n"
    . 'Location: https://' . stream_socket_get_name($server, false) . "/unexpected\r\n"
    . 'Content-Length: ' . strlen($payload) . "\r\nConnection: close\r\n\r\n" . $payload);
fclose($connection);
fclose($server);
