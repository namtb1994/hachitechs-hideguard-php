<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Http;

use Hachitech\Antidetect\Contracts\HttpTransport;
use Hachitech\Antidetect\Exceptions\ApiException;

final class CurlTransport implements HttpTransport
{
    public function __construct(
        private readonly int $timeoutSeconds = 10,
        private readonly int $connectTimeoutSeconds = 3
    ) {
        if ($connectTimeoutSeconds < 1 || $timeoutSeconds < $connectTimeoutSeconds) {
            throw new \InvalidArgumentException(
                'HTTP timeouts must be positive; connect timeout must not exceed total.'
            );
        }
    }

    public function post(string $url, array $headers, string $body): HttpResponse
    {
        if (!function_exists('curl_init')) {
            throw new ApiException('The default HTTP transport requires ext-curl; install it or supply HttpTransport.');
        }
        $handle = curl_init($url);
        if ($handle === false) {
            throw new ApiException('Could not initialize the HideGuard HTTP request.');
        }
        try {
            $headerLines = [];
            foreach ($headers as $name => $value) {
                $headerLines[] = $name . ': ' . $value;
            }
            $configured = curl_setopt_array($handle, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_HTTPHEADER => $headerLines,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_ENCODING => 'gzip, deflate',
                CURLOPT_TIMEOUT => $this->timeoutSeconds,
                CURLOPT_CONNECTTIMEOUT => $this->connectTimeoutSeconds,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ]);
            if (!$configured) {
                throw new ApiException('Could not configure the HideGuard HTTP request.');
            }
            $response = curl_exec($handle);
            if (!is_string($response)) {
                throw new ApiException('HideGuard HTTP request failed (cURL error ' . curl_errno($handle) . ').');
            }
            return new HttpResponse((int)curl_getinfo($handle, CURLINFO_HTTP_CODE), $response);
        } finally {
            curl_close($handle);
        }
    }
}
