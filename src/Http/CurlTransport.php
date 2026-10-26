<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Http;

use Hachitechs\HideguardPhp\Contracts\HttpTransport;
use Hachitechs\HideguardPhp\Exceptions\ApiException;

final class CurlTransport implements HttpTransport
{
    public const DEFAULT_MAX_RESPONSE_BYTES = 65536;

    public function __construct(
        private readonly int $timeoutSeconds = 10,
        private readonly int $connectTimeoutSeconds = 3,
        private readonly int $maxResponseBytes = self::DEFAULT_MAX_RESPONSE_BYTES
    ) {
        if ($connectTimeoutSeconds < 1 || $timeoutSeconds < $connectTimeoutSeconds) {
            throw new \InvalidArgumentException(
                'HTTP timeouts must be positive; connect timeout must not exceed total.'
            );
        }
        if ($maxResponseBytes < 1) {
            throw new \InvalidArgumentException('Response size limit must be positive.');
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
            $response = '';
            $oversized = false;
            $configured = curl_setopt_array($handle, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_HTTPHEADER => $headerLines,
                CURLOPT_WRITEFUNCTION => function ($curl, string $chunk) use (&$response, &$oversized): int {
                    $length = strlen($chunk);
                    if ($length > $this->maxResponseBytes - strlen($response)) {
                        $oversized = true;
                        return 0;
                    }
                    $response .= $chunk;
                    return $length;
                },
                CURLOPT_NOPROGRESS => false,
                CURLOPT_XFERINFOFUNCTION => function ($curl, float $total, float $downloaded) use (&$oversized): int {
                    if ($downloaded > $this->maxResponseBytes || $total > $this->maxResponseBytes) {
                        $oversized = true;
                        return 1;
                    }
                    return 0;
                },
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
            $completed = curl_exec($handle);
            if ($oversized) {
                throw new ApiException('HideGuard verdict response exceeds the size limit.');
            }
            if ($completed === false) {
                throw new ApiException('HideGuard HTTP request failed (cURL error ' . curl_errno($handle) . ').');
            }
            return new HttpResponse((int)curl_getinfo($handle, CURLINFO_HTTP_CODE), $response);
        } finally {
            curl_close($handle);
        }
    }
}
