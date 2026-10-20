<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Contracts;

use Hachitech\Antidetect\Exceptions\ApiException;
use Hachitech\Antidetect\Http\HttpResponse;

interface HttpTransport
{
    /**
     * Send once with a finite timeout, verify TLS and do not follow redirects.
     * Return HTTP errors as responses; throw on connection/transport failures.
     *
     * @param array<string, string> $headers
     * @throws ApiException
     */
    public function post(string $url, array $headers, string $body): HttpResponse;
}
