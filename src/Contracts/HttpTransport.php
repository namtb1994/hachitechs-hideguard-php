<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Contracts;

use Hachitechs\HideguardPhp\Exceptions\ApiException;
use Hachitechs\HideguardPhp\Http\HttpResponse;

interface HttpTransport
{
    /**
     * Send once with a finite timeout, verify TLS and do not follow redirects.
     * Bound downloaded and decompressed response bytes while receiving the body.
     * Return HTTP errors as responses; throw on connection/transport failures.
     *
     * @param array<string, string> $headers
     * @throws ApiException
     */
    public function post(string $url, array $headers, string $body): HttpResponse;
}
