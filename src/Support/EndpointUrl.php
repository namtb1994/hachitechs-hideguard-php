<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Support;

use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;

final class EndpointUrl
{
    public static function normalize(string $value): string
    {
        $url = trim($value, " \t\n\r\v\f");
        $parts = parse_url($url);
        if (
            strlen($value) > 2048 || filter_var($url, FILTER_VALIDATE_URL) === false
            || str_contains($url, '\\') || preg_match('/[\x00-\x20\x7f]/', $url)
            || $parts === false || !isset($parts['host']) || strtolower($parts['scheme'] ?? '') !== 'https'
            || isset($parts['user']) || isset($parts['pass'])
            || !in_array($parts['path'] ?? '', ['', '/'], true)
            || isset($parts['query']) || isset($parts['fragment'])
        ) {
            throw new GuardException(
                FailureReason::InvalidConfiguration,
                'HideGuard URL must be an HTTPS origin without a path, credentials, query or fragment.'
            );
        }
        $port = isset($parts['port']) && $parts['port'] !== 443 ? ':' . $parts['port'] : '';
        return 'https://' . strtolower($parts['host']) . $port;
    }
}
