<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Http;

use Hachitechs\HideguardPhp\Contracts\{HttpTransport, CircuitBreakerStoreContract};
use Hachitechs\HideguardPhp\Configuration\CircuitBreakerPolicy;
use Hachitechs\HideguardPhp\Exceptions\ApiException;
use Psr\Clock\ClockInterface;

/** Optional decorator; no HTTP retries or cached Allow fallback. */
final class CircuitBreakingTransport implements HttpTransport
{
    public function __construct(
        private readonly HttpTransport $transport,
        private readonly CircuitBreakerStoreContract $store,
        private readonly ClockInterface $clock,
        private readonly CircuitBreakerPolicy $policy,
        private readonly string $scopeKey
    ) {
    }
    public function post(string $url, array $headers, string $body): HttpResponse
    {
        // Credential hashes isolate environments without storing credentials in circuit rows.
        $credentials = [];
        foreach ($headers as $name => $value) {
            if (in_array(strtolower($name), ['x-api-key', 'authorization'], true)) {
                $credentials[strtolower($name)] = hash('sha256', $value);
            }
        }
        ksort($credentials);
        $key = hash('sha256', $this->scopeKey . ':' . $url . ':' . json_encode($credentials, JSON_THROW_ON_ERROR));
        try {
            $permit = $this->store->acquire($key, $this->clock->now()->getTimestamp(), $this->policy);
        } catch (\Throwable $error) {
            throw new ApiException('HideGuard circuit is unavailable.', 503, $error);
        }
        try {
            $response = $this->transport->post($url, $headers, $body);
        } catch (\Throwable $error) {
            try {
                $this->store->record($key, $permit, true, $this->clock->now()->getTimestamp(), $this->policy);
            } catch (\Throwable $storageError) {
                throw new ApiException('HideGuard circuit storage failed.', 503, $storageError);
            }
            throw $error;
        }
        try {
            $this->store->record(
                $key,
                $permit,
                $response->statusCode === 429 || $response->statusCode >= 500,
                $this->clock->now()->getTimestamp(),
                $this->policy
            );
        } catch (\Throwable $error) {
            throw new ApiException('HideGuard circuit storage failed.', 503, $error);
        }
        return $response;
    }
}
