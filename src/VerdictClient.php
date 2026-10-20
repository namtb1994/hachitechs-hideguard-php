<?php

declare(strict_types=1);

namespace Hachitech\Antidetect;

use Hachitech\Antidetect\Contracts\HttpTransport;
use Hachitech\Antidetect\Exceptions\ApiException;
use Hachitech\Antidetect\Exceptions\FailureReason;
use Hachitech\Antidetect\Exceptions\GuardException;
use Hachitech\Antidetect\Http\CurlTransport;
use Hachitech\Antidetect\Support\EndpointUrl;

final class VerdictClient
{
    private readonly string $url;

    public function __construct(
        string $baseUrl,
        private readonly string $apiKey,
        private readonly HttpTransport $transport = new CurlTransport()
    ) {
        $this->url = EndpointUrl::normalize($baseUrl) . '/api/v1/verdict';
        if ($apiKey === '' || preg_match('/[\x00-\x20\x7f]/', $apiKey)) {
            throw new GuardException(
                FailureReason::InvalidConfiguration,
                'API key must be non-empty without whitespace.'
            );
        }
    }

    /**
     * Return the complete JSON response, including nested objects, as PHP arrays.
     *
     * @return array<array-key, mixed>
     * @throws ApiException
     * @throws GuardException Invalid configuration or visitor identity.
     */
    public function getVerdict(string $visitorId): array
    {
        if (trim($visitorId) === '' || preg_match('/[\x00-\x1f\x7f]/', $visitorId)) {
            throw new GuardException(
                FailureReason::InvalidIdentity,
                'A non-empty visitorId without controls is required.'
            );
        }
        try {
            $body = json_encode(['visitorId' => $visitorId], JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new GuardException(FailureReason::InvalidIdentity, 'visitorId must contain valid UTF-8.');
        }
        $response = $this->transport->post($this->url, [
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
            'x-api-key' => $this->apiKey,
        ], $body);
        if ($response->statusCode < 200 || $response->statusCode >= 300) {
            throw new ApiException(
                'HideGuard verdict request returned HTTP ' . $response->statusCode . '.',
                $response->statusCode
            );
        }
        try {
            $result = json_decode($response->body, true, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (\JsonException $error) {
            throw new ApiException('HideGuard verdict response is not valid JSON.', $response->statusCode, $error);
        }
        if (!is_array($result)) {
            throw new ApiException('HideGuard verdict response must be a JSON object or array.', $response->statusCode);
        }
        return $result;
    }
}
