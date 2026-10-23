<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Configuration;

use Hachitechs\HideguardPhp\Access\BrowserState;
use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;
use Hachitechs\HideguardPhp\Support\EndpointUrl;

final class ProtectionPolicy
{
    public const ENVIRONMENTS = ['development', 'staging', 'production'];
    public const BLOCK_DURATIONS = [900, 3600, 21600, 86400];
    public const PASS_DURATIONS = [0, 60, 300, 900, 3600];
    public const DEFAULT_PASS_DURATION = 300;
    public const ALWAYS_GRANT_SECONDS = 300;
    public const DEFAULT_ENDPOINT_URL = 'https://hideguard.io';

    public readonly string $endpointUrl;

    /**
     * @param list<string> $accessPoints
     * @param list<string> $pageRules
     */
    public function __construct(
        public readonly bool $enabled = false,
        public readonly string $environment = 'development',
        public readonly string $publicKey = '',
        public readonly string $signaturePublicKey = '',
        public readonly array $accessPoints = [],
        public readonly array $pageRules = [],
        public readonly int $blockDuration = 3600,
        public readonly int $passDuration = self::DEFAULT_PASS_DURATION,
        public readonly RateLimits $limits = new RateLimits(),
        string $endpointUrl = self::DEFAULT_ENDPOINT_URL,
        public readonly int $verificationTimeout = 35
    ) {
        $this->endpointUrl = EndpointUrl::normalize($endpointUrl);
        if (
            !in_array($environment, self::ENVIRONMENTS, true)
            || !in_array($blockDuration, self::BLOCK_DURATIONS, true)
            || !in_array($passDuration, self::PASS_DURATIONS, true)
            || $verificationTimeout < 5 || $verificationTimeout > 120
            || strlen($publicKey) > 1024 || strlen($signaturePublicKey) > 4096
        ) {
            throw new GuardException(FailureReason::InvalidConfiguration, 'Invalid environment, key or duration.');
        }
        foreach ($accessPoints as $point) {
            if (!is_string($point) || !preg_match('/^[a-zA-Z0-9_.:-]{1,128}$/D', $point)) {
                throw new GuardException(FailureReason::InvalidConfiguration, 'Invalid access point name.');
            }
        }
        foreach ($pageRules as $rule) {
            if (!is_string($rule) || str_contains($rule, "\0")) {
                throw new GuardException(FailureReason::InvalidConfiguration, 'Invalid page rule.');
            }
        }
        if (count($pageRules) > 50 || strlen(implode("\n", $pageRules)) > 4096) {
            throw new GuardException(FailureReason::InvalidConfiguration, 'Use at most 50 rules and 4096 bytes.');
        }
        if (
            $enabled && (trim($publicKey) === ''
            || ($environment !== 'development' && trim($signaturePublicKey) === ''))
        ) {
            throw new GuardException(FailureReason::InvalidConfiguration, 'The active environment requires keys.');
        }
    }

    public function protects(string $point): bool
    {
        return $this->enabled && (in_array('all_pages', $this->accessPoints, true)
            || in_array($point, $this->accessPoints, true));
    }

    public function grantSeconds(): int
    {
        return $this->passDuration === 0 ? self::ALWAYS_GRANT_SECONDS : $this->passDuration;
    }

    public function fingerprint(): string
    {
        $settings = get_object_vars($this);
        sort($settings['accessPoints']);
        sort($settings['pageRules']);
        return hash('sha256', 'hideguard-policy-v3:' . json_encode($settings, JSON_THROW_ON_ERROR));
    }

    public function grants(BrowserState $state, ?string $actorId, int $now): bool
    {
        return $this->enabled && $state->actorId === $actorId && $state->grantedUntil > $now
            && ($this->environment === 'development' || $state->verification === 'verified')
            && $state->policyHash !== null && hash_equals($this->fingerprint(), $state->policyHash);
    }
}
