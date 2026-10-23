<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Verification;

use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Contracts\VerdictVerifier;
use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;
use Hachitechs\HideguardPhp\Support\SystemClock;
use Psr\Clock\ClockInterface;

/** Verifies HideGuard collect responses using the site's Ed25519 SPKI public key. */
final class Ed25519Verifier implements VerdictVerifier
{
    private const TOKEN = '/\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z/';
    private const HEADER = '/\Av=2,alg=ed25519,kid=([A-Za-z0-9][A-Za-z0-9._:-]{0,127}),'
        . 't=([1-9][0-9]{0,11}),sig=([A-Za-z0-9_-]{86})\z/';
    private const SPKI_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

    public function __construct(private readonly ClockInterface $clock = new SystemClock())
    {
    }

    public function verify(array $payload, AccessContext $context, ProtectionPolicy $policy): VerifiedVerdict
    {
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            throw new GuardException(
                FailureReason::VerificationUnavailable,
                'Ed25519 verification requires ext-sodium.'
            );
        }
        $key = self::decodePublicKey($policy->signaturePublicKey);
        if (!is_string($payload['signature'] ?? null) || !preg_match(self::HEADER, $payload['signature'], $header)) {
            throw new GuardException(FailureReason::InvalidVerdict, 'Invalid HideGuard signature header.');
        }
        foreach (['siteId', 'requestId', 'visitorId'] as $field) {
            if (!self::token($payload[$field] ?? null)) {
                throw new GuardException(FailureReason::InvalidVerdict, 'Invalid HideGuard signed identity.');
            }
        }
        $group = VerdictPolicy::groupFor($payload['verdict'] ?? null);
        if (
            ($payload['environment'] ?? null) !== $policy->environment
            || $group === null
            || !is_int($payload['score'] ?? null) || $payload['score'] < 0 || $payload['score'] > 9007199254740991
        ) {
            throw new GuardException(FailureReason::InvalidVerdict, 'Invalid HideGuard signed response fields.');
        }
        $reasons = $payload['reasons'] ?? null;
        if (!is_array($reasons) || !array_is_list($reasons) || count($reasons) > 64) {
            throw new GuardException(FailureReason::InvalidVerdict, 'Invalid HideGuard reason codes.');
        }
        $codes = [];
        foreach ($reasons as $reason) {
            if (!is_array($reason) || !self::token($reason['code'] ?? null)) {
                throw new GuardException(FailureReason::InvalidVerdict, 'Invalid HideGuard reason code.');
            }
            $codes[] = $reason['code'];
        }
        $issuedAt = (int)$header[2];
        $now = $this->clock->now()->getTimestamp();
        $lifetime = $group === 'block'
            ? min($policy->grantSeconds(), $policy->blockDuration) : $policy->grantSeconds();
        if ((string)$issuedAt !== $header[2] || $issuedAt > $now + 30 || $issuedAt + $lifetime <= $now) {
            throw new GuardException(
                FailureReason::InvalidVerdict,
                'HideGuard response is expired or dated in the future.'
            );
        }
        $message = implode("\n", [
            'hideguard-collect-ed25519-v2', 'alg=ed25519', 'kid=' . $header[1], 't=' . $header[2],
            'site=' . $payload['siteId'], 'environment=' . $payload['environment'],
            'request=' . $payload['requestId'], 'visitor=' . $payload['visitorId'],
            'verdict=' . $payload['verdict'], 'score=' . $payload['score'],
            'reasons=' . json_encode($codes, JSON_THROW_ON_ERROR),
        ]);
        $signature = base64_decode(strtr($header[3], '-_', '+/') . '==', true);
        if (
            strlen($payload['signature'] . "\n" . $message) > 12288
            || $signature === false || strlen($signature) !== 64
            || rtrim(strtr(base64_encode($signature), '+/', '-_'), '=') !== $header[3]
            || !sodium_crypto_sign_verify_detached($signature, $message, $key)
        ) {
            throw new GuardException(FailureReason::InvalidVerdict, 'Invalid HideGuard response signature.');
        }
        // Only the configured block group denies access after signature verification.
        return new VerifiedVerdict(
            $group === 'block' ? 'block' : 'allow',
            $payload['visitorId'],
            true,
            $issuedAt
        );
    }

    /** Validate admin configuration without requiring a loaded crypto extension. */
    public static function validatePublicKey(string $pem): void
    {
        self::decodePublicKey($pem);
    }

    /** @return non-empty-string */
    private static function decodePublicKey(string $pem): string
    {
        if (
            strlen($pem) <= 4096
            && preg_match(
                '/\A-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+\/=\s]+)-----END PUBLIC KEY-----\z/',
                trim($pem),
                $match
            )
        ) {
            $encoded = preg_replace('/\s+/', '', $match[1]) ?? '';
            $der = base64_decode($encoded, true);
            if (
                $der !== false && strlen($der) === 44 && str_starts_with($der, self::SPKI_PREFIX)
                && base64_encode($der) === $encoded
            ) {
                $key = substr($der, 12);
                if ($key !== '') {
                    return $key;
                }
            }
        }
        throw new GuardException(
            FailureReason::InvalidConfiguration,
            'An Ed25519 PEM public key is required for this site.'
        );
    }

    private static function token(mixed $value): bool
    {
        return is_string($value) && preg_match(self::TOKEN, $value) === 1;
    }
}
