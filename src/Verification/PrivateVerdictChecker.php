<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Verification;

use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;
use Hachitechs\HideguardPhp\Support\SystemClock;
use Psr\Clock\ClockInterface;

/** Only for responses just received by the authenticated server-side VerdictClient, never browser proofs. */
final class PrivateVerdictChecker
{
    private const TOKEN = '/\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z/';

    public function __construct(private readonly ClockInterface $clock = new SystemClock())
    {
    }

    /** @param array<array-key, mixed> $payload */
    public function check(array $payload, string $expectedVisitorId): VerifiedVerdict
    {
        $visitorId = $payload['visitorId'] ?? null;
        $group = VerdictPolicy::groupFor($payload['verdict'] ?? null);
        $reasons = $payload['reasons'] ?? null;
        if (
            !is_string($visitorId) || !preg_match(self::TOKEN, $visitorId) || $visitorId !== $expectedVisitorId
            || $group === null
            || !is_int($payload['score'] ?? null) || $payload['score'] < 0 || $payload['score'] > 9007199254740991
            || !is_array($reasons) || !array_is_list($reasons) || count($reasons) > 64
        ) {
            throw new GuardException(FailureReason::InvalidVerdict, 'Invalid HideGuard private verdict response.');
        }
        foreach ($reasons as $reason) {
            if (
                !is_array($reason) || !is_string($reason['code'] ?? null)
                || !preg_match(self::TOKEN, $reason['code'])
            ) {
                throw new GuardException(FailureReason::InvalidVerdict, 'Invalid HideGuard private reason code.');
            }
        }
        return new VerifiedVerdict($group, $visitorId, true, $this->clock->now()->getTimestamp());
    }
}
