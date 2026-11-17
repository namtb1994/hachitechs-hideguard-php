<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Support;

use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Contracts\VerdictVerifier;
use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;
use Hachitechs\HideguardPhp\Verification\VerifiedVerdict;

/** Trusted stub for storage/lifecycle tests; never part of the distributed SDK. */
final class FixtureVerdictVerifier implements VerdictVerifier
{
    public function verify(array $payload, AccessContext $context, ProtectionPolicy $policy): VerifiedVerdict
    {
        if (!is_string($payload['verdict'] ?? null) || !is_string($payload['visitorId'] ?? null)) {
            throw new GuardException(FailureReason::InvalidVerdict, 'A verdict and visitor ID are required.');
        }
        return new VerifiedVerdict($payload['verdict'], $payload['visitorId'], true);
    }
}
