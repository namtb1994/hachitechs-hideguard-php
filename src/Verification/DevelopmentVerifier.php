<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Verification;

use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Contracts\VerdictVerifier;
use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;

/** Explicit opt-in for development; browser payloads are forgeable in this mode. */
final class DevelopmentVerifier implements VerdictVerifier
{
    public function verify(array $payload, AccessContext $context, ProtectionPolicy $policy): VerifiedVerdict
    {
        if ($policy->environment !== 'development') {
            throw new GuardException(
                FailureReason::VerificationUnavailable,
                'Development verification cannot authorize signed environments.'
            );
        }
        if (!is_string($payload['verdict'] ?? null) || !is_string($payload['visitorId'] ?? null)) {
            throw new GuardException(FailureReason::InvalidVerdict, 'A known verdict and visitor ID are required.');
        }
        return new VerifiedVerdict($payload['verdict'], $payload['visitorId'], false);
    }
}
